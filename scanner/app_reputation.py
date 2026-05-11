"""
scanner/app_reputation.py — Suspicious App & Software Detector

Enumerates installed applications and running software, checking for signs of
being suspicious, unwanted, or potentially malicious through multiple detection
layers: registry audit, digital signature verification, publisher reputation,
behavior-based scoring, and PUP pattern matching.
"""
import json
import logging
import os
import re
import subprocess
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Callable, List, Dict, Any

logger = logging.getLogger(__name__)

try:
    import winreg
    WINREG_AVAILABLE = True
except ImportError:
    WINREG_AVAILABLE = False
    logger.warning("winreg not available — app reputation scanner disabled")

# ─── Paths ─────────────────────────────────────────────────────────────────
INTEL_DIR = Path("intel")
TRUSTED_PUBLISHERS_PATH = INTEL_DIR / "trusted_publishers.json"
PUP_SIGNATURES_PATH = INTEL_DIR / "pup_signatures.json"

# ─── Registry locations for installed programs ─────────────────────────────
UNINSTALL_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE if WINREG_AVAILABLE else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_CURRENT_USER if WINREG_AVAILABLE else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE if WINREG_AVAILABLE else None,
     r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
] if WINREG_AVAILABLE else []

# ─── Suspicious path fragments ────────────────────────────────────────────
SUSPICIOUS_PATHS = [
    os.path.expandvars(r"%TEMP%").lower(),
    os.path.expandvars(r"%APPDATA%").lower(),
    os.path.expandvars(r"%LOCALAPPDATA%\Temp").lower(),
]

# ─── Risk level thresholds ─────────────────────────────────────────────────
RISK_THRESHOLDS = [
    (86, "critical", "quarantine"),
    (66, "high",     "remove"),
    (46, "medium",   "investigate"),
    (21, "low",      "monitor"),
    (0,  "clean",    "none"),
]


def _risk_from_score(score: int) -> tuple:
    """Return (risk_level, recommended_action) based on score."""
    for threshold, level, action in RISK_THRESHOLDS:
        if score >= threshold:
            return level, action
    return "clean", "none"


class AppReputationScanner:
    """
    Multi-layer installed application reputation scanner.
    Checks digital signatures, publisher trust, PUP patterns,
    and assigns behavior-based suspicion scores.
    """

    def __init__(self, config: dict, db=None,
                 on_alert: Optional[Callable[[dict], None]] = None):
        self.config = config
        self.db = db
        self.on_alert = on_alert
        self._lock = threading.Lock()

        # Load intelligence files
        self._trusted_publishers: List[str] = []
        self._pup_data: Dict[str, Any] = {}
        self._load_intel()

    # ------------------------------------------------------------------ #
    #  Intelligence loading                                                 #
    # ------------------------------------------------------------------ #
    def _load_intel(self) -> None:
        """Load trusted publishers and PUP signature databases."""
        try:
            if TRUSTED_PUBLISHERS_PATH.exists():
                with open(TRUSTED_PUBLISHERS_PATH, encoding="utf-8") as f:
                    self._trusted_publishers = json.load(f)
                logger.info(f"Loaded {len(self._trusted_publishers)} trusted publishers")
        except Exception as e:
            logger.error(f"Failed to load trusted publishers: {e}")

        try:
            if PUP_SIGNATURES_PATH.exists():
                with open(PUP_SIGNATURES_PATH, encoding="utf-8") as f:
                    self._pup_data = json.load(f)
                logger.info(f"Loaded PUP signatures database")
        except Exception as e:
            logger.error(f"Failed to load PUP signatures: {e}")

    def add_trusted_publisher(self, publisher: str) -> None:
        """Add a publisher to the trusted list and persist to disk."""
        if publisher and publisher not in self._trusted_publishers:
            self._trusted_publishers.append(publisher)
            try:
                INTEL_DIR.mkdir(parents=True, exist_ok=True)
                with open(TRUSTED_PUBLISHERS_PATH, "w", encoding="utf-8") as f:
                    json.dump(self._trusted_publishers, f, indent=2)
                logger.info(f"Added trusted publisher: {publisher}")
            except Exception as e:
                logger.error(f"Failed to save trusted publisher: {e}")

    def remove_trusted_publisher(self, publisher: str) -> None:
        """Remove a publisher from the trusted list."""
        if publisher in self._trusted_publishers:
            self._trusted_publishers.remove(publisher)
            try:
                with open(TRUSTED_PUBLISHERS_PATH, "w", encoding="utf-8") as f:
                    json.dump(self._trusted_publishers, f, indent=2)
            except Exception as e:
                logger.error(f"Failed to save trusted publishers: {e}")

    # ------------------------------------------------------------------ #
    #  Registry enumeration                                                 #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _read_reg_value(key, name: str) -> str:
        """Read a single registry value, returning empty string on failure."""
        try:
            value, _ = winreg.QueryValueEx(key, name)
            return str(value).strip() if value else ""
        except (FileNotFoundError, OSError):
            return ""

    def enumerate_installed_apps(self) -> List[Dict[str, str]]:
        """Enumerate all installed applications from Windows registry."""
        if not WINREG_AVAILABLE:
            return []

        apps = []
        seen_names = set()

        for hive, subkey_path in UNINSTALL_KEYS:
            if hive is None:
                continue
            try:
                key = winreg.OpenKey(hive, subkey_path, 0,
                                     winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        i += 1
                        try:
                            sub = winreg.OpenKey(key, subkey_name)
                            display_name = self._read_reg_value(sub, "DisplayName")
                            if not display_name or display_name in seen_names:
                                winreg.CloseKey(sub)
                                continue
                            seen_names.add(display_name)

                            app = {
                                "app_name": display_name,
                                "publisher": self._read_reg_value(sub, "Publisher"),
                                "install_date": self._read_reg_value(sub, "InstallDate"),
                                "install_path": self._read_reg_value(sub, "InstallLocation"),
                                "uninstall_string": self._read_reg_value(sub, "UninstallString"),
                                "display_version": self._read_reg_value(sub, "DisplayVersion"),
                                "registry_key": f"{subkey_path}\\{subkey_name}",
                            }
                            winreg.CloseKey(sub)
                            apps.append(app)
                        except OSError:
                            continue
                    except OSError:
                        break
                winreg.CloseKey(key)
            except (FileNotFoundError, OSError) as e:
                logger.debug(f"Could not open {subkey_path}: {e}")
                continue

        logger.info(f"Enumerated {len(apps)} installed applications")
        return apps

    # ------------------------------------------------------------------ #
    #  Digital signature verification                                       #
    # ------------------------------------------------------------------ #
    @staticmethod
    def verify_signature(exe_path: str) -> str:
        """
        Verify Authenticode signature of an executable using PowerShell.
        Returns: 'Valid', 'NotSigned', 'HashMismatch', or 'UnknownError'
        """
        if not exe_path or not os.path.isfile(exe_path):
            return "UnknownError"

        try:
            cmd = (
                f'powershell.exe -NoProfile -NonInteractive -Command '
                f'"(Get-AuthenticodeSignature \'{exe_path}\').Status"'
            )
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            status = result.stdout.strip()

            if status == "Valid":
                return "Valid"
            elif status == "NotSigned":
                return "NotSigned"
            elif status == "HashMismatch":
                return "HashMismatch"
            else:
                return "UnknownError"
        except subprocess.TimeoutExpired:
            logger.warning(f"Signature check timed out: {exe_path}")
            return "UnknownError"
        except Exception as e:
            logger.error(f"Signature check error for {exe_path}: {e}")
            return "UnknownError"

    # ------------------------------------------------------------------ #
    #  Find main executable                                                 #
    # ------------------------------------------------------------------ #
    @staticmethod
    def find_main_exe(app: Dict[str, str]) -> str:
        """Attempt to locate the main .exe for an installed application."""
        install_path = app.get("install_path", "")
        uninstall_str = app.get("uninstall_string", "")

        # Try install location first
        if install_path and os.path.isdir(install_path):
            for f in os.listdir(install_path):
                if f.lower().endswith(".exe"):
                    full = os.path.join(install_path, f)
                    if os.path.isfile(full):
                        return full

        # Try extracting from uninstall string
        if uninstall_str:
            # Remove quotes and extract path
            exe_match = re.search(r'([A-Za-z]:\\[^"*?<>|]+\.exe)', uninstall_str)
            if exe_match:
                candidate = exe_match.group(1)
                if os.path.isfile(candidate):
                    return candidate

        return ""

    # ------------------------------------------------------------------ #
    #  Publisher reputation check                                           #
    # ------------------------------------------------------------------ #
    def is_publisher_trusted(self, publisher: str) -> bool:
        """Check if a publisher is in the trusted list (case-insensitive)."""
        if not publisher:
            return False
        pub_lower = publisher.lower()
        return any(tp.lower() == pub_lower for tp in self._trusted_publishers)

    # ------------------------------------------------------------------ #
    #  PUP detection                                                        #
    # ------------------------------------------------------------------ #
    def check_pup(self, app: Dict[str, str]) -> Optional[str]:
        """Check if an app matches known PUP patterns. Returns match name or None."""
        app_name = app.get("app_name", "")
        publisher = app.get("publisher", "")

        # Check publisher names
        pup_publishers = self._pup_data.get("publishers", [])
        for pup_pub in pup_publishers:
            if pup_pub.lower() in publisher.lower():
                return f"PUP.Publisher.{pup_pub}"

        # Check program name patterns
        for pattern in self._pup_data.get("program_patterns", []):
            try:
                if re.search(pattern, app_name):
                    return f"PUP.Pattern.{app_name[:30]}"
            except re.error:
                continue

        # Check installer patterns in uninstall string
        uninstall = app.get("uninstall_string", "")
        for pattern in self._pup_data.get("installer_patterns", []):
            try:
                if re.search(pattern, uninstall):
                    return f"PUP.Installer.{app_name[:30]}"
            except re.error:
                continue

        return None

    # ------------------------------------------------------------------ #
    #  Check for startup/scheduled task presence                            #
    # ------------------------------------------------------------------ #
    @staticmethod
    def has_startup_entry(app_name: str, registry_watcher=None) -> bool:
        """Check if the app has any startup or scheduled task entry."""
        if registry_watcher and hasattr(registry_watcher, "get_startup_items"):
            items = registry_watcher.get_startup_items()
            app_lower = app_name.lower()
            for item in items:
                if app_lower in item.get("name", "").lower() or \
                   app_lower in item.get("path", "").lower():
                    return True
        return False

    # ------------------------------------------------------------------ #
    #  Suspicion scoring                                                    #
    # ------------------------------------------------------------------ #
    def compute_suspicion_score(self, app: Dict[str, str],
                                 signature_status: str,
                                 pup_match: Optional[str],
                                 has_startup: bool,
                                 yara_match: Optional[str],
                                 vt_malicious: bool,
                                 file_scanner=None) -> tuple:
        """
        Compute a 0–100 suspicion score for an installed application.
        Returns (score, flags_list).
        """
        score = 0
        flags = []

        # +10 → No publisher listed
        publisher = app.get("publisher", "")
        if not publisher or publisher.lower() in ("unknown", "n/a", ""):
            score += 10
            flags.append("no_publisher")

        # +15 → Unsigned binary
        if signature_status == "NotSigned":
            score += 15
            flags.append("unsigned_binary")

        # +25 → HashMismatch on signature
        if signature_status == "HashMismatch":
            score += 25
            flags.append("signature_hash_mismatch")

        # +20 → Installed in last 24 hours
        install_date = app.get("install_date", "")
        if install_date:
            try:
                dt = datetime.strptime(install_date, "%Y%m%d")
                if datetime.now() - dt < timedelta(hours=24):
                    score += 20
                    flags.append("recently_installed")
            except ValueError:
                pass

        # +15 → InstallLocation in Temp/AppData/Roaming
        install_path = app.get("install_path", "").lower()
        if install_path:
            for suspicious in SUSPICIOUS_PATHS:
                if suspicious in install_path:
                    score += 15
                    flags.append("suspicious_install_path")
                    break

        # +20 → Has startup/scheduled task entry
        if has_startup:
            score += 20
            flags.append("has_startup_entry")

        # +10 → No uninstall entry (ghost install)
        if not app.get("uninstall_string", ""):
            score += 10
            flags.append("no_uninstall_entry")

        # +10 → Version string blank or malformed
        version = app.get("display_version", "")
        if not version:
            score += 5
            flags.append("no_version_info")

        # +15 → UninstallString with unusual characters or encoded commands
        uninstall = app.get("uninstall_string", "")
        if uninstall:
            if any(c in uninstall for c in ['|', '&', ';', '`', '$']):
                score += 15
                flags.append("suspicious_uninstall_cmd")
            if re.search(r'(?i)(powershell|cmd\s*/c|wscript|cscript)', uninstall):
                score += 10
                flags.append("script_in_uninstall")

        # +30 → Main .exe matches known-bad hash (MalwareBazaar check)
        if vt_malicious:
            score += 30
            flags.append("vt_malicious_hash")

        # +20 → Main .exe detected by YARA rules
        if yara_match:
            score += 20
            flags.append(f"yara_match:{yara_match}")

        # +20 → PUP match
        if pup_match:
            score += 20
            flags.append(f"pup_detected:{pup_match}")

        # -30 → Valid Microsoft/trusted signature (reduces score)
        if signature_status == "Valid":
            if self.is_publisher_trusted(publisher):
                score -= 30
                flags.append("trusted_signed_publisher")

        # Clamp to 0–100
        score = max(0, min(100, score))

        return score, flags

    # ------------------------------------------------------------------ #
    #  Main scan function                                                   #
    # ------------------------------------------------------------------ #
    def scan_installed_apps(self, progress_callback: Optional[Callable] = None,
                             cancel_event: Optional[threading.Event] = None) -> List[Dict]:
        """
        Full scan of all installed applications.
        Returns list of app scan result dicts.
        """
        apps = self.enumerate_installed_apps()
        results = []
        total = len(apps)

        # Get references to other modules
        registry_watcher = None
        file_scanner_mod = None
        vt_checker = None

        if hasattr(self, '_modules'):
            registry_watcher = self._modules.get("registry_watcher")
            file_scanner_mod = self._modules.get("file_scanner")
            vt_checker = self._modules.get("virustotal")

        for idx, app in enumerate(apps):
            if cancel_event and cancel_event.is_set():
                break

            try:
                # Find main executable
                exe_path = self.find_main_exe(app)

                # Signature verification
                signature_status = "UnknownError"
                if exe_path:
                    signature_status = self.verify_signature(exe_path)

                # PUP check
                pup_match = self.check_pup(app)

                # Startup entry check
                has_startup = self.has_startup_entry(
                    app.get("app_name", ""), registry_watcher
                )

                # YARA scan on main exe
                yara_match = None
                if exe_path and file_scanner_mod:
                    try:
                        scan_result = file_scanner_mod.scan_file(exe_path)
                        if not scan_result.clean:
                            yara_match = scan_result.threat_name
                    except Exception:
                        pass

                # Hash check against MalwareBazaar
                vt_malicious = False
                vt_result = None
                if exe_path and self.db:
                    from scanner.file_scanner import FileScanner
                    hashes = FileScanner.hash_file(exe_path)
                    sha256 = hashes.get("sha256", "")
                    if sha256:
                        hit = self.db.hash_exists(sha256=sha256)
                        if hit:
                            vt_malicious = True
                            vt_result = hit

                # Compute suspicion score
                score, flags = self.compute_suspicion_score(
                    app, signature_status, pup_match,
                    has_startup, yara_match, vt_malicious,
                    file_scanner_mod
                )

                risk_level, recommended_action = _risk_from_score(score)

                result = {
                    "app_name": app.get("app_name", ""),
                    "publisher": app.get("publisher", ""),
                    "install_date": app.get("install_date", ""),
                    "install_path": app.get("install_path", ""),
                    "exe_path": exe_path,
                    "signature_status": signature_status,
                    "suspicion_score": score,
                    "risk_level": risk_level,
                    "flags": flags,
                    "vt_result": vt_result,
                    "yara_match": yara_match,
                    "recommended_action": recommended_action,
                }
                results.append(result)

                # Alert for high/critical
                if risk_level in ("high", "critical") and self.on_alert:
                    self.on_alert({
                        "type": "suspicious_app",
                        "severity": risk_level,
                        "detail": f"Suspicious app: {app.get('app_name', '')} "
                                  f"(score: {score}, flags: {', '.join(flags)})",
                        "path": exe_path or app.get("install_path", ""),
                    })

                if progress_callback:
                    progress_callback(idx + 1, total, app.get("app_name", ""))

            except Exception as e:
                logger.error(f"Error scanning app '{app.get('app_name', '')}': {e}")
                continue

        # Save results to database
        if self.db and results and hasattr(self.db, "save_app_scan"):
            try:
                self.db.save_app_scan(results)
            except Exception as e:
                logger.error(f"Failed to save app scan results: {e}")

        logger.info(f"App reputation scan complete: {len(results)} apps, "
                     f"{sum(1 for r in results if r['risk_level'] != 'clean')} flagged")
        return results

    def set_modules(self, modules: dict) -> None:
        """Inject references to other modules for cross-checking."""
        self._modules = modules

    # ------------------------------------------------------------------ #
    #  Compatibility                                                        #
    # ------------------------------------------------------------------ #
    @classmethod
    def is_supported(cls) -> bool:
        """Check if this module can run on the current platform."""
        return WINREG_AVAILABLE

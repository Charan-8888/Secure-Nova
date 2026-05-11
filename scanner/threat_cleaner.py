"""
scanner/threat_cleaner.py — Threat Cleaning Engine

Safely and thoroughly removes or neutralizes detected threats.
All cleaning is reversible where possible (quarantine first).
Handles: file quarantine with encryption, registry cleanup, scheduled task
removal, process termination, browser extension removal, hosts file
restoration, and persistence cleaning.
"""
import ctypes
import json
import logging
import os
import re
import shutil
import subprocess
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, Callable

logger = logging.getLogger(__name__)

from utils.safety import is_system_critical, is_protected_process, RollbackSnapshot
from utils.logger import audit_log

try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logger.warning("cryptography not installed — encrypted quarantine disabled")

try:
    import winreg
    WINREG_AVAILABLE = True
except ImportError:
    WINREG_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


# ─── Default hosts file content ───────────────────────────────────────────
DEFAULT_HOSTS = """# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
"""


class CleaningResult:
    """Result of a single threat cleaning operation."""

    def __init__(self, threat_path: str, threat_name: str):
        self.threat_path = threat_path
        self.threat_name = threat_name
        self.action_taken = ""
        self.success = False
        self.failure_reason = None
        self.requires_reboot = False
        self.verification_passed = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threat_path": self.threat_path,
            "threat_name": self.threat_name,
            "action_taken": self.action_taken,
            "success": self.success,
            "failure_reason": self.failure_reason,
            "requires_reboot": self.requires_reboot,
            "verification_passed": self.verification_passed,
        }


class ThreatCleaner:
    """
    Multi-stage threat cleaning engine.
    Quarantines threats with Fernet encryption, removes persistence
    mechanisms, terminates malicious processes, and verifies cleanup.
    """

    def __init__(self, config: dict, db=None,
                 on_alert: Optional[Callable[[dict], None]] = None):
        self.config = config
        self.db = db
        self.on_alert = on_alert
        self.quarantine_dir = Path(config.get("quarantine_path", "quarantine"))
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._rollback = RollbackSnapshot()

    # ------------------------------------------------------------------ #
    #  1. QUARANTINE (encrypted)                                           #
    # ------------------------------------------------------------------ #
    def quarantine_file(self, file_path: str, threat_name: str = "",
                         threat_type: str = "", engine: str = "") -> CleaningResult:
        """Move file to quarantine with optional Fernet encryption."""
        result = CleaningResult(file_path, threat_name)
        result.action_taken = "quarantined"

        # Safety check: never quarantine system-critical files
        if is_system_critical(file_path):
            result.failure_reason = "system_protected"
            logger.warning(f"Safety blocked quarantine of system file: {file_path}")
            audit_log("safety_blocked", "info", "threat_cleaner",
                      path=file_path, action="quarantine", reason="system_protected")
            return result

        try:
            src = Path(file_path)
            if not src.exists():
                result.failure_reason = "File not found"
                return result

            # Create unique quarantine subdirectory
            q_id = str(uuid.uuid4())[:8]
            q_dir = self.quarantine_dir / q_id
            q_dir.mkdir(parents=True, exist_ok=True)
            dest = q_dir / (src.name + ".quar")

            # Read file content
            with open(src, "rb") as f:
                data = f.read()

            # Capture rollback snapshot before any modification
            snap_id = self._rollback.capture_file(str(src))

            # Encrypt if available
            encryption_key = None
            if CRYPTO_AVAILABLE:
                key = Fernet.generate_key()
                fernet = Fernet(key)
                encrypted_data = fernet.encrypt(data)
                encryption_key = key.decode()

                with open(dest, "wb") as f:
                    f.write(encrypted_data)
            else:
                # Just move without encryption
                shutil.copy2(str(src), str(dest))

            # Remove original
            try:
                src.unlink()
            except PermissionError:
                # Try force removal
                try:
                    os.chmod(str(src), 0o777)
                    src.unlink()
                except Exception:
                    result.failure_reason = "Could not remove original (file locked)"
                    result.requires_reboot = True
                    self._schedule_delayed_delete(str(src))

            # Record in database
            if self.db:
                from scanner.file_scanner import FileScanner
                file_hash = FileScanner.hash_file(file_path).get("sha256", "") if os.path.exists(file_path) else ""

                self.db.add_quarantine_entry(
                    str(src), str(dest), threat_name, threat_type
                )

                # Store encryption key in a metadata file (not in the encrypted file)
                if encryption_key:
                    meta_path = q_dir / "metadata.json"
                    meta = {
                        "original_path": str(src),
                        "quarantine_path": str(dest),
                        "threat_name": threat_name,
                        "threat_type": threat_type,
                        "engine": engine,
                        "timestamp": datetime.now().isoformat(),
                        "encryption_key": encryption_key,
                        "file_hash": file_hash if 'file_hash' in dir() else "",
                    }
                    with open(meta_path, "w") as f:
                        json.dump(meta, f, indent=2)

            # Verify quarantine
            if not src.exists() or result.requires_reboot:
                result.success = True
                result.verification_passed = not src.exists()
            else:
                result.failure_reason = "File still exists after quarantine"

            logger.info(f"Quarantined: {src} → {dest}")

        except Exception as e:
            result.failure_reason = str(e)
            logger.error(f"Quarantine failed for {file_path}: {e}")

        return result

    def restore_quarantined(self, quarantine_path: str,
                             original_path: str) -> bool:
        """Restore a quarantined file to its original location."""
        try:
            q_path = Path(quarantine_path)
            q_dir = q_path.parent
            meta_path = q_dir / "metadata.json"

            if not q_path.exists():
                logger.error(f"Quarantine file not found: {quarantine_path}")
                return False

            # Check for encryption metadata
            if meta_path.exists() and CRYPTO_AVAILABLE:
                with open(meta_path) as f:
                    meta = json.load(f)
                key = meta.get("encryption_key", "")
                if key:
                    fernet = Fernet(key.encode())
                    with open(q_path, "rb") as f:
                        encrypted_data = f.read()
                    decrypted_data = fernet.decrypt(encrypted_data)
                    with open(original_path, "wb") as f:
                        f.write(decrypted_data)
                    # Clean up quarantine
                    shutil.rmtree(str(q_dir), ignore_errors=True)
                    logger.info(f"Restored (decrypted): {quarantine_path} → {original_path}")
                    return True

            # No encryption — just move back
            shutil.move(str(q_path), original_path)
            logger.info(f"Restored: {quarantine_path} → {original_path}")
            return True

        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return False

    # ------------------------------------------------------------------ #
    #  2. REGISTRY CLEANUP                                                  #
    # ------------------------------------------------------------------ #
    def clean_registry_entry(self, key_path: str, value_name: str) -> CleaningResult:
        """Remove a specific registry value from a Run/RunOnce key."""
        result = CleaningResult(key_path, f"Registry:{value_name}")
        result.action_taken = "registry_removed"

        if not WINREG_AVAILABLE:
            result.failure_reason = "winreg not available"
            return result

        try:
            # Determine hive
            if key_path.startswith(str(winreg.HKEY_LOCAL_MACHINE)):
                hive = winreg.HKEY_LOCAL_MACHINE
                subkey = key_path.split("\\", 1)[1] if "\\" in key_path else key_path
            elif key_path.startswith(str(winreg.HKEY_CURRENT_USER)):
                hive = winreg.HKEY_CURRENT_USER
                subkey = key_path.split("\\", 1)[1] if "\\" in key_path else key_path
            else:
                # Try common patterns
                if "HKLM" in key_path or "HKEY_LOCAL_MACHINE" in key_path:
                    hive = winreg.HKEY_LOCAL_MACHINE
                else:
                    hive = winreg.HKEY_CURRENT_USER
                subkey = re.sub(r'^(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\',
                                '', key_path)

            key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, value_name)
            winreg.CloseKey(key)

            result.success = True
            result.verification_passed = True
            logger.info(f"Removed registry value: {key_path}\\{value_name}")

        except FileNotFoundError:
            result.success = True  # Already gone
            result.verification_passed = True
        except PermissionError:
            result.failure_reason = "Access denied — requires elevation"
        except Exception as e:
            result.failure_reason = str(e)
            logger.error(f"Registry cleanup failed: {e}")

        return result

    # ------------------------------------------------------------------ #
    #  3. SCHEDULED TASK CLEANUP                                            #
    # ------------------------------------------------------------------ #
    def remove_scheduled_task(self, task_name: str) -> CleaningResult:
        """Delete a Windows scheduled task."""
        result = CleaningResult(task_name, f"ScheduledTask:{task_name}")
        result.action_taken = "task_deleted"

        try:
            cmd = f'schtasks /Delete /TN "{task_name}" /F'
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15,
                shell=True, creationflags=subprocess.CREATE_NO_WINDOW
            )
            if proc.returncode == 0:
                result.success = True
                result.verification_passed = True
                logger.info(f"Deleted scheduled task: {task_name}")
            else:
                result.failure_reason = proc.stderr.strip() or "Failed to delete task"
        except Exception as e:
            result.failure_reason = str(e)
            logger.error(f"Scheduled task removal failed: {e}")

        return result

    # ------------------------------------------------------------------ #
    #  4. PROCESS TERMINATION                                               #
    # ------------------------------------------------------------------ #
    def terminate_process(self, file_path: str) -> CleaningResult:
        """Terminate any process using the specified file."""
        result = CleaningResult(file_path, "ProcessTermination")
        result.action_taken = "process_terminated"

        if not PSUTIL_AVAILABLE:
            result.failure_reason = "psutil not available"
            return result

        # Safety check: never terminate protected processes
        file_name = os.path.basename(file_path).lower()
        if is_protected_process(file_name):
            result.failure_reason = "protected_process"
            logger.warning(f"Safety blocked termination of protected process: {file_name}")
            audit_log("safety_blocked", "info", "threat_cleaner",
                      path=file_path, action="terminate", reason="protected_process")
            return result

        try:
            terminated = []
            file_path_lower = file_path.lower()

            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    exe = proc.info.get('exe', '') or ''
                    if exe.lower() == file_path_lower:
                        # Try graceful termination
                        proc.terminate()
                        terminated.append(proc)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            if terminated:
                # Wait for graceful shutdown
                gone, alive = psutil.wait_procs(terminated, timeout=3)

                # Force kill survivors
                for proc in alive:
                    try:
                        proc.kill()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                result.success = True
                result.verification_passed = True
                logger.info(f"Terminated {len(terminated)} process(es) for {file_path}")
            else:
                result.success = True  # No processes to terminate
                result.verification_passed = True

        except Exception as e:
            result.failure_reason = str(e)
            logger.error(f"Process termination failed: {e}")

        return result

    # ------------------------------------------------------------------ #
    #  5. BROWSER EXTENSION REMOVAL                                         #
    # ------------------------------------------------------------------ #
    def remove_browser_extension(self, ext_path: str,
                                  browser: str = "") -> CleaningResult:
        """Remove a browser extension folder."""
        result = CleaningResult(ext_path, f"BrowserExtension:{browser}")
        result.action_taken = "extension_removed"

        try:
            ext = Path(ext_path)
            if ext.exists():
                if ext.is_dir():
                    shutil.rmtree(str(ext), ignore_errors=True)
                else:
                    ext.unlink()

                result.success = not ext.exists()
                result.verification_passed = result.success
                if not result.success:
                    result.failure_reason = "Extension still exists after removal"
                else:
                    logger.info(f"Removed {browser} extension: {ext_path}")
            else:
                result.success = True
                result.verification_passed = True

        except Exception as e:
            result.failure_reason = str(e)
            logger.error(f"Extension removal failed: {e}")

        return result

    # ------------------------------------------------------------------ #
    #  6. HOSTS FILE RESTORATION                                            #
    # ------------------------------------------------------------------ #
    def restore_hosts_file(self) -> CleaningResult:
        """Restore Windows hosts file to default."""
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        result = CleaningResult(hosts_path, "HostsFileRestore")
        result.action_taken = "hosts_restored"

        try:
            hosts = Path(hosts_path)
            if hosts.exists():
                # Backup current hosts to quarantine
                backup_dir = self.quarantine_dir / "hosts_backup"
                backup_dir.mkdir(parents=True, exist_ok=True)
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup = backup_dir / f"hosts_{ts}.bak"
                shutil.copy2(hosts_path, str(backup))
                logger.info(f"Backed up hosts file to {backup}")

            # Write default hosts
            with open(hosts_path, "w") as f:
                f.write(DEFAULT_HOSTS)

            result.success = True
            result.verification_passed = True
            logger.info("Hosts file restored to default")

        except PermissionError:
            result.failure_reason = "Access denied — requires Administrator"
        except Exception as e:
            result.failure_reason = str(e)
            logger.error(f"Hosts restore failed: {e}")

        return result

    # ------------------------------------------------------------------ #
    #  7. PERSISTENCE CLEANING                                              #
    # ------------------------------------------------------------------ #
    def clean_wmi_subscription(self, name: str) -> CleaningResult:
        """Remove a suspicious WMI event subscription."""
        result = CleaningResult(name, f"WMI:{name}")
        result.action_taken = "wmi_removed"

        try:
            # Remove WMI event filter
            cmd = (
                f'powershell.exe -NoProfile -NonInteractive -Command '
                f'"Get-WmiObject __EventFilter -Namespace root\\subscription | '
                f'Where-Object {{ $_.Name -eq \'{name}\' }} | Remove-WmiObject"'
            )
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            # Remove associated consumer
            cmd2 = (
                f'powershell.exe -NoProfile -NonInteractive -Command '
                f'"Get-WmiObject CommandLineEventConsumer -Namespace root\\subscription | '
                f'Where-Object {{ $_.Name -eq \'{name}\' }} | Remove-WmiObject"'
            )
            subprocess.run(
                cmd2, capture_output=True, text=True, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            result.success = True
            result.verification_passed = True
            logger.info(f"Removed WMI subscription: {name}")

        except Exception as e:
            result.failure_reason = str(e)
            logger.error(f"WMI cleanup failed: {e}")

        return result

    # ------------------------------------------------------------------ #
    #  8. DELAYED DELETE (for locked files)                                 #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _schedule_delayed_delete(file_path: str) -> bool:
        """Schedule file deletion on next reboot using MoveFileEx."""
        try:
            MoveFileEx = ctypes.windll.kernel32.MoveFileExW
            MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004
            success = MoveFileEx(file_path, None, MOVEFILE_DELAY_UNTIL_REBOOT)
            if success:
                logger.info(f"Scheduled delayed delete for: {file_path}")
            else:
                logger.error(f"MoveFileEx failed for: {file_path}")
            return bool(success)
        except Exception as e:
            logger.error(f"Delayed delete scheduling failed: {e}")
            return False

    # ------------------------------------------------------------------ #
    #  9. COMPREHENSIVE CLEAN                                               #
    # ------------------------------------------------------------------ #
    def clean_threat(self, threat: Dict[str, Any]) -> CleaningResult:
        """
        Clean a detected threat using the full cleaning pipeline.
        Steps: terminate process → quarantine file → clean registry →
               clean tasks → verify.
        """
        file_path = threat.get("path", threat.get("file_path", ""))
        threat_name = threat.get("threat_name", "Unknown")
        severity = threat.get("severity", "medium")

        # Step 1: Terminate any running process using this file
        if file_path and os.path.isfile(file_path):
            self.terminate_process(file_path)

        # Step 2: Quarantine the file
        result = self.quarantine_file(
            file_path, threat_name,
            threat.get("threat_type", ""),
            threat.get("engine", "")
        )

        # Step 3: Check and clean registry entries
        if WINREG_AVAILABLE and file_path:
            self._clean_registry_for_file(file_path)

        # Step 4: Log to database
        if self.db and result.success:
            self.db.log_threat(
                "threat_cleaned", severity, file_path,
                f"Cleaned: {threat_name} | Action: {result.action_taken}",
                result.action_taken
            )

        # Step 5: Alert
        if self.on_alert and result.success:
            self.on_alert({
                "type": "threat_cleaned",
                "severity": "info",
                "detail": f"Cleaned: {threat_name} from {file_path}",
                "path": file_path,
            })

        return result

    def clean_threats(self, threats: List[Dict],
                       progress_callback: Optional[Callable] = None) -> List[CleaningResult]:
        """Clean multiple threats, returning a list of results."""
        results = []
        total = len(threats)

        for idx, threat in enumerate(threats):
            result = self.clean_threat(threat)
            results.append(result)

            if progress_callback:
                progress_callback(idx + 1, total, threat.get("threat_name", ""))

        # Summary log
        success_count = sum(1 for r in results if r.success)
        reboot_count = sum(1 for r in results if r.requires_reboot)
        logger.info(f"Cleaning complete: {success_count}/{total} cleaned, "
                     f"{reboot_count} require reboot")

        return results

    def _clean_registry_for_file(self, file_path: str) -> None:
        """Remove any startup registry entries pointing to the given file."""
        if not WINREG_AVAILABLE:
            return

        startup_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]

        file_lower = file_path.lower()
        for hive, subkey in startup_keys:
            try:
                key = winreg.OpenKey(hive, subkey, 0,
                                     winreg.KEY_READ | winreg.KEY_SET_VALUE)
                i = 0
                to_delete = []
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        if file_lower in str(value).lower():
                            to_delete.append(name)
                        i += 1
                    except OSError:
                        break

                for name in to_delete:
                    try:
                        winreg.DeleteValue(key, name)
                        logger.info(f"Removed startup entry: {name} from {subkey}")
                    except Exception as e:
                        logger.error(f"Failed to remove registry entry {name}: {e}")

                winreg.CloseKey(key)
            except (FileNotFoundError, OSError):
                continue

    # ------------------------------------------------------------------ #
    #  Compatibility                                                        #
    # ------------------------------------------------------------------ #
    @classmethod
    def is_supported(cls) -> bool:
        return True

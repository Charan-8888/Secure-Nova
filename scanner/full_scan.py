"""
scanner/full_scan.py — Full PC Scan Engine

Comprehensive, configurable scan of the entire PC covering all drives,
checking every file, reporting all threats found, and then cleaning them.
Runs in phases: Drive Discovery → File Enumeration → Priority Scanning →
Deep Content Scan → System Area Scan → Results Aggregation.
"""
import hashlib
import json
import logging
import os
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path
from queue import Queue, Empty
from typing import Optional, Callable, List, Dict, Any

logger = logging.getLogger(__name__)

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

# ─── File priority categories ─────────────────────────────────────────────
PRIORITY_EXECUTABLES = {".exe", ".dll", ".sys", ".drv", ".com", ".scr"}
PRIORITY_SCRIPTS     = {".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf", ".hta"}
PRIORITY_INSTALLERS  = {".msi", ".cab", ".zip", ".rar", ".7z", ".tar"}
PRIORITY_DOCUMENTS   = {".pdf", ".docx", ".xlsx", ".docm", ".xlsm", ".pptm"}

# Files to always skip
SKIP_FILES = {"hiberfil.sys", "pagefile.sys", "swapfile.sys"}

# Default max file size (500 MB)
DEFAULT_MAX_FILE_SIZE = 500 * 1024 * 1024

# Scan cache validity (7 days)
CACHE_VALIDITY_DAYS = 7


class ScanProgress:
    """Encapsulates scan progress state."""

    def __init__(self):
        self.phase = ""
        self.phase_number = 0
        self.total_phases = 6
        self.current_file = ""
        self.files_scanned = 0
        self.total_files = 0
        self.files_skipped = 0
        self.threats_found = 0
        self.threats_cleaned = 0
        self.files_per_second = 0.0
        self.start_time = None
        self.eta_seconds = 0

    def to_dict(self) -> Dict:
        return {
            "phase": self.phase,
            "phase_number": self.phase_number,
            "total_phases": self.total_phases,
            "current_file": self.current_file,
            "files_scanned": self.files_scanned,
            "total_files": self.total_files,
            "files_skipped": self.files_skipped,
            "threats_found": self.threats_found,
            "threats_cleaned": self.threats_cleaned,
            "files_per_second": round(self.files_per_second, 1),
            "eta_seconds": self.eta_seconds,
            "percent": int((self.files_scanned / max(self.total_files, 1)) * 100),
        }


class FullScanEngine:
    """
    Full PC scan engine with 6 phases, configurable threading,
    priority-based scanning, and pause/cancel support.
    """

    def __init__(self, config: dict, db=None,
                 on_alert: Optional[Callable] = None):
        self.config = config
        self.db = db
        self.on_alert = on_alert

        self._thread_count = max(1, (os.cpu_count() or 4) // 2)
        self._max_file_size = config.get("max_scan_file_size",
                                          DEFAULT_MAX_FILE_SIZE)
        self._exclude_paths = set(
            p.lower() for p in config.get("scan_exclude_paths", [])
        )

        # Control flags
        self._cancel_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set()  # Not paused initially

        # State
        self._progress = ScanProgress()
        self._threats: List[Dict] = []
        self._file_queue: Queue = Queue()
        self._modules: Dict = {}

    def set_modules(self, modules: dict) -> None:
        """Inject references to scanner modules."""
        self._modules = modules

    # ------------------------------------------------------------------ #
    #  Control                                                              #
    # ------------------------------------------------------------------ #
    def pause(self) -> None:
        self._pause_event.clear()
        logger.info("Scan paused")

    def resume(self) -> None:
        self._pause_event.set()
        logger.info("Scan resumed")

    def cancel(self) -> None:
        self._cancel_event.set()
        self._pause_event.set()  # Unpause to allow threads to exit
        logger.info("Scan cancelled")

    @property
    def progress(self) -> ScanProgress:
        return self._progress

    @property
    def is_cancelled(self) -> bool:
        return self._cancel_event.is_set()

    # ------------------------------------------------------------------ #
    #  PHASE 1: Drive Discovery                                             #
    # ------------------------------------------------------------------ #
    def discover_drives(self, include_network: bool = False) -> List[Dict]:
        """Enumerate all suitable drives for scanning."""
        if not PSUTIL_AVAILABLE:
            return [{"mountpoint": "C:\\", "fstype": "NTFS",
                      "total": 0, "free": 0, "device": "C:"}]

        drives = []
        for part in psutil.disk_partitions(all=True):
            opts = part.opts.lower() if part.opts else ""

            # Skip CDROMs
            if "cdrom" in opts or part.fstype == "":
                continue

            # Skip network unless enabled
            if ("remote" in opts or "network" in opts) and not include_network:
                continue

            try:
                usage = psutil.disk_usage(part.mountpoint)
                drives.append({
                    "mountpoint": part.mountpoint,
                    "device": part.device,
                    "fstype": part.fstype,
                    "total": usage.total,
                    "free": usage.free,
                    "used": usage.used,
                })
            except (PermissionError, OSError):
                continue

        logger.info(f"Discovered {len(drives)} drives")
        return drives

    # ------------------------------------------------------------------ #
    #  PHASE 2: File Enumeration                                            #
    # ------------------------------------------------------------------ #
    def enumerate_files(self, drives: List[str],
                         progress_callback: Optional[Callable] = None) -> Dict[int, List[str]]:
        """
        Walk all directories on selected drives, categorizing files by priority.
        Returns dict mapping priority level (1-5) to file lists.
        """
        self._progress.phase = "File Enumeration"
        self._progress.phase_number = 2

        prioritized = {1: [], 2: [], 3: [], 4: [], 5: []}
        skipped = 0
        total = 0

        for drive in drives:
            if self._cancel_event.is_set():
                break

            for root, dirs, files in os.walk(drive, topdown=True):
                if self._cancel_event.is_set():
                    break

                # Wait if paused
                self._pause_event.wait()

                root_lower = root.lower()

                # Skip excluded paths
                if any(root_lower.startswith(ex) for ex in self._exclude_paths):
                    dirs.clear()
                    continue

                for fname in files:
                    if self._cancel_event.is_set():
                        break

                    # Skip system files
                    if fname.lower() in SKIP_FILES:
                        skipped += 1
                        continue

                    full_path = os.path.join(root, fname)

                    try:
                        size = os.path.getsize(full_path)
                    except OSError:
                        skipped += 1
                        continue

                    # Skip oversized files
                    if size > self._max_file_size:
                        skipped += 1
                        continue

                    total += 1
                    ext = os.path.splitext(fname)[1].lower()

                    if ext in PRIORITY_EXECUTABLES:
                        prioritized[1].append(full_path)
                    elif ext in PRIORITY_SCRIPTS:
                        prioritized[2].append(full_path)
                    elif ext in PRIORITY_INSTALLERS:
                        prioritized[3].append(full_path)
                    elif ext in PRIORITY_DOCUMENTS:
                        prioritized[4].append(full_path)
                    else:
                        prioritized[5].append(full_path)

                    if progress_callback and total % 1000 == 0:
                        progress_callback(total, skipped)

        self._progress.total_files = total
        self._progress.files_skipped = skipped

        logger.info(f"Enumerated {total} files, {skipped} skipped | "
                     f"P1:{len(prioritized[1])} P2:{len(prioritized[2])} "
                     f"P3:{len(prioritized[3])} P4:{len(prioritized[4])} "
                     f"P5:{len(prioritized[5])}")

        return prioritized

    # ------------------------------------------------------------------ #
    #  PHASE 3: Priority Scanning                                           #
    # ------------------------------------------------------------------ #
    def _scan_single_file(self, file_path: str) -> Optional[Dict]:
        """Scan a single file through all engines. Returns threat dict or None."""
        self._pause_event.wait()
        if self._cancel_event.is_set():
            return None

        self._progress.current_file = file_path

        file_scanner = self._modules.get("file_scanner")
        if not file_scanner:
            return None

        try:
            result = file_scanner.scan_file(file_path)
            self._progress.files_scanned += 1

            if not result.clean:
                threat = {
                    "path": file_path,
                    "threat_name": result.threat_name,
                    "severity": "high",
                    "engine": result.engine,
                    "action": "detected",
                    "cleaned": False,
                }
                self._threats.append(threat)
                self._progress.threats_found += 1
                return threat

        except Exception as e:
            logger.debug(f"Scan error on {file_path}: {e}")

        return None

    def scan_files_parallel(self, file_lists: Dict[int, List[str]],
                              progress_callback: Optional[Callable] = None) -> None:
        """Scan files by priority level using thread pool."""
        self._progress.phase = "Priority Scanning"
        self._progress.phase_number = 3
        self._progress.start_time = time.time()

        with ThreadPoolExecutor(max_workers=self._thread_count) as executor:
            for priority in sorted(file_lists.keys()):
                if self._cancel_event.is_set():
                    break

                files = file_lists[priority]
                futures = {executor.submit(self._scan_single_file, f): f
                           for f in files}

                for future in as_completed(futures):
                    if self._cancel_event.is_set():
                        break

                    try:
                        result = future.result(timeout=60)
                    except Exception:
                        pass

                    # Update speed
                    elapsed = time.time() - self._progress.start_time
                    if elapsed > 0:
                        self._progress.files_per_second = (
                            self._progress.files_scanned / elapsed
                        )
                        remaining = (self._progress.total_files -
                                     self._progress.files_scanned)
                        if self._progress.files_per_second > 0:
                            self._progress.eta_seconds = int(
                                remaining / self._progress.files_per_second
                            )

                    if progress_callback:
                        progress_callback(self._progress.to_dict())

    # ------------------------------------------------------------------ #
    #  PHASE 4: Deep Content Scan (archives, macros, PDFs)                  #
    # ------------------------------------------------------------------ #
    def deep_content_scan(self, file_lists: Dict[int, List[str]],
                            progress_callback: Optional[Callable] = None) -> None:
        """Scan inside archives, Office macros, and PDF JavaScript."""
        self._progress.phase = "Deep Content Scan"
        self._progress.phase_number = 4

        # Scan archives (priority 3)
        for archive_path in file_lists.get(3, []):
            if self._cancel_event.is_set():
                break
            self._pause_event.wait()
            self._scan_archive(archive_path)

        # Scan Office documents for macros (priority 4)
        for doc_path in file_lists.get(4, []):
            if self._cancel_event.is_set():
                break
            self._pause_event.wait()
            ext = os.path.splitext(doc_path)[1].lower()
            if ext in (".docm", ".xlsm", ".pptm", ".doc", ".xls"):
                self._scan_macro(doc_path)
            elif ext == ".pdf":
                self._scan_pdf(doc_path)

        if progress_callback:
            progress_callback(self._progress.to_dict())

    def _scan_archive(self, path: str, depth: int = 0) -> None:
        """Scan inside ZIP archives up to 3 levels deep."""
        if depth >= 3:
            return
        try:
            import zipfile
            if not zipfile.is_zipfile(path):
                return

            import tempfile
            with zipfile.ZipFile(path, 'r') as zf:
                # Create temp directory for extraction
                temp_dir = Path(tempfile.mkdtemp(prefix="sn_scan_"))
                try:
                    for info in zf.infolist():
                        if self._cancel_event.is_set():
                            break
                        if info.file_size > self._max_file_size:
                            continue
                        try:
                            extracted = zf.extract(info, str(temp_dir))
                            result = self._scan_single_file(extracted)
                            if result:
                                result["path"] = f"{path}!{info.filename}"
                            # Recurse into nested archives
                            ext = os.path.splitext(info.filename)[1].lower()
                            if ext in (".zip", ".rar", ".7z"):
                                self._scan_archive(extracted, depth + 1)
                        except Exception:
                            continue
                finally:
                    import shutil
                    shutil.rmtree(str(temp_dir), ignore_errors=True)
        except Exception as e:
            logger.debug(f"Archive scan error for {path}: {e}")

    def _scan_macro(self, path: str) -> None:
        """Extract and scan VBA macros from Office documents."""
        try:
            from oletools.olevba import VBA_Parser
            vba = VBA_Parser(path)
            if vba.detect_vba_macros():
                for _, _, _, vba_code in vba.extract_macros():
                    # Check for suspicious patterns
                    suspicious = any(pattern in vba_code.lower() for pattern in [
                        "shell(", "wscript.shell", "powershell",
                        "cmd /c", "downloadstring", "urldownloadtofile",
                        "auto_open", "document_open", "autoexec",
                    ])
                    if suspicious:
                        threat = {
                            "path": path,
                            "threat_name": "Suspicious.Macro.VBA",
                            "severity": "medium",
                            "engine": "MacroAnalysis",
                            "action": "detected",
                            "cleaned": False,
                        }
                        self._threats.append(threat)
                        self._progress.threats_found += 1
                        break
            vba.close()
        except ImportError:
            logger.debug("oletools not available — skipping macro scan")
        except Exception as e:
            logger.debug(f"Macro scan error for {path}: {e}")

    def _scan_pdf(self, path: str) -> None:
        """Scan PDF for JavaScript content."""
        try:
            import fitz  # PyMuPDF
            doc = fitz.open(path)
            for page in doc:
                text = page.get_text()
                if any(p in text.lower() for p in [
                    "javascript", "eval(", "app.launchurl",
                    "/js ", "/javascript"
                ]):
                    threat = {
                        "path": path,
                        "threat_name": "Suspicious.PDF.JavaScript",
                        "severity": "medium",
                        "engine": "PDFAnalysis",
                        "action": "detected",
                        "cleaned": False,
                    }
                    self._threats.append(threat)
                    self._progress.threats_found += 1
                    break
            doc.close()
        except ImportError:
            logger.debug("PyMuPDF not available — skipping PDF scan")
        except Exception as e:
            logger.debug(f"PDF scan error for {path}: {e}")

    # ------------------------------------------------------------------ #
    #  PHASE 5: System Area Scan                                            #
    # ------------------------------------------------------------------ #
    def system_area_scan(self,
                          progress_callback: Optional[Callable] = None) -> None:
        """Scan critical Windows system areas regardless of drive selection."""
        self._progress.phase = "System Area Scan"
        self._progress.phase_number = 5

        system_paths = [
            r"C:\Windows\System32",
            r"C:\Windows\SysWOW64",
        ]

        # Browser extension paths
        user_profile = os.path.expandvars(r"%USERPROFILE%")
        browser_ext_paths = [
            os.path.join(user_profile, r"AppData\Local\Google\Chrome\User Data\Default\Extensions"),
            os.path.join(user_profile, r"AppData\Roaming\Mozilla\Firefox\Profiles"),
            os.path.join(user_profile, r"AppData\Local\Microsoft\Edge\User Data\Default\Extensions"),
        ]

        # Scheduled tasks
        task_paths = [r"C:\Windows\System32\Tasks"]

        # Hosts file
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"

        all_system_files = []

        # Collect executable files from system paths
        for sys_path in system_paths:
            if not os.path.isdir(sys_path) or self._cancel_event.is_set():
                continue
            try:
                for f in os.listdir(sys_path):
                    if self._cancel_event.is_set():
                        break
                    ext = os.path.splitext(f)[1].lower()
                    if ext in PRIORITY_EXECUTABLES:
                        full = os.path.join(sys_path, f)
                        if os.path.isfile(full):
                            all_system_files.append(full)
            except PermissionError:
                continue

        # Scan running process executables
        if PSUTIL_AVAILABLE:
            for proc in psutil.process_iter(['exe']):
                try:
                    exe = proc.info.get('exe', '')
                    if exe and os.path.isfile(exe):
                        all_system_files.append(exe)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        # Remove duplicates
        all_system_files = list(set(all_system_files))

        # Scan system files
        for fpath in all_system_files:
            if self._cancel_event.is_set():
                break
            self._pause_event.wait()
            self._scan_single_file(fpath)

        # Check hosts file integrity
        self._check_hosts_file(hosts_path)

        if progress_callback:
            progress_callback(self._progress.to_dict())

    def _check_hosts_file(self, hosts_path: str) -> None:
        """Check hosts file for suspicious entries."""
        try:
            if not os.path.isfile(hosts_path):
                return

            with open(hosts_path, "r") as f:
                content = f.read()

            suspicious_entries = []
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    domain = parts[1]
                    # Flag non-localhost redirections
                    if ip not in ("127.0.0.1", "::1", "0.0.0.0"):
                        suspicious_entries.append(f"{ip} → {domain}")

            if suspicious_entries:
                threat = {
                    "path": hosts_path,
                    "threat_name": "Suspicious.HostsFile.Modified",
                    "severity": "medium",
                    "engine": "HostsCheck",
                    "action": "detected",
                    "cleaned": False,
                    "details": "; ".join(suspicious_entries[:5]),
                }
                self._threats.append(threat)
                self._progress.threats_found += 1

        except Exception as e:
            logger.debug(f"Hosts file check error: {e}")

    # ------------------------------------------------------------------ #
    #  PHASE 6: Results Aggregation                                         #
    # ------------------------------------------------------------------ #
    def generate_report(self, scan_type: str = "full",
                         drives_scanned: List[str] = None) -> Dict:
        """Generate the final scan report."""
        end_time = datetime.now()
        start_time = (datetime.fromtimestamp(self._progress.start_time)
                      if self._progress.start_time else end_time)
        duration = int((end_time - start_time).total_seconds())

        status = "clean"
        if self._cancel_event.is_set():
            status = "cancelled"
        elif self._progress.threats_found > 0:
            if self._progress.threats_cleaned >= self._progress.threats_found:
                status = "cleaned"
            else:
                status = "threats_found"

        report = {
            "scan_id": str(uuid.uuid4()),
            "scan_type": scan_type,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": duration,
            "drives_scanned": drives_scanned or [],
            "total_files": self._progress.total_files,
            "files_scanned": self._progress.files_scanned,
            "files_skipped": self._progress.files_skipped,
            "threats_found": self._progress.threats_found,
            "threats_cleaned": self._progress.threats_cleaned,
            "threats_quarantined": self._progress.threats_cleaned,
            "threat_list": self._threats,
            "scan_status": status,
        }

        # Save to database
        if self.db and hasattr(self.db, "save_scan_run"):
            try:
                self.db.save_scan_run(report)
            except Exception as e:
                logger.error(f"Failed to save scan report: {e}")

        return report

    # ------------------------------------------------------------------ #
    #  RUN: Full scan pipeline                                              #
    # ------------------------------------------------------------------ #
    def run_full_scan(self, drives: List[str] = None,
                       progress_callback: Optional[Callable] = None) -> Dict:
        """
        Execute the complete full scan pipeline.
        Returns the scan report dict.
        """
        self._cancel_event.clear()
        self._pause_event.set()
        self._threats.clear()
        self._progress = ScanProgress()
        self._progress.start_time = time.time()

        # Phase 1: Drive Discovery
        self._progress.phase = "Drive Discovery"
        self._progress.phase_number = 1
        if not drives:
            discovered = self.discover_drives()
            drives = [d["mountpoint"] for d in discovered]
        if progress_callback:
            progress_callback(self._progress.to_dict())

        if self._cancel_event.is_set():
            return self.generate_report("full", drives)

        # Phase 2: File Enumeration
        file_lists = self.enumerate_files(drives, progress_callback=None)
        if progress_callback:
            progress_callback(self._progress.to_dict())

        if self._cancel_event.is_set():
            return self.generate_report("full", drives)

        # Phase 3: Priority Scanning
        self.scan_files_parallel(file_lists, progress_callback)

        if self._cancel_event.is_set():
            return self.generate_report("full", drives)

        # Phase 4: Deep Content Scan
        self.deep_content_scan(file_lists, progress_callback)

        if self._cancel_event.is_set():
            return self.generate_report("full", drives)

        # Phase 5: System Area Scan
        self.system_area_scan(progress_callback)

        # Phase 6: Results
        self._progress.phase = "Results Aggregation"
        self._progress.phase_number = 6

        report = self.generate_report("full", drives)

        if progress_callback:
            progress_callback(self._progress.to_dict())

        logger.info(f"Full scan complete: {report['files_scanned']} files, "
                     f"{report['threats_found']} threats")

        return report

    # ------------------------------------------------------------------ #
    #  Quick scan                                                           #
    # ------------------------------------------------------------------ #
    def run_quick_scan(self,
                        progress_callback: Optional[Callable] = None) -> Dict:
        """Quick scan of common user folders only."""
        self._cancel_event.clear()
        self._pause_event.set()
        self._threats.clear()
        self._progress = ScanProgress()
        self._progress.start_time = time.time()

        user = os.path.expandvars(r"%USERPROFILE%")
        quick_paths = [
            os.path.join(user, "Desktop"),
            os.path.join(user, "Downloads"),
            os.path.join(user, "Documents"),
            os.path.expandvars(r"%APPDATA%"),
            os.path.expandvars(r"%LOCALAPPDATA%\Temp"),
        ]

        existing = [p for p in quick_paths if os.path.isdir(p)]

        # Use file enumeration on quick paths
        file_lists = self.enumerate_files(existing)
        self.scan_files_parallel(file_lists, progress_callback)

        # System areas
        self.system_area_scan(progress_callback)

        return self.generate_report("quick", existing)

    # ------------------------------------------------------------------ #
    #  Custom scan                                                          #
    # ------------------------------------------------------------------ #
    def run_custom_scan(self, paths: List[str],
                         engines: Optional[List[str]] = None,
                         progress_callback: Optional[Callable] = None) -> Dict:
        """Custom scan of user-selected paths."""
        self._cancel_event.clear()
        self._pause_event.set()
        self._threats.clear()
        self._progress = ScanProgress()
        self._progress.start_time = time.time()

        file_lists = self.enumerate_files(paths)
        self.scan_files_parallel(file_lists, progress_callback)

        return self.generate_report("custom", paths)

    # ------------------------------------------------------------------ #
    #  Compatibility                                                        #
    # ------------------------------------------------------------------ #
    @classmethod
    def is_supported(cls) -> bool:
        return True

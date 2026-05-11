"""
scanner/scan_pipeline.py — Shared scan pipeline components

Eliminates duplication across full_scan, antivirus_scan, and deep_scan.
Provides: ScanProgress, ScanReportBuilder, ParallelFileScanner.
"""
import logging
import os
import time
import uuid
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Callable, Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class ScanProgress:
    """Shared scan progress tracker."""

    def __init__(self, total_phases: int = 1):
        self.phase = ""
        self.phase_number = 0
        self.total_phases = total_phases
        self.current_file = ""
        self.files_scanned = 0
        self.total_files = 0
        self.files_skipped = 0
        self.threats_found = 0
        self.threats_cleaned = 0
        self.files_per_second = 0.0
        self.start_time = None
        self.eta_seconds = 0
        self.errors: List[Dict] = []

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
            "errors_count": len(self.errors),
        }

    def update_speed(self):
        if self.start_time:
            elapsed = time.time() - self.start_time
            if elapsed > 0:
                self.files_per_second = self.files_scanned / elapsed
                remaining = self.total_files - self.files_scanned
                if self.files_per_second > 0:
                    self.eta_seconds = int(remaining / self.files_per_second)


class ScanReportBuilder:
    """Generates standardized scan report dicts."""

    @staticmethod
    def build(scan_type: str, progress: ScanProgress, threats: List[Dict],
              drives: List[str] = None, errors: List[Dict] = None) -> Dict:
        end_time = datetime.now()
        start_time = (datetime.fromtimestamp(progress.start_time)
                      if progress.start_time else end_time)
        duration = int((end_time - start_time).total_seconds())

        status = "clean"
        if progress.threats_found > 0:
            if progress.threats_cleaned >= progress.threats_found:
                status = "cleaned"
            else:
                status = "threats_found"

        return {
            "scan_id": str(uuid.uuid4()),
            "scan_type": scan_type,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": duration,
            "drives_scanned": drives or [],
            "total_files": progress.total_files,
            "files_scanned": progress.files_scanned,
            "files_skipped": progress.files_skipped,
            "threats_found": progress.threats_found,
            "threats_cleaned": progress.threats_cleaned,
            "threats_quarantined": progress.threats_cleaned,
            "threat_list": threats,
            "scan_status": status,
            "errors": errors or progress.errors,
        }

    @staticmethod
    def save_to_db(db, report: Dict) -> None:
        if db and hasattr(db, "save_scan_run"):
            try:
                db.save_scan_run(report)
            except Exception as e:
                logger.error(f"Failed to save scan report: {e}")


class ParallelFileScanner:
    """Reusable parallel file scanning with cancel/pause support."""

    def __init__(self, file_scanner, thread_count: int = None,
                 cancel_event: threading.Event = None,
                 pause_event: threading.Event = None):
        self.file_scanner = file_scanner
        self.thread_count = thread_count or max(1, (os.cpu_count() or 4) // 2)
        self.cancel_event = cancel_event or threading.Event()
        self.pause_event = pause_event or threading.Event()
        self.pause_event.set()

    def scan_files(self, files: List[str], progress: ScanProgress,
                   threats: List[Dict],
                   progress_callback: Optional[Callable] = None) -> None:
        """Scan a list of files in parallel, updating progress and threats."""
        if not self.file_scanner:
            logger.warning("No file_scanner module available for parallel scan")
            return

        with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
            futures = {executor.submit(self._scan_one, f, progress, threats): f
                       for f in files}

            for future in as_completed(futures):
                if self.cancel_event.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                try:
                    future.result(timeout=60)
                except Exception as e:
                    progress.errors.append({
                        "error_type": "ScanError",
                        "message": str(e),
                        "path": futures[future],
                    })
                progress.update_speed()
                if progress_callback:
                    progress_callback(progress.to_dict())

    def _scan_one(self, file_path: str, progress: ScanProgress,
                  threats: List[Dict]) -> Optional[Dict]:
        self.pause_event.wait()
        if self.cancel_event.is_set():
            return None

        progress.current_file = file_path

        try:
            result = self.file_scanner.scan_file(file_path)
            progress.files_scanned += 1

            if not result.clean:
                threat = {
                    "path": file_path,
                    "threat_name": result.threat_name,
                    "severity": "high",
                    "engine": result.engine,
                    "action": "detected",
                    "cleaned": False,
                    "confidence": getattr(result, "confidence", 0),
                }
                threats.append(threat)
                progress.threats_found += 1
                return threat

        except PermissionError:
            progress.files_skipped += 1
            progress.errors.append({
                "error_type": "PermissionDenied",
                "message": f"Access denied: {file_path}",
                "path": file_path,
                "severity": "low",
            })
        except Exception as e:
            logger.debug(f"Scan error on {file_path}: {e}")
            progress.errors.append({
                "error_type": "ScanError",
                "message": str(e),
                "path": file_path,
            })

        return None

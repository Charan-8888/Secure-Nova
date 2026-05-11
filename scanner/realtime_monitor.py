"""
scanner/realtime_monitor.py — Watchdog-based real-time filesystem monitor
"""
import logging
import threading
from pathlib import Path
from typing import Callable, List

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    logging.warning("watchdog not installed — real-time monitoring disabled")

logger = logging.getLogger(__name__)

# Extensions to skip (avoid scanning media/archives that aren't executable)
SKIP_EXTENSIONS = {
    ".mp4", ".mp3", ".mkv", ".avi", ".mov", ".wav", ".flac",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg",
    ".zip", ".rar", ".7z", ".tar", ".gz",
    ".db", ".sqlite", ".quarantine",
}


class _EventHandler(FileSystemEventHandler if WATCHDOG_AVAILABLE else object):
    def __init__(self, scanner, on_event: Callable):
        if WATCHDOG_AVAILABLE:
            super().__init__()
        self.scanner = scanner
        self.on_event = on_event

    def _should_scan(self, path: str) -> bool:
        p = Path(path)
        return p.suffix.lower() not in SKIP_EXTENSIONS and p.is_file()

    def on_created(self, event):
        if not event.is_directory and self._should_scan(event.src_path):
            self.on_event(event.src_path)

    def on_modified(self, event):
        if not event.is_directory and self._should_scan(event.src_path):
            self.on_event(event.src_path)


class RealtimeMonitor:
    """
    Watches configured directories and triggers FileScanner on events.
    """

    def __init__(self, config: dict, scanner, on_threat: Callable = None):
        self.config = config
        self.scanner = scanner
        self.on_threat = on_threat
        self._observer = None
        self._running = False
        self._scan_queue: List[str] = []
        self._queue_lock = threading.Lock()
        self._worker_thread: threading.Thread | None = None

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self) -> bool:
        if not WATCHDOG_AVAILABLE:
            logger.error("watchdog library not available")
            return False
        if self._running:
            return True

        paths = self._resolve_paths()
        if not paths:
            logger.warning("No valid scan paths configured")
            return False

        handler = _EventHandler(self.scanner, self._enqueue)
        self._observer = Observer()
        for path in paths:
            try:
                self._observer.schedule(handler, str(path), recursive=True)
                logger.info(f"Watching: {path}")
            except Exception as e:
                logger.error(f"Could not watch {path}: {e}")

        self._observer.start()
        self._running = True

        # Background scan worker
        self._worker_thread = threading.Thread(
            target=self._scan_worker, name="ScanWorker", daemon=True
        )
        self._worker_thread.start()

        logger.info("Real-time monitor started")
        return True

    def stop(self) -> None:
        self._running = False
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
        logger.info("Real-time monitor stopped")

    def _resolve_paths(self) -> List[Path]:
        import os
        paths = []
        for raw in self.config.get("scan_paths", []):
            expanded = os.path.expandvars(raw)
            p = Path(expanded)
            if p.exists():
                paths.append(p)
            else:
                logger.warning(f"Scan path does not exist: {p}")
        return paths

    def _enqueue(self, path: str) -> None:
        with self._queue_lock:
            if path not in self._scan_queue:
                self._scan_queue.append(path)

    def _scan_worker(self) -> None:
        import time
        while self._running:
            to_scan = []
            with self._queue_lock:
                if self._scan_queue:
                    to_scan = self._scan_queue.copy()
                    self._scan_queue.clear()
            for path in to_scan:
                try:
                    result = self.scanner.scan_file(path)
                    if not result.clean and self.on_threat:
                        self.on_threat(result)
                except Exception as e:
                    logger.error(f"Scan worker error on {path}: {e}")
            time.sleep(0.5)

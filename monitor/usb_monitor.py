"""
monitor/usb_monitor.py — USB insertion detection and auto-scan
"""
import logging
import threading
from typing import Callable, Optional

logger = logging.getLogger(__name__)

try:
    import wmi as wmi_module
    WMI_AVAILABLE = True
except ImportError:
    WMI_AVAILABLE = False
    logger.warning("wmi not installed — USB monitor disabled")


class USBMonitor:
    def __init__(self, config: dict, scanner=None,
                 on_alert: Optional[Callable[[dict], None]] = None):
        self.config = config
        self.scanner = scanner
        self.on_alert = on_alert
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if not WMI_AVAILABLE:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, name="USBMonitor", daemon=True)
        self._thread.start()
        logger.info("USB monitor started")

    def stop(self) -> None:
        self._running = False

    def _run(self) -> None:
        try:
            c = wmi_module.WMI()
            watcher = c.Win32_VolumeChangeEvent.watch_for("creation")
            while self._running:
                try:
                    event = watcher(timeout_ms=3000)
                    if event and event.EventType == 2:  # insertion
                        drive = event.DriveName
                        logger.info(f"USB inserted: {drive}")
                        self._on_usb_inserted(drive)
                except Exception:
                    pass
        except Exception as e:
            logger.error(f"USB monitor WMI error: {e}")

    def _on_usb_inserted(self, drive: str) -> None:
        if self.on_alert:
            self.on_alert({
                "type": "usb_inserted",
                "severity": "low",
                "detail": f"USB drive inserted: {drive}",
                "path": drive,
            })
        if self.scanner:
            self._scan_drive(drive)

    def _scan_drive(self, drive: str) -> None:
        import os
        from pathlib import Path
        drive_path = Path(drive)
        if not drive_path.exists():
            return
        threats = []
        for root, _, files in os.walk(drive):
            for fname in files:
                fp = os.path.join(root, fname)
                try:
                    result = self.scanner.scan_file(fp)
                    if not result.clean:
                        threats.append(fp)
                except Exception:
                    pass

        summary = f"USB scan complete: {len(threats)} threat(s) found on {drive}"
        logger.info(summary)
        if self.on_alert:
            severity = "high" if threats else "low"
            self.on_alert({
                "type": "usb_scan_complete",
                "severity": severity,
                "detail": summary,
                "path": drive,
            })

        if threats and self.config.get("auto_eject_usb_on_threat", False):
            self._eject_drive(drive)

    @staticmethod
    def _eject_drive(drive: str) -> None:
        import subprocess
        try:
            # PowerShell eject
            script = (
                f"$vol = Get-WmiObject Win32_Volume -Filter \"DriveLetter='{drive[0]}:'\";"
                "$vol.Dismount($true, $false)"
            )
            subprocess.run(["powershell", "-Command", script], check=False, timeout=10)
            logger.info(f"Ejected drive: {drive}")
        except Exception as e:
            logger.error(f"Eject failed: {e}")

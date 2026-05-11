"""
monitor/registry_watcher.py — Windows registry startup key monitor
"""
import logging
import threading
import time
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    import winreg
    WINREG_AVAILABLE = True
except ImportError:
    WINREG_AVAILABLE = False
    logger.warning("winreg not available — registry watcher disabled")

STARTUP_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE if WINREG_AVAILABLE else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE if WINREG_AVAILABLE else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_CURRENT_USER if WINREG_AVAILABLE else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER if WINREG_AVAILABLE else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
] if WINREG_AVAILABLE else []


def _read_run_key(hive, subkey: str) -> Dict[str, str]:
    entries = {}
    try:
        key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
        i = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, i)
                entries[name] = value
                i += 1
            except OSError:
                break
        winreg.CloseKey(key)
    except FileNotFoundError:
        pass
    except Exception as e:
        logger.error(f"Registry read error [{subkey}]: {e}")
    return entries


class RegistryWatcher:
    def __init__(self, db=None, on_alert: Optional[Callable[[dict], None]] = None):
        self.db = db
        self.on_alert = on_alert
        self._baseline: Dict[str, Dict[str, str]] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if not WINREG_AVAILABLE:
            return
        self._take_baseline()
        self._running = True
        self._thread = threading.Thread(target=self._run, name="RegistryWatcher", daemon=True)
        self._thread.start()
        logger.info("Registry watcher started")

    def stop(self) -> None:
        self._running = False

    def _take_baseline(self) -> None:
        for hive, subkey in STARTUP_KEYS:
            key_id = f"{hive}\\{subkey}"
            entries = _read_run_key(hive, subkey)
            self._baseline[key_id] = entries
            if self.db:
                for name, path in entries.items():
                    self.db.snapshot_startup_item(name, path, key_id)
        logger.info(f"Registry baseline: {sum(len(v) for v in self._baseline.values())} entries")

    def _run(self) -> None:
        while self._running:
            try:
                self._check()
            except Exception as e:
                logger.error(f"Registry watcher error: {e}")
            time.sleep(10)

    def _check(self) -> None:
        for hive, subkey in STARTUP_KEYS:
            key_id = f"{hive}\\{subkey}"
            current = _read_run_key(hive, subkey)
            baseline = self._baseline.get(key_id, {})
            for name, value in current.items():
                if name not in baseline:
                    logger.warning(f"NEW startup entry: [{key_id}] {name} = {value}")
                    alert = {"type": "registry_hijack", "severity": "high",
                             "path": value, "detail": f"New Run key: '{name}' in {key_id}"}
                    if self.db:
                        self.db.log_threat("registry_hijack", "high", value,
                                           alert["detail"], "alert")
                        self.db.snapshot_startup_item(name, value, key_id)
                    if self.on_alert:
                        self.on_alert(alert)
                    self._baseline[key_id][name] = value

    def get_startup_items(self) -> List[dict]:
        items = []
        for hive, subkey in STARTUP_KEYS:
            key_id = f"{hive}\\{subkey}"
            for name, value in _read_run_key(hive, subkey).items():
                items.append({"name": name, "path": value, "location": key_id,
                              "trusted": name in self._baseline.get(key_id, {})})
        return items

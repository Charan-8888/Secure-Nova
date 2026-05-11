"""
main.py — SecureNova Personal Security Suite entry point
"""
import ctypes
import json
import os
import sys
import threading
from pathlib import Path

# ─── Ensure project root is in path ─────────────────────────────────────────
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

from utils.logger   import setup_logging
from utils.database import get_db
from utils.updater  import Updater
from utils.event_bus import EventBus, create_alert_bridge, EventTypes


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def elevate_uac() -> None:
    """Re-launch the script with UAC elevation."""
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )
    sys.exit(0)


def load_config() -> dict:
    config_path = ROOT / "config" / "settings.json"
    try:
        with open(config_path) as f:
            cfg = json.load(f)
        # Expand %USERNAME% in paths
        for key in ("scan_paths", "quarantine_path"):
            if isinstance(cfg.get(key), list):
                cfg[key] = [os.path.expandvars(p) for p in cfg[key]]
            elif isinstance(cfg.get(key), str):
                cfg[key] = os.path.expandvars(cfg[key])
        return cfg
    except Exception as e:
        print(f"[WARNING] Could not load config: {e} — using defaults")
        return {"scan_paths": [], "quarantine_path": "quarantine",
                "auto_quarantine": True, "virustotal_api_key": "",
                "whitelist_processes": ["explorer.exe", "svchost.exe"],
                "notifications_enabled": True, "log_level": "INFO",
                "blocklist_refresh_hours": 6, "hash_db_refresh_hours": 24,
                "process_poll_interval": 2, "network_poll_interval": 5,
                "vt_rate_limit_seconds": 15, "vt_malicious_threshold": 3}


def main() -> None:
    # ── 1. Admin check ───────────────────────────────────────────────────
    if not is_admin():
        print("[INFO] Not running as administrator — some features (hosts file, registry) "
              "require elevation.")
        # Don't force-elevate; the app can still run with limited features

    # ── 2. Config & logging ──────────────────────────────────────────────
    config = load_config()
    setup_logging(config.get("log_level", "INFO"))

    import logging
    logger = logging.getLogger(__name__)
    logger.info("SecureNova starting…")

    # ── 3. Database ───────────────────────────────────────────────────────
    db = get_db()

    # ── 4. Launch PyQt6 application ──────────────────────────────────────
    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtCore import Qt
    app = QApplication(sys.argv)
    app.setApplicationName("SecureNova")
    app.setOrganizationName("SecureNova")
    app.setQuitOnLastWindowClosed(False)  # allow tray-only mode

    # ── 5. Instantiate modules ───────────────────────────────────────────
    from gui.main_window import MainWindow

    # We need the window first for callbacks
    window = MainWindow(config, db, {})

    def on_threat(result):
        window.emit_alert({
            "type": result.threat_type,
            "severity": "high",
            "detail": f"{result.threat_name} — {result.path}",
            "path": result.path,
            "confidence": getattr(result, 'confidence', 0),
        })

    # Create event bus and alert bridge
    event_bus = EventBus()
    on_alert = create_alert_bridge(event_bus)

    # Bridge events to GUI
    event_bus.subscribe_all(lambda evt: window.emit_alert(evt.to_alert()))

    # File scanner
    from scanner.file_scanner import FileScanner
    from scanner.realtime_monitor import RealtimeMonitor
    scanner = FileScanner(config, db, on_threat=on_threat)

    realtime_monitor = RealtimeMonitor(config, scanner, on_threat=on_threat)

    # VirusTotal
    from scanner.virustotal import VirusTotalChecker
    vt = VirusTotalChecker(
        config.get("virustotal_api_key", ""),
        db,
        rate_limit_seconds=config.get("vt_rate_limit_seconds", 15),
        malicious_threshold=config.get("vt_malicious_threshold", 3)
    )

    # Process monitor
    from monitor.process_monitor import ProcessMonitor
    process_monitor = ProcessMonitor(config, db, on_alert=on_alert)

    # Registry watcher
    from monitor.registry_watcher import RegistryWatcher
    registry_watcher = RegistryWatcher(db, on_alert=on_alert)

    # Network monitors
    from network.connection_monitor import ConnectionMonitor
    from network.blocklist_manager  import BlocklistManager
    connection_monitor = ConnectionMonitor(config, db, on_alert=on_alert)
    blocklist_manager  = BlocklistManager(config, db)

    # USB monitor
    from monitor.usb_monitor import USBMonitor
    usb_monitor = USBMonitor(config, scanner, on_alert=on_alert)

    # Startup manager
    from monitor.startup_manager import StartupManager
    startup_manager = StartupManager(db, registry_watcher, on_alert=on_alert)

    # Updater
    updater = Updater(config, db)

    # ── NEW: App Reputation Scanner ──────────────────────────────────────
    from scanner.app_reputation import AppReputationScanner
    app_reputation = AppReputationScanner(config, db, on_alert=on_alert)

    # ── NEW: Threat Cleaner ──────────────────────────────────────────────
    from scanner.threat_cleaner import ThreatCleaner
    threat_cleaner = ThreatCleaner(config, db, on_alert=on_alert)

    # ── NEW: Full Scan Engine ────────────────────────────────────────────
    from scanner.full_scan import FullScanEngine
    full_scan = FullScanEngine(config, db, on_alert=on_alert)

    # ── NEW: Antivirus Scan Engine ───────────────────────────────────────
    from scanner.antivirus_scan import AntivirusScanEngine
    antivirus_scan = AntivirusScanEngine(config, db, on_alert=on_alert)

    # ── NEW: Deep Scan Engine ────────────────────────────────────────────
    from scanner.deep_scan import DeepScanEngine
    deep_scan = DeepScanEngine(config, db, on_alert=on_alert)

    # ── 6. Wire modules into window ──────────────────────────────────────
    modules = {
        "file_scanner":       scanner,
        "realtime_monitor":   realtime_monitor,
        "virustotal":         vt,
        "process_monitor":    process_monitor,
        "registry_watcher":   registry_watcher,
        "connection_monitor": connection_monitor,
        "blocklist_manager":  blocklist_manager,
        "usb_monitor":        usb_monitor,
        "startup_manager":    startup_manager,
        "updater":            updater,
        "app_reputation":     app_reputation,
        "threat_cleaner":     threat_cleaner,
        "full_scan":          full_scan,
        "antivirus_scan":     antivirus_scan,
        "deep_scan":          deep_scan,
        "event_bus":          event_bus,
    }

    # Inject cross-references so engines can use each other
    app_reputation.set_modules(modules)
    full_scan.set_modules(modules)
    antivirus_scan.set_modules(modules)
    deep_scan.set_modules(modules)
    window.modules = modules
    # Rebind module references in panels
    for panel in window._panels.values():
        panel.modules = modules

    # ── 7. Start background monitors ─────────────────────────────────────
    logger.info("Starting background monitors…")
    process_monitor.start()
    registry_watcher.start()
    connection_monitor.start()
    blocklist_manager.start()
    usb_monitor.start()
    updater.start()

    # Startup snapshot (one-time)
    threading.Thread(target=startup_manager.snapshot_all, daemon=True).start()

    # Auto-start real-time monitor
    realtime_monitor.start()

    # ── 8. Show window and enter event loop ──────────────────────────────
    window.show()
    logger.info("SecureNova GUI started")

    exit_code = app.exec()

    # ── 9. Graceful shutdown ─────────────────────────────────────────────
    logger.info("Shutting down…")
    realtime_monitor.stop()
    process_monitor.stop()
    registry_watcher.stop()
    connection_monitor.stop()
    blocklist_manager.stop()
    usb_monitor.stop()
    updater.stop()
    logger.info("SecureNova stopped cleanly")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

"""
gui/main_window.py — SecureNova main PyQt6 dashboard
"""
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread, QSize
from PyQt6.QtGui import (QColor, QFont, QIcon, QPalette, QPixmap,
                          QAction, QLinearGradient, QPainter)
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QStackedWidget, QFrame, QSystemTrayIcon,
    QMenu, QSizePolicy, QScrollArea
)

from gui.widgets.overview_panel        import OverviewPanel
from gui.widgets.filescan_panel        import FileScanPanel
from gui.widgets.process_panel         import ProcessPanel
from gui.widgets.network_panel         import NetworkPanel
from gui.widgets.quarantine_panel      import QuarantinePanel
from gui.widgets.settings_panel        import SettingsPanel
from gui.widgets.alert_banner          import AlertBanner
from gui.widgets.app_reputation_panel  import AppReputationPanel
from gui.widgets.scan_center_panel     import ScanCenterPanel

logger = logging.getLogger(__name__)

# ─── Color palette ─────────────────────────────────────────────────────────
BG       = "#0f1117"
SURFACE  = "#1a1d27"
BORDER   = "#2a2d3a"
PRIMARY  = "#4f8ef7"
SUCCESS  = "#4caf7d"
WARNING  = "#f5a623"
DANGER   = "#e05252"
TEXT     = "#e0e4f0"
MUTED    = "#8890a4"
ACCENT2  = "#7c5cbf"

SIDEBAR_W = 210
NAV_ITEMS = [
    ("overview",       "🛡",  "Overview"),
    ("scancenter",    "🔍",  "Scan Center"),
    ("filescan",      "📂",  "File Scan"),
    ("appreputation", "📋",  "App Reputation"),
    ("processes",     "⚙",  "Processes"),
    ("network",       "🌐",  "Network"),
    ("quarantine",    "🔒",  "Quarantine"),
    ("settings",      "⚙",  "Settings"),
]


class NavButton(QPushButton):
    def __init__(self, icon_char: str, label: str, parent=None):
        super().__init__(parent)
        self.icon_char = icon_char
        self.setCheckable(True)
        self.setText(f"  {icon_char}  {label}")
        self.setFixedHeight(46)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._badge = 0
        self._apply_style(False)

    def _apply_style(self, active: bool) -> None:
        bg = PRIMARY if active else "transparent"
        fg = "#ffffff" if active else TEXT
        self.setStyleSheet(f"""
            QPushButton {{
                background: {bg};
                color: {fg};
                border: none;
                border-radius: 10px;
                font-size: 14px;
                font-weight: {'600' if active else '400'};
                text-align: left;
                padding-left: 14px;
            }}
            QPushButton:hover {{
                background: {'#3d7ef5' if active else '#252838'};
            }}
        """)

    def setActive(self, active: bool) -> None:
        self._apply_style(active)

    def set_badge(self, count: int) -> None:
        self._badge = count
        # Badge rendered via paintEvent override would be ideal;
        # for simplicity append count to text
        base_text = self.text().split("  (")[0]
        if count:
            self.setText(f"{base_text}  ({count})")
        else:
            self.setText(base_text)


class MainWindow(QMainWindow):
    # Signals from background threads
    alert_received  = pyqtSignal(dict)
    stats_updated   = pyqtSignal(dict)

    def __init__(self, config: dict, db=None, modules: dict = None):
        super().__init__()
        self.config = config
        self.db = db
        self.modules = modules or {}
        self._current_tab = "overview"
        self._unread = 0

        self.setWindowTitle("SecureNova — Personal Security Suite")
        self.setMinimumSize(1100, 720)
        self.resize(1280, 800)
        self._apply_dark_theme()
        self._build_ui()
        self._setup_tray()
        self._start_stats_timer()

        # Connect alert signal
        self.alert_received.connect(self._on_alert)

    # ------------------------------------------------------------------ #
    #  Theme                                                                #
    # ------------------------------------------------------------------ #
    def _apply_dark_theme(self) -> None:
        self.setStyleSheet(f"""
            QMainWindow, QWidget {{
                background-color: {BG};
                color: {TEXT};
                font-family: 'Segoe UI', 'Inter', sans-serif;
                font-size: 13px;
            }}
            QScrollBar:vertical {{
                background: {SURFACE};
                width: 8px;
                border-radius: 4px;
            }}
            QScrollBar::handle:vertical {{
                background: {BORDER};
                border-radius: 4px;
                min-height: 20px;
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0px;
            }}
            QToolTip {{
                background-color: {SURFACE};
                color: {TEXT};
                border: 1px solid {BORDER};
                border-radius: 6px;
                padding: 4px 8px;
            }}
        """)

    # ------------------------------------------------------------------ #
    #  UI construction                                                      #
    # ------------------------------------------------------------------ #
    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Top bar
        root.addWidget(self._build_topbar())

        # Alert banner (hidden by default)
        self._alert_banner = AlertBanner()
        self._alert_banner.hide()
        root.addWidget(self._alert_banner)

        # Main body — sidebar first, then content area (panels must exist before
        # _switch_tab is called, so build content area before activating a tab)
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        body.addWidget(self._build_sidebar())
        body.addWidget(self._build_content_area(), 1)
        root.addLayout(body, 1)

        # Now that _panels and _stack both exist, activate the default tab
        self._switch_tab("overview")

    def _build_topbar(self) -> QWidget:
        bar = QFrame()
        bar.setFixedHeight(58)
        bar.setStyleSheet(f"""
            QFrame {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #141720, stop:1 #1a1d2e);
                border-bottom: 1px solid {BORDER};
            }}
        """)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(20, 0, 20, 0)

        # Logo
        logo = QLabel("🛡 SecureNova")
        logo.setStyleSheet(f"color: {PRIMARY}; font-size: 20px; font-weight: 700;")

        # Status badge
        self._status_label = QLabel("● PROTECTED")
        self._status_label.setStyleSheet(f"""
            color: {SUCCESS}; font-size: 12px; font-weight: 600;
            background: rgba(76,175,125,0.15); border-radius: 12px;
            padding: 4px 14px;
        """)

        # Clock
        self._clock = QLabel()
        self._clock.setStyleSheet(f"color: {MUTED}; font-size: 12px;")
        self._update_clock()
        clock_timer = QTimer(self)
        clock_timer.timeout.connect(self._update_clock)
        clock_timer.start(1000)

        layout.addWidget(logo)
        layout.addStretch()
        layout.addWidget(self._status_label)
        layout.addSpacing(20)
        layout.addWidget(self._clock)
        return bar

    def _build_sidebar(self) -> QWidget:
        sidebar = QFrame()
        sidebar.setFixedWidth(SIDEBAR_W)
        sidebar.setStyleSheet(f"""
            QFrame {{
                background: {SURFACE};
                border-right: 1px solid {BORDER};
            }}
        """)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(12, 20, 12, 20)
        layout.setSpacing(4)

        self._nav_buttons: dict[str, NavButton] = {}
        for key, icon, label in NAV_ITEMS:
            btn = NavButton(icon, label)
            btn.clicked.connect(lambda checked, k=key: self._switch_tab(k))
            self._nav_buttons[key] = btn
            layout.addWidget(btn)

        layout.addStretch()

        # Version info
        ver = QLabel("v1.0.0  |  SecureNova")
        ver.setStyleSheet(f"color: {MUTED}; font-size: 10px;")
        ver.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(ver)

        # Do NOT call _switch_tab here — _panels doesn't exist yet at this point.
        # The call is made at the end of _build_ui() after _build_content_area().
        return sidebar

    def _build_content_area(self) -> QWidget:
        self._stack = QStackedWidget()
        self._stack.setStyleSheet("background: transparent;")

        self._panels = {
            "overview":       OverviewPanel(self.config, self.db, self.modules),
            "scancenter":    ScanCenterPanel(self.config, self.db, self.modules),
            "filescan":      FileScanPanel(self.config, self.db, self.modules),
            "appreputation": AppReputationPanel(self.config, self.db, self.modules),
            "processes":     ProcessPanel(self.config, self.db, self.modules),
            "network":       NetworkPanel(self.config, self.db, self.modules),
            "quarantine":    QuarantinePanel(self.config, self.db, self.modules),
            "settings":      SettingsPanel(self.config, self.db, self.modules),
        }

        for panel in self._panels.values():
            self._stack.addWidget(panel)

        return self._stack

    # ------------------------------------------------------------------ #
    #  Navigation                                                           #
    # ------------------------------------------------------------------ #
    def _switch_tab(self, key: str) -> None:
        self._current_tab = key
        # Update nav button highlights (always safe — buttons exist before panels)
        if hasattr(self, "_nav_buttons"):
            for k, btn in self._nav_buttons.items():
                btn.setActive(k == key)
                btn.setChecked(k == key)
        # Switch panel (only safe after _build_content_area has run)
        if not hasattr(self, "_panels"):
            return
        panel = self._panels.get(key)
        if panel:
            self._stack.setCurrentWidget(panel)
            if hasattr(panel, "refresh"):
                panel.refresh()

    # ------------------------------------------------------------------ #
    #  System tray                                                          #
    # ------------------------------------------------------------------ #
    def _setup_tray(self) -> None:
        self._tray = QSystemTrayIcon(self)
        icon_path = Path("assets/shield.png")
        if icon_path.exists():
            self._tray.setIcon(QIcon(str(icon_path)))
        else:
            # Generate a simple icon
            px = QPixmap(32, 32)
            px.fill(QColor(PRIMARY))
            self._tray.setIcon(QIcon(px))

        menu = QMenu()
        menu.setStyleSheet(f"""
            QMenu {{ background: {SURFACE}; color: {TEXT}; border: 1px solid {BORDER};
                     border-radius: 8px; padding: 4px; }}
            QMenu::item:selected {{ background: {PRIMARY}; border-radius: 4px; }}
        """)
        menu.addAction("Show SecureNova", self.show_window)
        menu.addSeparator()
        menu.addAction("Exit", self._quit_app)
        self._tray.setContextMenu(menu)
        self._tray.activated.connect(self._on_tray_activated)
        self._tray.show()

    def show_window(self) -> None:
        self.show()
        self.activateWindow()
        self.raise_()

    def _on_tray_activated(self, reason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show_window()

    def _quit_app(self) -> None:
        self._tray.hide()
        QApplication.quit()

    # ------------------------------------------------------------------ #
    #  Alerts                                                               #
    # ------------------------------------------------------------------ #
    def emit_alert(self, alert: dict) -> None:
        """Thread-safe: call from any thread."""
        self.alert_received.emit(alert)

    def _on_alert(self, alert: dict) -> None:
        self._unread += 1
        self._nav_buttons["overview"].set_badge(self._unread)

        severity = alert.get("severity", "low")
        detail   = alert.get("detail", "Threat detected")
        atype    = alert.get("type", "alert")

        self._alert_banner.show_alert(severity, atype, detail)

        if self.config.get("notifications_enabled", True):
            self._tray.showMessage(
                "SecureNova Alert",
                detail[:150],
                QSystemTrayIcon.MessageIcon.Warning
                if severity in ("high", "critical")
                else QSystemTrayIcon.MessageIcon.Information,
                5000
            )

        # Forward to overview panel
        overview = self._panels.get("overview")
        if overview and hasattr(overview, "add_alert"):
            overview.add_alert(alert)

    # ------------------------------------------------------------------ #
    #  Stats refresh                                                        #
    # ------------------------------------------------------------------ #
    def _start_stats_timer(self) -> None:
        t = QTimer(self)
        t.timeout.connect(self._refresh_stats)
        t.start(5000)  # every 5 seconds

    def _refresh_stats(self) -> None:
        if self.db:
            try:
                stats = self.db.get_scan_stats()
                self.stats_updated.emit(stats)
                overview = self._panels.get("overview")
                if overview and hasattr(overview, "update_stats"):
                    overview.update_stats(stats)
            except Exception:
                pass

    def _update_clock(self) -> None:
        self._clock.setText(datetime.now().strftime("%H:%M:%S  %d %b %Y"))

    # ------------------------------------------------------------------ #
    #  Window events                                                        #
    # ------------------------------------------------------------------ #
    def closeEvent(self, event) -> None:
        # Minimize to tray instead of closing
        event.ignore()
        self.hide()
        self._tray.showMessage(
            "SecureNova", "Running in background — double-click tray icon to restore.",
            QSystemTrayIcon.MessageIcon.Information, 3000
        )

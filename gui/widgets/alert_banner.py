"""
gui/widgets/alert_banner.py — Dismissable top-of-screen alert banner
"""
from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton

SEVERITY_COLORS = {
    "critical": ("#e05252", "#2a0f0f"),
    "high":     ("#e05252", "#2a0f0f"),
    "medium":   ("#f5a623", "#2a1a00"),
    "low":      ("#4caf7d", "#0a1f14"),
}


class AlertBanner(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(40)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 0, 16, 0)

        self._icon  = QLabel("⚠")
        self._type  = QLabel()
        self._msg   = QLabel()
        self._msg.setSizePolicy(
            self._msg.sizePolicy().horizontalPolicy(),
            self._msg.sizePolicy().verticalPolicy()
        )
        close_btn = QPushButton("✕")
        close_btn.setFixedSize(24, 24)
        close_btn.setStyleSheet("background:transparent;border:none;color:#fff;font-size:14px;")
        close_btn.clicked.connect(self.hide)

        for w in (self._icon, self._type, self._msg):
            layout.addWidget(w)
        layout.addStretch()
        layout.addWidget(close_btn)

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.hide)

    def show_alert(self, severity: str, alert_type: str, message: str,
                   auto_hide_ms: int = 8000) -> None:
        fg, bg = SEVERITY_COLORS.get(severity, ("#4f8ef7", "#0f1a2e"))
        self.setStyleSheet(f"""
            QFrame {{ background: {bg}; border-bottom: 2px solid {fg}; }}
            QLabel {{ color: {fg}; font-size: 12px; }}
        """)
        self._icon.setText("🔴" if severity in ("high", "critical") else "⚠")
        self._type.setText(f"  [{alert_type.upper()}]  ")
        self._type.setStyleSheet(f"color:{fg}; font-weight:700;")
        self._msg.setText(message[:120])
        self.show()
        self._timer.start(auto_hide_ms)

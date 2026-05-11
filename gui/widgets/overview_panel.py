"""
gui/widgets/overview_panel.py — Overview dashboard panel
"""
from datetime import datetime

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea, QGridLayout, QPushButton
)

BG      = "#0f1117"
SURFACE = "#1a1d27"
BORDER  = "#2a2d3a"
PRIMARY = "#4f8ef7"
SUCCESS = "#4caf7d"
WARNING = "#f5a623"
DANGER  = "#e05252"
TEXT    = "#e0e4f0"
MUTED   = "#8890a4"

SEVERITY_COLOR = {
    "critical": DANGER,
    "high":     DANGER,
    "medium":   WARNING,
    "low":      SUCCESS,
    "info":     PRIMARY,
}

# Map DB type strings → human-readable labels
TYPE_LABELS = {
    "yara_match":          "YARA Match",
    "hash_match":          "Known Malware",
    "ransomware_pattern":  "Ransomware",
    "cryptominer_pattern": "Cryptominer",
    "mass_deletion":       "Mass Deletion",
    "registry_hijack":     "Registry Hijack",
    "new_process":         "New Process",
    "network_phone_home":  "Network Alert",
    "usb_inserted":        "USB Inserted",
    "usb_scan_complete":   "USB Scan Done",
}


# ─────────────────────────────────────────────────────────────────────────────
#  Stat card
# ─────────────────────────────────────────────────────────────────────────────
def _make_card(title: str, value: str, color: str, icon: str) -> QFrame:
    f = QFrame()
    f.setStyleSheet(f"""
        QFrame {{
            background: {SURFACE};
            border: 1px solid {BORDER};
            border-left: 4px solid {color};
            border-radius: 12px;
        }}
    """)
    layout = QVBoxLayout(f)
    layout.setContentsMargins(16, 14, 16, 14)
    layout.setSpacing(6)

    top = QHBoxLayout()
    lbl = QLabel(title)
    lbl.setStyleSheet(f"color: {MUTED}; font-size: 11px; font-weight: 500;")
    ico = QLabel(icon)
    ico.setStyleSheet(f"color: {color}; font-size: 18px;")
    top.addWidget(lbl)
    top.addStretch()
    top.addWidget(ico)

    val_lbl = QLabel(value)
    val_lbl.setStyleSheet(f"color: {TEXT}; font-size: 26px; font-weight: 700;")
    val_lbl.setObjectName("value")

    layout.addLayout(top)
    layout.addWidget(val_lbl)
    return f


def _set_card_value(card: QFrame, value) -> None:
    lbl = card.findChild(QLabel, "value")
    if lbl:
        lbl.setText(str(value))


# ─────────────────────────────────────────────────────────────────────────────
#  Single alert row
# ─────────────────────────────────────────────────────────────────────────────
class AlertRow(QFrame):
    """
    One row in the Live Threat Feed.
    Accepts either a live alert dict or a DB threat_log row dict.
    """

    def __init__(self, alert: dict):
        super().__init__()
        severity = alert.get("severity", "low")
        color    = SEVERITY_COLOR.get(severity, PRIMARY)

        # Support both live alerts (detail key) and DB rows (details key)
        detail    = alert.get("detail") or alert.get("details") or "—"
        alert_type = alert.get("type", "alert")
        label     = TYPE_LABELS.get(alert_type, alert_type.replace("_", " ").title())

        # Timestamp: live alert uses now(), DB row has "timestamp" field
        ts_raw = alert.get("timestamp", "")
        if ts_raw:
            try:
                # DB stores "2026-05-10 09:07:07" → show just time
                ts = datetime.strptime(ts_raw[:19], "%Y-%m-%d %H:%M:%S").strftime("%H:%M:%S")
            except ValueError:
                ts = ts_raw[:8]
        else:
            ts = datetime.now().strftime("%H:%M:%S")

        self.setStyleSheet(f"""
            QFrame {{
                background: {SURFACE};
                border: 1px solid {BORDER};
                border-left: 3px solid {color};
                border-radius: 8px;
            }}
            QFrame:hover {{
                background: #1f2335;
                border-color: {color};
            }}
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 7, 12, 7)
        layout.setSpacing(10)

        # Severity badge
        sev_badge = QLabel(severity.upper())
        sev_badge.setFixedWidth(68)
        sev_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sev_badge.setStyleSheet(f"""
            color: {color};
            background: rgba(0,0,0,0.3);
            border-radius: 6px;
            font-size: 10px;
            font-weight: 700;
            padding: 2px 4px;
        """)

        # Type label
        type_lbl = QLabel(label)
        type_lbl.setFixedWidth(150)
        type_lbl.setStyleSheet(f"color: {MUTED}; font-size: 11px; font-weight: 600;")

        # Detail (truncated)
        detail_lbl = QLabel(detail[:90] + ("…" if len(detail) > 90 else ""))
        detail_lbl.setStyleSheet(f"color: {TEXT}; font-size: 12px;")
        detail_lbl.setToolTip(detail)  # full text on hover

        # Timestamp
        ts_lbl = QLabel(ts)
        ts_lbl.setStyleSheet(f"color: {MUTED}; font-size: 10px;")
        ts_lbl.setFixedWidth(58)
        ts_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        layout.addWidget(sev_badge)
        layout.addWidget(type_lbl)
        layout.addWidget(detail_lbl, 1)
        layout.addWidget(ts_lbl)


# ─────────────────────────────────────────────────────────────────────────────
#  Overview panel
# ─────────────────────────────────────────────────────────────────────────────
class OverviewPanel(QWidget):
    """
    Main overview page:
      • 4 stat cards (Threats Today, Files Scanned, Blocked Domains, Processes)
      • Live Threat Feed — shows DB history on load + new alerts in real time
    """

    MAX_ROWS = 100

    def __init__(self, config: dict, db=None, modules: dict = None):
        super().__init__()
        self.config  = config
        self.db      = db
        self.modules = modules or {}
        self._alert_rows: list[AlertRow] = []
        self._build_ui()

    # ------------------------------------------------------------------ #
    #  UI                                                                   #
    # ------------------------------------------------------------------ #
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(20)

        # ── Header row ───────────────────────────────────────────────────
        header = QHBoxLayout()
        title = QLabel("Security Overview")
        title.setStyleSheet(f"color: {TEXT}; font-size: 22px; font-weight: 700;")
        header.addWidget(title)
        header.addStretch()

        self._lbl_status = QLabel("● System Protected")
        self._lbl_status.setStyleSheet(f"""
            color: {SUCCESS}; font-size: 12px; font-weight: 600;
            background: rgba(76,175,125,0.12);
            border: 1px solid rgba(76,175,125,0.3);
            border-radius: 12px; padding: 4px 14px;
        """)
        header.addWidget(self._lbl_status)
        layout.addLayout(header)

        # ── Stat cards ────────────────────────────────────────────────────
        grid = QGridLayout()
        grid.setSpacing(16)
        self._card_threats = _make_card("Threats Today",    "0", DANGER,   "🦠")
        self._card_scanned = _make_card("Files Scanned",    "0", PRIMARY,  "📂")
        self._card_blocked = _make_card("Blocked Domains",  "0", WARNING,  "🔒")
        self._card_procs   = _make_card("Active Processes", "0", SUCCESS,  "⚙")
        grid.addWidget(self._card_threats, 0, 0)
        grid.addWidget(self._card_scanned, 0, 1)
        grid.addWidget(self._card_blocked, 0, 2)
        grid.addWidget(self._card_procs,   0, 3)
        layout.addLayout(grid)

        # ── Feed header ───────────────────────────────────────────────────
        feed_header = QHBoxLayout()

        feed_title = QLabel("🔴  Live Threat Feed")
        feed_title.setStyleSheet(f"color: {TEXT}; font-size: 15px; font-weight: 600;")
        feed_header.addWidget(feed_title)
        feed_header.addStretch()

        self._lbl_feed_count = QLabel("0 events")
        self._lbl_feed_count.setStyleSheet(f"color: {MUTED}; font-size: 11px;")
        feed_header.addWidget(self._lbl_feed_count)

        btn_clear = QPushButton("Clear")
        btn_clear.setFixedSize(60, 26)
        btn_clear.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_clear.setStyleSheet(f"""
            QPushButton {{
                background: transparent; color: {MUTED};
                border: 1px solid {BORDER}; border-radius: 6px; font-size: 11px;
            }}
            QPushButton:hover {{ color: {TEXT}; border-color: {PRIMARY}; }}
        """)
        btn_clear.clicked.connect(self._clear_feed)
        feed_header.addWidget(btn_clear)

        layout.addLayout(feed_header)

        # ── Feed scroll area ──────────────────────────────────────────────
        self._feed_container = QWidget()
        self._feed_container.setStyleSheet("background: transparent;")
        self._feed_layout = QVBoxLayout(self._feed_container)
        self._feed_layout.setContentsMargins(8, 8, 8, 8)
        self._feed_layout.setSpacing(4)
        self._feed_layout.addStretch()

        # "No threats" placeholder
        self._placeholder = QLabel("✅  No threats detected — system is clean")
        self._placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._placeholder.setStyleSheet(f"""
            color: {MUTED}; font-size: 13px;
            padding: 40px;
        """)
        self._feed_layout.insertWidget(0, self._placeholder)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self._feed_container)
        scroll.setStyleSheet(f"""
            QScrollArea {{
                border: 1px solid {BORDER};
                border-radius: 12px;
                background: {SURFACE};
            }}
        """)
        scroll.setMinimumHeight(280)
        layout.addWidget(scroll, 1)

    # ------------------------------------------------------------------ #
    #  Feed management                                                      #
    # ------------------------------------------------------------------ #
    def add_alert(self, alert: dict) -> None:
        """Called from main_window for live alerts (any thread via signal)."""
        self._placeholder.hide()

        row = AlertRow(alert)
        # Insert at position 0 (below the stretch at the bottom)
        self._feed_layout.insertWidget(0, row)
        self._alert_rows.insert(0, row)

        # Enforce max rows
        while len(self._alert_rows) > self.MAX_ROWS:
            old = self._alert_rows.pop()
            old.setParent(None)

        self._update_feed_count()

    def _load_db_history(self) -> None:
        """Populate feed with the last 50 threats from the database."""
        if not self.db:
            return
        rows = self.db.get_threats(limit=50)
        if not rows:
            return

        self._placeholder.hide()
        # rows are newest-first from DB; add them in reverse so newest ends on top
        for row_data in reversed(rows):
            alert = {
                "type":      row_data.get("type", "alert"),
                "severity":  row_data.get("severity", "low"),
                "detail":    row_data.get("details", "") or row_data.get("path", ""),
                "timestamp": row_data.get("timestamp", ""),
            }
            alert_row = AlertRow(alert)
            self._feed_layout.insertWidget(0, alert_row)
            self._alert_rows.insert(0, alert_row)

        self._update_feed_count()

    def _clear_feed(self) -> None:
        for row in self._alert_rows:
            row.setParent(None)
        self._alert_rows.clear()
        self._placeholder.show()
        self._update_feed_count()
        # Mark all as read in DB
        if self.db:
            self.db.mark_threats_read()

    def _update_feed_count(self) -> None:
        n = len(self._alert_rows)
        self._lbl_feed_count.setText(f"{n} event{'s' if n != 1 else ''}")

    # ------------------------------------------------------------------ #
    #  Stats + refresh                                                      #
    # ------------------------------------------------------------------ #
    def update_stats(self, stats: dict) -> None:
        _set_card_value(self._card_threats, stats.get("threats_today", 0))
        _set_card_value(self._card_scanned, stats.get("total_scanned", 0))
        _set_card_value(self._card_blocked, stats.get("blocked_domains", 0))

        pm = self.modules.get("process_monitor")
        if pm and hasattr(pm, "get_process_list"):
            _set_card_value(self._card_procs, len(pm.get_process_list()))

        # Update status badge colour based on threat count
        threats = stats.get("threats_today", 0)
        if threats > 0:
            self._lbl_status.setText(f"⚠ {threats} Threat(s) Today")
            self._lbl_status.setStyleSheet(f"""
                color: {DANGER}; font-size: 12px; font-weight: 600;
                background: rgba(224,82,82,0.12);
                border: 1px solid rgba(224,82,82,0.3);
                border-radius: 12px; padding: 4px 14px;
            """)
        else:
            self._lbl_status.setText("● System Protected")
            self._lbl_status.setStyleSheet(f"""
                color: {SUCCESS}; font-size: 12px; font-weight: 600;
                background: rgba(76,175,125,0.12);
                border: 1px solid rgba(76,175,125,0.3);
                border-radius: 12px; padding: 4px 14px;
            """)

    def refresh(self) -> None:
        """Called when the user switches to this tab."""
        if self.db:
            stats = self.db.get_scan_stats()
            self.update_stats(stats)
        # Load DB history only on first visit
        if not self._alert_rows:
            self._load_db_history()

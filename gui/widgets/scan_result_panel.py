"""
gui/widgets/scan_result_panel.py — Reusable Scan Result Display Widget

Used by AV scan, Full scan, and Deep scan to show results with animated
progress ring, expandable threat rows, and action buttons.
"""
import json
from datetime import datetime

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QMessageBox, QFileDialog
)

SURFACE = "#1a1d27"
BORDER  = "#2a2d3a"
PRIMARY = "#4f8ef7"
SUCCESS = "#4caf7d"
DANGER  = "#e05252"
WARNING = "#f5a623"
TEXT    = "#e0e4f0"
MUTED   = "#8890a4"


def _btn(label, color=PRIMARY, small=False):
    b = QPushButton(label)
    pad = "5px 12px" if small else "8px 20px"
    sz = "11px" if small else "13px"
    b.setStyleSheet(f"""
        QPushButton {{
            background: {color}; color: #fff; border: none;
            border-radius: 8px; padding: {pad}; font-size: {sz}; font-weight: 600;
        }}
        QPushButton:hover {{ opacity: 0.85; }}
    """)
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    return b


class ThreatRow(QFrame):
    """Single expandable threat row in scan results."""

    def __init__(self, threat: dict):
        super().__init__()
        self.threat = threat
        severity = threat.get("severity", "medium")
        color = DANGER if severity in ("high", "critical") else WARNING

        self.setStyleSheet(f"""
            QFrame {{
                background: {SURFACE}; border: 1px solid {BORDER};
                border-left: 3px solid {color}; border-radius: 8px;
            }}
            QFrame:hover {{ background: #1f2335; }}
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(10)

        # Severity icon
        icon = "🔴" if severity in ("high", "critical") else "🟡"
        icon_lbl = QLabel(icon)
        icon_lbl.setFixedWidth(24)
        layout.addWidget(icon_lbl)

        # Threat info
        info = QVBoxLayout()
        info.setSpacing(2)
        name = QLabel(threat.get("threat_name", "Unknown"))
        name.setStyleSheet(f"color: {color}; font-size: 13px; font-weight: 600;")
        path = QLabel(threat.get("path", "")[:80])
        path.setStyleSheet(f"color: {MUTED}; font-size: 11px;")
        path.setToolTip(threat.get("path", ""))
        engine = QLabel(f"Detected by: {threat.get('engine', 'Unknown')}")
        engine.setStyleSheet(f"color: {MUTED}; font-size: 10px;")
        info.addWidget(name)
        info.addWidget(path)
        info.addWidget(engine)
        layout.addLayout(info, 1)

        # Action status
        action = threat.get("action", "detected")
        cleaned = threat.get("cleaned", False)
        if cleaned:
            status = QLabel("✓ Quarantined")
            status.setStyleSheet(f"color: {SUCCESS}; font-size: 11px; font-weight: 600;")
        else:
            status = QLabel(action.upper())
            status.setStyleSheet(f"color: {WARNING}; font-size: 11px; font-weight: 600;")
        layout.addWidget(status)


class ScanResultPanel(QWidget):
    """Reusable scan result display widget."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        # Summary card
        self._summary = QFrame()
        self._summary.setStyleSheet(f"""
            QFrame {{
                background: {SURFACE}; border: 1px solid {BORDER};
                border-radius: 12px;
            }}
        """)
        summary_layout = QVBoxLayout(self._summary)
        summary_layout.setContentsMargins(20, 16, 20, 16)
        summary_layout.setSpacing(8)

        self._title = QLabel("SCAN COMPLETE")
        self._title.setStyleSheet(f"color: {TEXT}; font-size: 18px; font-weight: 700;")
        self._duration = QLabel("")
        self._duration.setStyleSheet(f"color: {MUTED}; font-size: 12px;")
        self._duration.setAlignment(Qt.AlignmentFlag.AlignRight)

        title_row = QHBoxLayout()
        title_row.addWidget(self._title)
        title_row.addStretch()
        title_row.addWidget(self._duration)
        summary_layout.addLayout(title_row)

        # Stats row
        stats_row = QHBoxLayout()
        self._stat_labels = {}
        for key, label in [("files", "Files Scanned"), ("threats", "Threats Found"),
                           ("cleaned", "Cleaned"), ("speed", "Speed")]:
            frame = QFrame()
            frame.setStyleSheet(f"background: rgba(0,0,0,0.2); border-radius: 8px;")
            fl = QVBoxLayout(frame)
            fl.setContentsMargins(12, 8, 12, 8)
            lbl = QLabel(label)
            lbl.setStyleSheet(f"color: {MUTED}; font-size: 10px;")
            val = QLabel("0")
            val.setStyleSheet(f"color: {TEXT}; font-size: 18px; font-weight: 700;")
            fl.addWidget(lbl)
            fl.addWidget(val)
            stats_row.addWidget(frame)
            self._stat_labels[key] = val

        summary_layout.addLayout(stats_row)

        # Status badge
        self._status_badge = QLabel("● CLEAN")
        self._status_badge.setStyleSheet(f"""
            color: {SUCCESS}; font-size: 14px; font-weight: 700;
            background: rgba(76,175,125,0.15); border-radius: 8px;
            padding: 8px 16px;
        """)
        self._status_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        summary_layout.addWidget(self._status_badge)

        layout.addWidget(self._summary)

        # Threats scroll area
        self._threats_container = QWidget()
        self._threats_container.setStyleSheet("background: transparent;")
        self._threats_layout = QVBoxLayout(self._threats_container)
        self._threats_layout.setContentsMargins(0, 0, 0, 0)
        self._threats_layout.setSpacing(6)
        self._threats_layout.addStretch()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self._threats_container)
        scroll.setStyleSheet(f"QScrollArea {{ border: none; background: transparent; }}")
        layout.addWidget(scroll, 1)

        # Action buttons
        btn_row = QHBoxLayout()
        self._btn_export = _btn("📄 Export Report", MUTED)
        self._btn_export.clicked.connect(self._export_report)
        btn_row.addStretch()
        btn_row.addWidget(self._btn_export)
        layout.addLayout(btn_row)

        self._report_data = None

    def show_report(self, report: dict):
        """Populate the panel with scan report data."""
        self._report_data = report

        duration = report.get("duration_seconds", 0)
        mins, secs = divmod(duration, 60)
        self._duration.setText(f"Duration: {mins}m {secs}s")

        self._stat_labels["files"].setText(str(report.get("files_scanned", 0)))
        self._stat_labels["threats"].setText(str(report.get("threats_found", 0)))
        self._stat_labels["cleaned"].setText(str(report.get("threats_cleaned", 0)))
        speed = report.get("files_scanned", 0) / max(duration, 1)
        self._stat_labels["speed"].setText(f"{speed:.0f}/s")

        status = report.get("scan_status", "clean")
        threats = report.get("threats_found", 0)
        if threats == 0:
            self._status_badge.setText("✅ SYSTEM CLEAN — No threats detected")
            self._status_badge.setStyleSheet(f"""
                color: {SUCCESS}; font-size: 14px; font-weight: 700;
                background: rgba(76,175,125,0.15); border-radius: 8px; padding: 8px 16px;
            """)
        elif status == "cleaned":
            self._status_badge.setText(f"⚠ {threats} THREAT(S) FOUND AND CLEANED")
            self._status_badge.setStyleSheet(f"""
                color: {WARNING}; font-size: 14px; font-weight: 700;
                background: rgba(245,166,35,0.15); border-radius: 8px; padding: 8px 16px;
            """)
        else:
            self._status_badge.setText(f"🔴 {threats} THREAT(S) FOUND")
            self._status_badge.setStyleSheet(f"""
                color: {DANGER}; font-size: 14px; font-weight: 700;
                background: rgba(224,82,82,0.15); border-radius: 8px; padding: 8px 16px;
            """)

        # Add threat rows
        # Clear existing
        while self._threats_layout.count() > 1:
            item = self._threats_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        for threat in report.get("threat_list", []):
            row = ThreatRow(threat)
            self._threats_layout.insertWidget(self._threats_layout.count() - 1, row)

    def _export_report(self):
        if not self._report_data:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Scan Report", f"securenova_report_{datetime.now():%Y%m%d_%H%M}.json",
            "JSON Files (*.json);;Text Files (*.txt)"
        )
        if path:
            try:
                with open(path, "w") as f:
                    json.dump(self._report_data, f, indent=2, default=str)
                QMessageBox.information(self, "Exported", f"Report saved to:\n{path}")
            except Exception as e:
                QMessageBox.warning(self, "Error", str(e))

"""
gui/widgets/scan_center_panel.py — Unified Scan Center

Lets users choose scan type (Quick, Full, Deep, AV, Custom), configure it,
run it, view results, and manage scan history — all from one panel.
"""
import json
import subprocess
import threading
from datetime import datetime

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QStackedWidget, QProgressBar, QScrollArea,
    QFileDialog, QMessageBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QComboBox, QSpinBox
)

from gui.widgets.scan_result_panel import ScanResultPanel

SURFACE = "#1a1d27"
BORDER  = "#2a2d3a"
PRIMARY = "#4f8ef7"
SUCCESS = "#4caf7d"
DANGER  = "#e05252"
WARNING = "#f5a623"
TEXT    = "#e0e4f0"
MUTED   = "#8890a4"
ACCENT  = "#7c5cbf"

STATUS_COLORS = {"clean": SUCCESS, "threats_found": DANGER,
                 "cleaned": WARNING, "cancelled": MUTED, "partial": MUTED}


def _btn(label, color=PRIMARY, big=False):
    h = "60px" if big else "auto"
    sz = "14px" if big else "13px"
    b = QPushButton(label)
    b.setStyleSheet(f"""
        QPushButton {{
            background: {color}; color: #fff; border: none;
            border-radius: 12px; padding: 12px 20px; font-size: {sz}; font-weight: 600;
            min-height: {h};
        }}
        QPushButton:hover {{ opacity: 0.85; }}
        QPushButton:disabled {{ background: #333; color: #666; }}
    """)
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    return b


def _scan_card(icon, title, subtitle, time_est, color):
    """Create a scan type selection card."""
    card = QPushButton()
    card.setStyleSheet(f"""
        QPushButton {{
            background: {SURFACE}; border: 1px solid {BORDER};
            border-radius: 14px; text-align: left; padding: 18px;
        }}
        QPushButton:hover {{
            border-color: {color}; background: #1f2233;
        }}
    """)
    card.setCursor(Qt.CursorShape.PointingHandCursor)

    layout = QVBoxLayout(card)
    layout.setSpacing(6)

    icon_lbl = QLabel(icon)
    icon_lbl.setStyleSheet(f"font-size: 28px;")
    icon_lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

    title_lbl = QLabel(title)
    title_lbl.setStyleSheet(f"color: {TEXT}; font-size: 15px; font-weight: 700;")
    title_lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

    sub_lbl = QLabel(subtitle)
    sub_lbl.setStyleSheet(f"color: {MUTED}; font-size: 11px;")
    sub_lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

    time_lbl = QLabel(time_est)
    time_lbl.setStyleSheet(f"color: {color}; font-size: 11px; font-weight: 600;")
    time_lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

    layout.addWidget(icon_lbl)
    layout.addWidget(title_lbl)
    layout.addWidget(sub_lbl)
    layout.addWidget(time_lbl)

    return card


class ScanWorkerGeneric(QObject):
    """Generic background worker for any scan type."""
    finished = pyqtSignal(dict)
    progress = pyqtSignal(dict)

    def __init__(self, scan_fn, *args, **kwargs):
        super().__init__()
        self.scan_fn = scan_fn
        self.args = args
        self.kwargs = kwargs

    def run(self):
        def on_progress(data):
            self.progress.emit(data)

        self.kwargs["progress_callback"] = on_progress
        report = self.scan_fn(*self.args, **self.kwargs)
        self.finished.emit(report)


class ScanCenterPanel(QWidget):
    """Unified scan center with type selection, progress, results, and history."""

    def __init__(self, config: dict, db=None, modules: dict = None):
        super().__init__()
        self.config = config
        self.db = db
        self.modules = modules or {}
        self._thread = None
        self._worker = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._stack = QStackedWidget()
        layout.addWidget(self._stack)

        # Page 0: Scan type selector
        self._selector_page = self._build_selector()
        self._stack.addWidget(self._selector_page)

        # Page 1: Scan progress
        self._progress_page = self._build_progress()
        self._stack.addWidget(self._progress_page)

        # Page 2: Scan results
        self._result_panel = ScanResultPanel()
        result_wrapper = QWidget()
        rw_layout = QVBoxLayout(result_wrapper)
        rw_layout.setContentsMargins(24, 24, 24, 24)

        back_btn = _btn("← Back to Scan Center", MUTED)
        back_btn.clicked.connect(lambda: self._stack.setCurrentIndex(0))
        rw_layout.addWidget(back_btn)
        rw_layout.addWidget(self._result_panel, 1)
        self._stack.addWidget(result_wrapper)

    def _build_selector(self):
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(16)

        # Header
        title = QLabel("Scan Center")
        title.setStyleSheet(f"color: {TEXT}; font-size: 22px; font-weight: 700;")
        outer.addWidget(title)

        # Main body: history sidebar + scan cards
        body = QHBoxLayout()
        body.setSpacing(16)

        # History sidebar
        history_frame = QFrame()
        history_frame.setFixedWidth(220)
        history_frame.setStyleSheet(f"""
            QFrame {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 12px; }}
        """)
        h_layout = QVBoxLayout(history_frame)
        h_layout.setContentsMargins(12, 12, 12, 12)
        h_layout.setSpacing(6)

        h_title = QLabel("Scan History")
        h_title.setStyleSheet(f"color: {MUTED}; font-size: 12px; font-weight: 600;")
        h_layout.addWidget(h_title)

        self._history_container = QVBoxLayout()
        self._history_container.setSpacing(4)
        h_layout.addLayout(self._history_container)
        h_layout.addStretch()

        body.addWidget(history_frame)

        # Scan cards grid
        cards_layout = QVBoxLayout()
        cards_layout.setSpacing(12)

        # Row 1: Quick, Full, Deep
        row1 = QHBoxLayout()
        row1.setSpacing(12)

        card_quick = _scan_card("⚡", "QUICK SCAN", "Smart targets", "~3 min", PRIMARY)
        card_full = _scan_card("💻", "FULL PC SCAN", "All drives", "~30 min", SUCCESS)
        card_deep = _scan_card("🔬", "DEEP SCAN", "Memory + Rootkit", "~60 min", ACCENT)

        card_quick.clicked.connect(lambda: self._start_scan("quick"))
        card_full.clicked.connect(lambda: self._start_scan("full"))
        card_deep.clicked.connect(lambda: self._start_scan("deep"))

        row1.addWidget(card_quick)
        row1.addWidget(card_full)
        row1.addWidget(card_deep)
        cards_layout.addLayout(row1)

        # Row 2: AV, Custom
        row2 = QHBoxLayout()
        row2.setSpacing(12)

        card_av = _scan_card("🛡", "ANTIVIRUS SCAN", "AV-style scan", "~5 min", WARNING)
        card_custom = _scan_card("📁", "CUSTOM SCAN", "You pick targets", "Varies", MUTED)

        card_av.clicked.connect(lambda: self._start_scan("antivirus"))
        card_custom.clicked.connect(self._start_custom_scan)

        row2.addWidget(card_av)
        row2.addWidget(card_custom)
        row2.addStretch()
        cards_layout.addLayout(row2)

        # Schedule button
        sched_row = QHBoxLayout()
        btn_schedule = _btn("📅 Schedule Scan", MUTED)
        btn_schedule.clicked.connect(self._schedule_scan)
        sched_row.addWidget(btn_schedule)
        sched_row.addStretch()
        cards_layout.addLayout(sched_row)

        cards_layout.addStretch()
        body.addLayout(cards_layout, 1)
        outer.addLayout(body, 1)

        return page

    def _build_progress(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        self._prog_title = QLabel("SCAN IN PROGRESS")
        self._prog_title.setStyleSheet(f"color: {TEXT}; font-size: 20px; font-weight: 700;")
        layout.addWidget(self._prog_title)

        # Phase indicators
        self._phase_labels = []
        phases_frame = QFrame()
        phases_frame.setStyleSheet(f"""
            QFrame {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 12px; }}
        """)
        pl = QVBoxLayout(phases_frame)
        pl.setContentsMargins(16, 16, 16, 16)
        pl.setSpacing(4)

        for i in range(6):
            lbl = QLabel(f"⏳ Phase {i+1}: Pending")
            lbl.setStyleSheet(f"color: {MUTED}; font-size: 12px;")
            pl.addWidget(lbl)
            self._phase_labels.append(lbl)

        layout.addWidget(phases_frame)

        # Progress bar
        self._scan_progress = QProgressBar()
        self._scan_progress.setFixedHeight(12)
        self._scan_progress.setTextVisible(False)
        self._scan_progress.setStyleSheet(f"""
            QProgressBar {{ background: {SURFACE}; border-radius: 6px; border: 1px solid {BORDER}; }}
            QProgressBar::chunk {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                stop:0 {PRIMARY}, stop:1 {ACCENT}); border-radius: 5px; }}
        """)
        layout.addWidget(self._scan_progress)

        # Stats row
        stats_row = QHBoxLayout()
        self._prog_elapsed = QLabel("Elapsed: 0:00")
        self._prog_elapsed.setStyleSheet(f"color: {MUTED}; font-size: 12px;")
        self._prog_eta = QLabel("ETA: calculating…")
        self._prog_eta.setStyleSheet(f"color: {MUTED}; font-size: 12px;")
        self._prog_threats = QLabel("Threats: 0")
        self._prog_threats.setStyleSheet(f"color: {TEXT}; font-size: 12px; font-weight: 600;")
        self._prog_file = QLabel("")
        self._prog_file.setStyleSheet(f"color: {MUTED}; font-size: 10px;")

        stats_row.addWidget(self._prog_elapsed)
        stats_row.addWidget(self._prog_eta)
        stats_row.addStretch()
        stats_row.addWidget(self._prog_threats)
        layout.addLayout(stats_row)
        layout.addWidget(self._prog_file)

        # Cancel button
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        self._btn_cancel = _btn("Cancel Scan", DANGER)
        self._btn_cancel.clicked.connect(self._cancel_scan)
        btn_row.addWidget(self._btn_cancel)
        layout.addLayout(btn_row)

        layout.addStretch()
        return page

    # ────────────────────────────────────────────────────────────────────
    #  Scan execution
    # ────────────────────────────────────────────────────────────────────
    def _start_scan(self, scan_type: str):
        """Start a scan of the given type."""
        engine = None
        scan_fn = None

        if scan_type == "quick":
            engine = self.modules.get("full_scan")
            if engine:
                scan_fn = engine.run_quick_scan
        elif scan_type == "full":
            engine = self.modules.get("full_scan")
            if engine:
                scan_fn = engine.run_full_scan
        elif scan_type == "deep":
            engine = self.modules.get("deep_scan")
            if engine:
                scan_fn = engine.run_scan
        elif scan_type == "antivirus":
            engine = self.modules.get("antivirus_scan")
            if engine:
                scan_fn = engine.run_scan

        if not scan_fn:
            QMessageBox.warning(self, "Not Available",
                                f"{scan_type.title()} scan engine not available.")
            return

        self._prog_title.setText(f"{scan_type.upper()} SCAN IN PROGRESS")
        self._scan_progress.setValue(0)
        self._scan_progress.setMaximum(100)
        self._stack.setCurrentIndex(1)

        # Reset phase labels
        for lbl in self._phase_labels:
            lbl.setText(f"⏳ Pending")
            lbl.setStyleSheet(f"color: {MUTED}; font-size: 12px;")

        self._worker = ScanWorkerGeneric(scan_fn)
        self._thread = QThread()
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_finished)
        self._thread.start()

    def _start_custom_scan(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if not folder:
            return
        engine = self.modules.get("full_scan")
        if not engine:
            QMessageBox.warning(self, "Not Available", "Scan engine not available.")
            return

        self._prog_title.setText("CUSTOM SCAN IN PROGRESS")
        self._scan_progress.setValue(0)
        self._stack.setCurrentIndex(1)

        self._worker = ScanWorkerGeneric(engine.run_custom_scan, [folder])
        self._thread = QThread()
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_finished)
        self._thread.start()

    def _cancel_scan(self):
        for mod_name in ("full_scan", "deep_scan", "antivirus_scan"):
            engine = self.modules.get(mod_name)
            if engine and hasattr(engine, "cancel"):
                engine.cancel()

    def _on_progress(self, data):
        pct = data.get("percent", 0)
        self._scan_progress.setValue(pct)

        threats = data.get("threats_found", data.get("total_threats", 0))
        self._prog_threats.setText(f"Threats: {threats}")

        elapsed = data.get("elapsed", 0)
        if not elapsed and "eta_seconds" in data:
            elapsed = 0
        mins, secs = divmod(elapsed, 60)
        self._prog_elapsed.setText(f"Elapsed: {mins}:{secs:02d}")

        eta = data.get("eta_seconds", 0)
        if eta > 0:
            em, es = divmod(eta, 60)
            self._prog_eta.setText(f"ETA: ~{em}m {es}s")

        cf = data.get("current_file", "")
        if cf:
            self._prog_file.setText(cf[-80:])

        # Phase indicators
        phase_name = data.get("phase", data.get("phase_name", ""))
        phase_num = data.get("phase_number", data.get("phase", 0))
        if isinstance(phase_num, int) and phase_num < len(self._phase_labels):
            for i, lbl in enumerate(self._phase_labels):
                if i < phase_num:
                    lbl.setText(f"✅ Phase {i+1}: Complete")
                    lbl.setStyleSheet(f"color: {SUCCESS}; font-size: 12px;")
                elif i == phase_num:
                    lbl.setText(f"🔄 Phase {i+1}: {phase_name}")
                    lbl.setStyleSheet(f"color: {PRIMARY}; font-size: 12px; font-weight: 600;")

    def _on_finished(self, report):
        self._result_panel.show_report(report)
        self._stack.setCurrentIndex(2)
        self._load_history()
        if self._thread:
            self._thread.quit()

    # ────────────────────────────────────────────────────────────────────
    #  History
    # ────────────────────────────────────────────────────────────────────
    def _load_history(self):
        # Clear
        while self._history_container.count():
            item = self._history_container.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not self.db or not hasattr(self.db, "get_full_scan_history"):
            return

        try:
            history = self.db.get_full_scan_history(limit=10)
            for entry in history:
                scan_type = entry.get("scan_type", "unknown")
                status = entry.get("status", "")
                start = entry.get("start_time", "")[:10]
                threats = entry.get("threats_found", 0)
                color = STATUS_COLORS.get(status, MUTED)

                btn = QPushButton()
                btn.setStyleSheet(f"""
                    QPushButton {{
                        background: rgba(0,0,0,0.2); border: none;
                        border-radius: 8px; text-align: left; padding: 8px;
                    }}
                    QPushButton:hover {{ background: rgba(0,0,0,0.4); }}
                """)
                btn.setCursor(Qt.CursorShape.PointingHandCursor)

                bl = QVBoxLayout(btn)
                bl.setContentsMargins(8, 4, 8, 4)
                bl.setSpacing(2)

                date_lbl = QLabel(start)
                date_lbl.setStyleSheet(f"color: {MUTED}; font-size: 10px;")
                date_lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

                type_lbl = QLabel(f"{scan_type.title()} Scan")
                type_lbl.setStyleSheet(f"color: {TEXT}; font-size: 11px; font-weight: 600;")
                type_lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

                icon = "✅" if threats == 0 else "⚠"
                stat_lbl = QLabel(f"{icon} {threats} threats")
                stat_lbl.setStyleSheet(f"color: {color}; font-size: 10px;")
                stat_lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

                bl.addWidget(date_lbl)
                bl.addWidget(type_lbl)
                bl.addWidget(stat_lbl)

                scan_id = entry.get("scan_id", "")
                btn.clicked.connect(lambda _, sid=scan_id: self._view_history(sid))

                self._history_container.addWidget(btn)
        except Exception:
            pass

    def _view_history(self, scan_id):
        if not self.db:
            return
        report = self.db.get_scan_report(scan_id)
        if report:
            self._result_panel.show_report(report)
            self._stack.setCurrentIndex(2)

    # ────────────────────────────────────────────────────────────────────
    #  Schedule
    # ────────────────────────────────────────────────────────────────────
    def _schedule_scan(self):
        QMessageBox.information(
            self, "Schedule Scan",
            "Scan scheduling via Windows Task Scheduler.\n\n"
            "To schedule, use:\n"
            "  schtasks /create /tn \"SecureNova_QuickScan\" "
            "/sc daily /st 02:00 "
            "/tr \"python main.py --scan quick\"\n\n"
            "This feature will be fully automated in a future update."
        )

    def refresh(self):
        self._load_history()

"""
gui/widgets/filescan_panel.py — File scanner panel
"""
import os
import threading
from pathlib import Path

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QFileDialog, QTableWidget, QTableWidgetItem,
    QHeaderView, QProgressBar, QAbstractItemView
)

SURFACE = "#1a1d27"
BORDER  = "#2a2d3a"
PRIMARY = "#4f8ef7"
SUCCESS = "#4caf7d"
DANGER  = "#e05252"
WARNING = "#f5a623"
TEXT    = "#e0e4f0"
MUTED   = "#8890a4"


def _btn(label: str, color: str = PRIMARY) -> QPushButton:
    b = QPushButton(label)
    b.setStyleSheet(f"""
        QPushButton {{
            background: {color}; color: #fff; border: none;
            border-radius: 8px; padding: 8px 20px; font-size: 13px; font-weight: 600;
        }}
        QPushButton:hover {{ background: {'#3d7ef5' if color==PRIMARY else color}; }}
        QPushButton:disabled {{ background: #333; color: #666; }}
    """)
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    return b


class ScanWorker(QObject):
    finished = pyqtSignal()
    progress = pyqtSignal(int, int)
    result   = pyqtSignal(str, str, str)  # path, status, threat

    def __init__(self, paths: list[str], scanner):
        super().__init__()
        self.paths = paths
        self.scanner = scanner
        self._cancelled = False

    def run(self) -> None:
        total = len(self.paths)
        for i, path in enumerate(self.paths):
            if self._cancelled:
                break
            try:
                r = self.scanner.scan_file(path)
                status = "CLEAN" if r.clean else "THREAT"
                self.result.emit(path, status, r.threat_name)
            except Exception as e:
                self.result.emit(path, "ERROR", str(e))
            self.progress.emit(i + 1, total)
        self.finished.emit()

    def cancel(self) -> None:
        self._cancelled = True


class FileScanPanel(QWidget):
    def __init__(self, config: dict, db=None, modules: dict = None):
        super().__init__()
        self.config = config
        self.db = db
        self.modules = modules or {}
        self._scan_thread = None
        self._worker = None
        self._monitor_active = False
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("File Scanner")
        title.setStyleSheet(f"color: {TEXT}; font-size: 22px; font-weight: 700;")
        layout.addWidget(title)

        # Control bar
        ctrl = QHBoxLayout()
        self._btn_scan_file   = _btn("📂 Scan File")
        self._btn_scan_folder = _btn("📁 Scan Folder")
        self._btn_monitor     = _btn("▶ Start Monitor", SUCCESS)
        self._btn_update      = _btn("↻ Update Rules", "#7c5cbf")

        self._btn_scan_file.clicked.connect(self._pick_file)
        self._btn_scan_folder.clicked.connect(self._pick_folder)
        self._btn_monitor.clicked.connect(self._toggle_monitor)
        self._btn_update.clicked.connect(self._update_rules)

        for b in (self._btn_scan_file, self._btn_scan_folder,
                  self._btn_monitor, self._btn_update):
            ctrl.addWidget(b)
        ctrl.addStretch()
        layout.addLayout(ctrl)

        # Progress bar
        self._progress = QProgressBar()
        self._progress.setFixedHeight(6)
        self._progress.setTextVisible(False)
        self._progress.hide()
        self._progress.setStyleSheet(f"""
            QProgressBar {{ background: {SURFACE}; border-radius: 3px; border: none; }}
            QProgressBar::chunk {{ background: {PRIMARY}; border-radius: 3px; }}
        """)
        layout.addWidget(self._progress)

        # Status label
        self._status_lbl = QLabel("Ready")
        self._status_lbl.setStyleSheet(f"color: {MUTED}; font-size: 11px;")
        layout.addWidget(self._status_lbl)

        # Results table
        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["File Path", "Status", "Threat", "Timestamp"])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setStyleSheet(f"""
            QTableWidget {{
                background: {SURFACE}; color: {TEXT};
                border: 1px solid {BORDER}; border-radius: 10px;
                gridline-color: {BORDER};
            }}
            QTableWidget::item:selected {{ background: #253050; }}
            QHeaderView::section {{
                background: #141720; color: {MUTED};
                border: none; padding: 8px;
                font-weight: 600; font-size: 11px;
            }}
            QTableWidget::item:alternate {{ background: #15181f; }}
        """)
        layout.addWidget(self._table, 1)

        # Load history
        self._load_history()

    def _load_history(self) -> None:
        if self.db:
            for row in self.db.get_scan_history(50):
                self._add_row(row["path"], row["result"].upper(),
                              row.get("threat_name", ""), row["timestamp"])

    def _pick_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Scan")
        if path:
            self._run_scan([path])

    def _pick_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if folder:
            files = [str(p) for p in Path(folder).rglob("*") if p.is_file()]
            self._run_scan(files)

    def _run_scan(self, paths: list[str]) -> None:
        scanner = self.modules.get("file_scanner")
        if not scanner:
            self._status_lbl.setText("Scanner not available")
            return

        self._progress.setMaximum(len(paths))
        self._progress.setValue(0)
        self._progress.show()
        self._status_lbl.setText(f"Scanning {len(paths)} file(s)…")

        self._worker = ScanWorker(paths, scanner)
        self._scan_thread = QThread()
        self._worker.moveToThread(self._scan_thread)
        self._scan_thread.started.connect(self._worker.run)
        self._worker.result.connect(self._on_result)
        self._worker.progress.connect(lambda c, t: self._progress.setValue(c))
        self._worker.finished.connect(self._on_scan_done)
        self._scan_thread.start()

    def _on_result(self, path: str, status: str, threat: str) -> None:
        from datetime import datetime
        self._add_row(path, status, threat, datetime.now().strftime("%H:%M:%S"))

    def _on_scan_done(self) -> None:
        self._progress.hide()
        self._status_lbl.setText("Scan complete")
        if self._scan_thread:
            self._scan_thread.quit()

    def _add_row(self, path: str, status: str, threat: str, ts: str) -> None:
        self._table.insertRow(0)  # Insert at top
        color = DANGER if status == "THREAT" else (WARNING if status == "ERROR" else SUCCESS)
        for col, text in enumerate([path, status, threat, ts]):
            item = QTableWidgetItem(text)
            if col == 1:
                item.setForeground(QColor(color))
            self._table.setItem(0, col, item)

    def _toggle_monitor(self) -> None:
        mon = self.modules.get("realtime_monitor")
        if not mon:
            return
        if not self._monitor_active:
            mon.start()
            self._monitor_active = True
            self._btn_monitor.setText("■ Stop Monitor")
            self._btn_monitor.setStyleSheet(self._btn_monitor.styleSheet().replace(SUCCESS, DANGER))
        else:
            mon.stop()
            self._monitor_active = False
            self._btn_monitor.setText("▶ Start Monitor")

    def _update_rules(self) -> None:
        updater = self.modules.get("updater")
        if updater:
            threading.Thread(target=updater.update_yara_rules, daemon=True).start()
            self._status_lbl.setText("Updating YARA rules…")

    def refresh(self) -> None:
        pass

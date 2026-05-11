"""
gui/widgets/app_reputation_panel.py — Installed App Reputation Panel

Table view of all installed applications with color-coded risk columns,
filter bar, right-click context menu, and background QThread scanning.
"""
import json
import threading
from datetime import datetime

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject
from PyQt6.QtGui import QColor, QAction
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QComboBox, QProgressBar, QMenu, QMessageBox, QFrame
)

SURFACE = "#1a1d27"
BORDER  = "#2a2d3a"
PRIMARY = "#4f8ef7"
SUCCESS = "#4caf7d"
DANGER  = "#e05252"
WARNING = "#f5a623"
TEXT    = "#e0e4f0"
MUTED   = "#8890a4"
ACCENT  = "#7c5cbf"

RISK_COLORS = {
    "clean": SUCCESS, "low": "#6bba75", "medium": WARNING,
    "high": "#e07040", "critical": DANGER,
}


def _btn(label, color=PRIMARY):
    b = QPushButton(label)
    b.setStyleSheet(f"""
        QPushButton {{
            background: {color}; color: #fff; border: none;
            border-radius: 8px; padding: 8px 20px; font-size: 13px; font-weight: 600;
        }}
        QPushButton:hover {{ opacity: 0.85; }}
        QPushButton:disabled {{ background: #333; color: #666; }}
    """)
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    return b


class AppScanWorker(QObject):
    """Background worker for app reputation scanning."""
    finished = pyqtSignal()
    progress = pyqtSignal(int, int, str)  # current, total, app_name
    result = pyqtSignal(dict)

    def __init__(self, scanner):
        super().__init__()
        self.scanner = scanner
        self._cancel = threading.Event()

    def run(self):
        def on_progress(current, total, name):
            self.progress.emit(current, total, name)

        results = self.scanner.scan_installed_apps(
            progress_callback=on_progress,
            cancel_event=self._cancel
        )
        for r in results:
            self.result.emit(r)
        self.finished.emit()

    def cancel(self):
        self._cancel.set()


class AppReputationPanel(QWidget):
    """Panel displaying installed app reputation scan results."""

    def __init__(self, config: dict, db=None, modules: dict = None):
        super().__init__()
        self.config = config
        self.db = db
        self.modules = modules or {}
        self._results = []
        self._thread = None
        self._worker = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Header
        header = QHBoxLayout()
        title = QLabel("App Reputation Scanner")
        title.setStyleSheet(f"color: {TEXT}; font-size: 22px; font-weight: 700;")
        header.addWidget(title)
        header.addStretch()

        self._status = QLabel("Ready")
        self._status.setStyleSheet(f"color: {MUTED}; font-size: 12px;")
        header.addWidget(self._status)
        layout.addLayout(header)

        # Controls
        ctrl = QHBoxLayout()
        self._btn_scan = _btn("🔍 Scan Installed Apps", PRIMARY)
        self._btn_scan.clicked.connect(self._start_scan)
        ctrl.addWidget(self._btn_scan)

        # Filter
        self._filter = QComboBox()
        self._filter.addItems(["All", "Suspicious Only", "Unsigned", "PUPs", "High Risk"])
        self._filter.setStyleSheet(f"""
            QComboBox {{
                background: {SURFACE}; color: {TEXT}; border: 1px solid {BORDER};
                border-radius: 8px; padding: 6px 12px; min-width: 150px;
            }}
            QComboBox::drop-down {{ border: none; }}
            QComboBox QAbstractItemView {{
                background: {SURFACE}; color: {TEXT}; border: 1px solid {BORDER};
                selection-background-color: {PRIMARY};
            }}
        """)
        self._filter.currentIndexChanged.connect(self._apply_filter)
        ctrl.addWidget(QLabel("Filter:"))
        ctrl.addWidget(self._filter)
        ctrl.addStretch()

        self._lbl_count = QLabel("0 apps")
        self._lbl_count.setStyleSheet(f"color: {MUTED}; font-size: 11px;")
        ctrl.addWidget(self._lbl_count)
        layout.addLayout(ctrl)

        # Progress
        self._progress = QProgressBar()
        self._progress.setFixedHeight(6)
        self._progress.setTextVisible(False)
        self._progress.hide()
        self._progress.setStyleSheet(f"""
            QProgressBar {{ background: {SURFACE}; border-radius: 3px; border: none; }}
            QProgressBar::chunk {{ background: {PRIMARY}; border-radius: 3px; }}
        """)
        layout.addWidget(self._progress)

        # Table
        cols = ["App Name", "Publisher", "Installed", "Risk", "Score", "Signature", "Action"]
        self._table = QTableWidget(0, len(cols))
        self._table.setHorizontalHeaderLabels(cols)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for i in range(2, len(cols)):
            self._table.horizontalHeader().setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._context_menu)
        self._table.setStyleSheet(f"""
            QTableWidget {{
                background: {SURFACE}; color: {TEXT};
                border: 1px solid {BORDER}; border-radius: 10px;
                gridline-color: {BORDER};
            }}
            QTableWidget::item:selected {{ background: #253050; }}
            QHeaderView::section {{
                background: #141720; color: {MUTED};
                border: none; padding: 8px; font-weight: 600; font-size: 11px;
            }}
            QTableWidget::item:alternate {{ background: #15181f; }}
        """)
        layout.addWidget(self._table, 1)

        # Load cached results
        self._load_cached()

    def _load_cached(self):
        if not self.db or not hasattr(self.db, "get_app_scan_results"):
            return
        try:
            results = self.db.get_app_scan_results()
            for r in results:
                if isinstance(r.get("flags"), str):
                    try:
                        r["flags"] = json.loads(r["flags"])
                    except Exception:
                        r["flags"] = []
                self._results.append(r)
                self._add_row(r)
            self._lbl_count.setText(f"{len(results)} apps")
        except Exception:
            pass

    def _start_scan(self):
        scanner = self.modules.get("app_reputation")
        if not scanner:
            self._status.setText("App reputation scanner not available")
            return

        self._table.setRowCount(0)
        self._results.clear()
        self._btn_scan.setEnabled(False)
        self._progress.show()
        self._status.setText("Scanning installed apps…")

        self._worker = AppScanWorker(scanner)
        self._thread = QThread()
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._on_progress)
        self._worker.result.connect(self._on_result)
        self._worker.finished.connect(self._on_done)
        self._thread.start()

    def _on_progress(self, current, total, name):
        self._progress.setMaximum(total)
        self._progress.setValue(current)
        self._status.setText(f"Scanning: {name} ({current}/{total})")

    def _on_result(self, result):
        self._results.append(result)
        self._add_row(result)

    def _on_done(self):
        self._progress.hide()
        self._btn_scan.setEnabled(True)
        flagged = sum(1 for r in self._results if r.get("risk_level") != "clean")
        self._status.setText(f"Scan complete: {len(self._results)} apps, {flagged} flagged")
        self._lbl_count.setText(f"{len(self._results)} apps")
        if self._thread:
            self._thread.quit()

    def _add_row(self, result):
        row = self._table.rowCount()
        self._table.insertRow(row)

        risk = result.get("risk_level", "clean")
        color = RISK_COLORS.get(risk, MUTED)
        score = result.get("suspicion_score", 0)

        items = [
            result.get("app_name", ""),
            result.get("publisher", "") or "Unknown",
            result.get("install_date", "") or "—",
            risk.upper(),
            str(score),
            result.get("signature_status", ""),
            result.get("recommended_action", "none"),
        ]

        for col, text in enumerate(items):
            item = QTableWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, result)
            if col == 3:  # Risk
                item.setForeground(QColor(color))
                item.setFont(item.font())
            if col == 4:  # Score
                if score >= 66:
                    item.setForeground(QColor(DANGER))
                elif score >= 46:
                    item.setForeground(QColor(WARNING))
                elif score >= 21:
                    item.setForeground(QColor("#6bba75"))
            self._table.setItem(row, col, item)

    def _apply_filter(self, index):
        filter_text = self._filter.currentText()
        for row in range(self._table.rowCount()):
            item = self._table.item(row, 0)
            if not item:
                continue
            result = item.data(Qt.ItemDataRole.UserRole)
            if not result:
                continue

            show = True
            risk = result.get("risk_level", "clean")
            sig = result.get("signature_status", "")
            flags = result.get("flags", [])

            if filter_text == "Suspicious Only":
                show = risk not in ("clean",)
            elif filter_text == "Unsigned":
                show = sig == "NotSigned"
            elif filter_text == "PUPs":
                show = any("pup" in f.lower() for f in flags)
            elif filter_text == "High Risk":
                show = risk in ("high", "critical")

            self._table.setRowHidden(row, not show)

    def _context_menu(self, pos):
        row = self._table.rowAt(pos.y())
        if row < 0:
            return
        item = self._table.item(row, 0)
        if not item:
            return
        result = item.data(Qt.ItemDataRole.UserRole)

        menu = QMenu(self)
        menu.setStyleSheet(f"""
            QMenu {{ background: {SURFACE}; color: {TEXT}; border: 1px solid {BORDER};
                     border-radius: 8px; padding: 4px; }}
            QMenu::item:selected {{ background: {PRIMARY}; border-radius: 4px; }}
        """)

        act_details = menu.addAction("📋 View Details")
        act_trust = menu.addAction("✅ Add Publisher to Trusted")
        act_remove = menu.addAction("🗑 Remove App")
        menu.addSeparator()
        act_quarantine = menu.addAction("🔒 Quarantine Installer")

        action = menu.exec(self._table.viewport().mapToGlobal(pos))

        if action == act_details:
            details = json.dumps(result, indent=2, default=str)
            QMessageBox.information(self, "App Details", details[:2000])
        elif action == act_trust:
            publisher = result.get("publisher", "")
            if publisher:
                scanner = self.modules.get("app_reputation")
                if scanner:
                    scanner.add_trusted_publisher(publisher)
                    QMessageBox.information(self, "Trusted",
                                            f"Added '{publisher}' to trusted publishers.")
        elif action == act_remove:
            uninstall = result.get("uninstall_string", "")
            if uninstall:
                QMessageBox.information(self, "Remove App",
                                        f"Run this to uninstall:\n{uninstall}")
            else:
                QMessageBox.warning(self, "No Uninstaller",
                                    "No uninstall command found for this app.")

    def refresh(self):
        pass

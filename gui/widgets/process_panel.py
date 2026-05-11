"""
gui/widgets/process_panel.py — Live process monitor panel
"""
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QMessageBox
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
            border-radius: 8px; padding: 7px 16px; font-size: 12px; font-weight: 600;
        }}
        QPushButton:hover {{ opacity: 0.85; }}
        QPushButton:disabled {{ background: #333; color: #666; }}
    """)
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    return b


class ProcessPanel(QWidget):
    def __init__(self, config: dict, db=None, modules: dict = None):
        super().__init__()
        self.config = config
        self.db = db
        self.modules = modules or {}
        self._build_ui()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh_table)
        self._timer.start(3000)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("Process Monitor")
        title.setStyleSheet(f"color: {TEXT}; font-size: 22px; font-weight: 700;")
        layout.addWidget(title)

        # Controls
        ctrl = QHBoxLayout()
        self._btn_kill  = _btn("🗑 Kill Process", DANGER)
        self._btn_trust = _btn("✓ Trust Process", SUCCESS)
        self._lbl_count = QLabel("0 processes")
        self._lbl_count.setStyleSheet(f"color: {MUTED}; font-size: 12px;")

        self._btn_kill.clicked.connect(self._kill_selected)
        self._btn_trust.clicked.connect(self._trust_selected)

        ctrl.addWidget(self._btn_kill)
        ctrl.addWidget(self._btn_trust)
        ctrl.addStretch()
        ctrl.addWidget(self._lbl_count)
        layout.addLayout(ctrl)

        # Table
        cols = ["PID", "Name", "CPU %", "Mem MB", "Status", "Alerts"]
        self._table = QTableWidget(0, len(cols))
        self._table.setHorizontalHeaderLabels(cols)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for i in (0, 2, 3, 4, 5):
            self._table.horizontalHeader().setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setSortingEnabled(True)
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
        self._refresh_table()

    def _refresh_table(self) -> None:
        pm = self.modules.get("process_monitor")
        if not pm:
            return
        procs = pm.get_process_list()
        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        for proc in procs:
            row = self._table.rowCount()
            self._table.insertRow(row)
            suspicious = proc.get("suspicious", False)
            row_color = QColor("#2a1515") if suspicious else QColor("transparent")
            vals = [
                str(proc["pid"]),
                proc["name"],
                f"{proc['cpu']:.1f}",
                str(proc["mem_mb"]),
                proc["status"],
                ", ".join(proc.get("alerts", [])) or "—"
            ]
            for col, val in enumerate(vals):
                item = QTableWidgetItem(val)
                item.setData(Qt.ItemDataRole.UserRole, proc["pid"])
                if suspicious:
                    item.setForeground(QColor(WARNING))
                if col == 2:  # CPU column color
                    cpu = proc["cpu"]
                    c = DANGER if cpu > 80 else WARNING if cpu > 50 else SUCCESS
                    item.setForeground(QColor(c))
                self._table.setItem(row, col, item)

        self._table.setSortingEnabled(True)
        self._lbl_count.setText(f"{len(procs)} processes")

    def _get_selected_pid(self) -> int:
        rows = self._table.selectedItems()
        if rows:
            return rows[0].data(Qt.ItemDataRole.UserRole)
        return -1

    def _kill_selected(self) -> None:
        pid = self._get_selected_pid()
        if pid < 0:
            return
        reply = QMessageBox.question(self, "Kill Process", f"Kill PID {pid}?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            pm = self.modules.get("process_monitor")
            if pm:
                pm.kill_process(pid)
                self._refresh_table()

    def _trust_selected(self) -> None:
        pid = self._get_selected_pid()
        if pid < 0:
            return
        pm = self.modules.get("process_monitor")
        if pm:
            pm.trust_process(pid)
            self._refresh_table()

    def refresh(self) -> None:
        self._refresh_table()

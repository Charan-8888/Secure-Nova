"""
gui/widgets/quarantine_panel.py — Quarantined files management panel
"""
import os
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QMessageBox, QFileDialog
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


class QuarantinePanel(QWidget):
    def __init__(self, config: dict, db=None, modules: dict = None):
        super().__init__()
        self.config = config
        self.db = db
        self.modules = modules or {}
        self._entries: list[dict] = []
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("Quarantine Vault")
        title.setStyleSheet(f"color: {TEXT}; font-size: 22px; font-weight: 700;")
        layout.addWidget(title)

        # Info bar
        self._lbl_count = QLabel("0 items in quarantine")
        self._lbl_count.setStyleSheet(f"color: {MUTED}; font-size: 12px;")

        ctrl = QHBoxLayout()
        self._btn_restore = _btn("↩ Restore", WARNING)
        self._btn_delete  = _btn("🗑 Delete Permanently", DANGER)
        self._btn_refresh_q = _btn("↻ Refresh", PRIMARY)

        self._btn_restore.clicked.connect(self._restore_selected)
        self._btn_delete.clicked.connect(self._delete_selected)
        self._btn_refresh_q.clicked.connect(self.refresh)

        ctrl.addWidget(self._lbl_count)
        ctrl.addStretch()
        ctrl.addWidget(self._btn_restore)
        ctrl.addWidget(self._btn_delete)
        ctrl.addWidget(self._btn_refresh_q)
        layout.addLayout(ctrl)

        # Table
        cols = ["ID", "Original Path", "Threat Name", "Type", "Quarantined At"]
        self._table = QTableWidget(0, len(cols))
        self._table.setHorizontalHeaderLabels(cols)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for i in (0, 2, 3, 4):
            self._table.horizontalHeader().setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
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
                border: none; padding: 8px; font-weight: 600; font-size: 11px;
            }}
            QTableWidget::item:alternate {{ background: #15181f; }}
        """)
        layout.addWidget(self._table, 1)
        self.refresh()

    def refresh(self) -> None:
        if not self.db:
            return
        self._entries = self.db.get_quarantine()
        self._table.setRowCount(0)
        for entry in self._entries:
            row = self._table.rowCount()
            self._table.insertRow(row)
            vals = [
                str(entry["id"]),
                entry["original_path"],
                entry.get("threat_name", ""),
                entry.get("threat_type", ""),
                entry["timestamp"],
            ]
            for col, val in enumerate(vals):
                item = QTableWidgetItem(val)
                item.setData(Qt.ItemDataRole.UserRole, entry["id"])
                if col == 2 and val:
                    item.setForeground(QColor(DANGER))
                self._table.setItem(row, col, item)
        self._lbl_count.setText(f"{len(self._entries)} item(s) in quarantine")

    def _get_selected_entry(self) -> dict | None:
        rows = self._table.selectedItems()
        if not rows:
            return None
        entry_id = rows[0].data(Qt.ItemDataRole.UserRole)
        return next((e for e in self._entries if e["id"] == entry_id), None)

    def _restore_selected(self) -> None:
        entry = self._get_selected_entry()
        if not entry:
            return
        dest_folder = QFileDialog.getExistingDirectory(self, "Restore to Folder")
        if not dest_folder:
            return
        scanner = self.modules.get("file_scanner")
        if scanner:
            dest = Path(dest_folder) / Path(entry["quarantine_path"]).stem
            ok = scanner.restore_from_quarantine(
                entry["quarantine_path"], str(dest), entry["id"]
            )
            if ok:
                QMessageBox.information(self, "Restored", f"File restored to:\n{dest}")
                self.refresh()
            else:
                QMessageBox.warning(self, "Error", "Restore failed — see log.")

    def _delete_selected(self) -> None:
        entry = self._get_selected_entry()
        if not entry:
            return
        reply = QMessageBox.warning(
            self, "Delete Permanently",
            f"Permanently delete:\n{entry['original_path']}\n\nThis cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                qp = Path(entry["quarantine_path"])
                if qp.exists():
                    qp.unlink()
                if self.db:
                    self.db.mark_restored(entry["id"])  # mark as "handled"
                self.refresh()
            except Exception as e:
                QMessageBox.warning(self, "Error", str(e))

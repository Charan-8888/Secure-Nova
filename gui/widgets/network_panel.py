"""
gui/widgets/network_panel.py — Network connections panel
"""
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QLineEdit
)

SURFACE = "#1a1d27"
BORDER  = "#2a2d3a"
PRIMARY = "#4f8ef7"
SUCCESS = "#4caf7d"
DANGER  = "#e05252"
WARNING = "#f5a623"
TEXT    = "#e0e4f0"
MUTED   = "#8890a4"

RISK_COLORS = {"high": DANGER, "medium": WARNING, "low": SUCCESS}


def _btn(label: str, color: str = PRIMARY) -> QPushButton:
    b = QPushButton(label)
    b.setStyleSheet(f"""
        QPushButton {{
            background: {color}; color: #fff; border: none;
            border-radius: 8px; padding: 7px 16px; font-size: 12px; font-weight: 600;
        }}
        QPushButton:hover {{ opacity: 0.85; }}
    """)
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    return b


class NetworkPanel(QWidget):
    def __init__(self, config: dict, db=None, modules: dict = None):
        super().__init__()
        self.config = config
        self.db = db
        self.modules = modules or {}
        self._build_ui()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh_table)
        self._timer.start(5000)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("Network Monitor")
        title.setStyleSheet(f"color: {TEXT}; font-size: 22px; font-weight: 700;")
        layout.addWidget(title)

        # Domain block controls
        block_row = QHBoxLayout()
        self._domain_input = QLineEdit()
        self._domain_input.setPlaceholderText("Block a domain (e.g. evil.com)")
        self._domain_input.setStyleSheet(f"""
            QLineEdit {{
                background: {SURFACE}; color: {TEXT};
                border: 1px solid {BORDER}; border-radius: 8px;
                padding: 8px 12px; font-size: 13px;
            }}
            QLineEdit:focus {{ border-color: {PRIMARY}; }}
        """)
        self._btn_block  = _btn("🔒 Block Domain", DANGER)
        self._btn_refresh_bl = _btn("↻ Refresh Blocklist", "#7c5cbf")
        self._btn_block.clicked.connect(self._block_domain)
        self._btn_refresh_bl.clicked.connect(self._refresh_blocklist)

        block_row.addWidget(self._domain_input, 1)
        block_row.addWidget(self._btn_block)
        block_row.addWidget(self._btn_refresh_bl)
        layout.addLayout(block_row)

        # Stats row
        stats_row = QHBoxLayout()
        self._lbl_connections = QLabel("Active Connections: 0")
        self._lbl_connections.setStyleSheet(f"color: {MUTED}; font-size: 12px;")
        stats_row.addWidget(self._lbl_connections)
        stats_row.addStretch()
        layout.addLayout(stats_row)

        # Connections table
        cols = ["PID", "Process", "Local Addr", "Remote IP", "Port", "Protocol", "Risk"]
        self._table = QTableWidget(0, len(cols))
        self._table.setHorizontalHeaderLabels(cols)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        for i in (0, 2, 4, 5, 6):
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
        self._refresh_table()

    def _refresh_table(self) -> None:
        cm = self.modules.get("connection_monitor")
        if not cm:
            return
        conns = cm.get_connections()
        self._table.setRowCount(0)
        for conn in conns:
            row = self._table.rowCount()
            self._table.insertRow(row)
            risk = conn.get("risk", "low")
            color = QColor(RISK_COLORS.get(risk, SUCCESS))
            vals = [
                str(conn.get("pid", "")),
                conn.get("process_name", ""),
                conn.get("local_addr", ""),
                conn.get("remote_ip", ""),
                str(conn.get("remote_port", "")),
                conn.get("protocol", ""),
                risk.upper(),
            ]
            for col, val in enumerate(vals):
                item = QTableWidgetItem(val)
                if col == 6:
                    item.setForeground(color)
                self._table.setItem(row, col, item)
        self._lbl_connections.setText(f"Active Connections: {len(conns)}")

    def _block_domain(self) -> None:
        domain = self._domain_input.text().strip().lower()
        if not domain:
            return
        bm = self.modules.get("blocklist_manager")
        if bm:
            bm.add_custom_domain(domain)
        if self.db:
            self.db.add_custom_domain(domain)
        self._domain_input.clear()

    def _refresh_blocklist(self) -> None:
        import threading
        bm = self.modules.get("blocklist_manager")
        if bm:
            threading.Thread(target=bm.refresh, daemon=True).start()

    def refresh(self) -> None:
        self._refresh_table()

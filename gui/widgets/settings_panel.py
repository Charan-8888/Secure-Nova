"""
gui/widgets/settings_panel.py — Settings and configuration panel
"""
import json
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QCheckBox, QScrollArea, QFrame, QSpinBox,
    QGroupBox, QFormLayout, QMessageBox, QListWidget, QListWidgetItem
)

CONFIG_PATH = Path("config/settings.json")
SURFACE = "#1a1d27"
BORDER  = "#2a2d3a"
PRIMARY = "#4f8ef7"
SUCCESS = "#4caf7d"
DANGER  = "#e05252"
TEXT    = "#e0e4f0"
MUTED   = "#8890a4"

CHECKBOX_STYLE = f"""
    QCheckBox {{ color: {TEXT}; spacing: 8px; }}
    QCheckBox::indicator {{ width:18px; height:18px; border-radius:5px;
        border: 2px solid {BORDER}; background: {SURFACE}; }}
    QCheckBox::indicator:checked {{ background: {PRIMARY}; border-color: {PRIMARY}; }}
"""
INPUT_STYLE = f"""
    QLineEdit, QSpinBox {{
        background: {SURFACE}; color: {TEXT};
        border: 1px solid {BORDER}; border-radius: 8px;
        padding: 8px 12px; font-size: 13px;
    }}
    QLineEdit:focus, QSpinBox:focus {{ border-color: {PRIMARY}; }}
"""
GROUP_STYLE = f"""
    QGroupBox {{
        color: {MUTED}; font-size: 11px; font-weight: 600;
        border: 1px solid {BORDER}; border-radius: 10px;
        margin-top: 12px; padding: 12px;
    }}
    QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 6px; }}
"""


def _btn(label: str, color: str = PRIMARY) -> QPushButton:
    b = QPushButton(label)
    b.setStyleSheet(f"""
        QPushButton {{
            background: {color}; color: #fff; border: none;
            border-radius: 8px; padding: 8px 20px; font-size: 13px; font-weight: 600;
        }}
        QPushButton:hover {{ opacity: 0.85; }}
    """)
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    return b


class SettingsPanel(QWidget):
    def __init__(self, config: dict, db=None, modules: dict = None):
        super().__init__()
        self.config = config
        self.db = db
        self.modules = modules or {}
        self._build_ui()

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        title = QLabel("Settings")
        title.setStyleSheet(f"color: {TEXT}; font-size: 22px; font-weight: 700;")
        title.setContentsMargins(24, 24, 24, 8)
        outer.addWidget(title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(24, 8, 24, 24)
        layout.setSpacing(16)
        scroll.setWidget(content)
        outer.addWidget(scroll, 1)

        # --- API Keys ---
        api_group = QGroupBox("API Keys")
        api_group.setStyleSheet(GROUP_STYLE)
        api_form = QFormLayout(api_group)

        self._vt_key = QLineEdit(self.config.get("virustotal_api_key", ""))
        self._vt_key.setPlaceholderText("VirusTotal API Key")
        self._vt_key.setEchoMode(QLineEdit.EchoMode.Password)
        self._vt_key.setStyleSheet(INPUT_STYLE)

        self._abuse_key = QLineEdit(self.config.get("abuseipdb_api_key", ""))
        self._abuse_key.setPlaceholderText("AbuseIPDB API Key (optional)")
        self._abuse_key.setEchoMode(QLineEdit.EchoMode.Password)
        self._abuse_key.setStyleSheet(INPUT_STYLE)

        api_form.addRow("VirusTotal:", self._vt_key)
        api_form.addRow("AbuseIPDB:", self._abuse_key)
        layout.addWidget(api_group)

        # --- Toggles ---
        toggle_group = QGroupBox("Module Toggles")
        toggle_group.setStyleSheet(GROUP_STYLE)
        tgl = QVBoxLayout(toggle_group)

        self._chk_auto_quarantine  = self._chk("Auto-quarantine threats", "auto_quarantine")
        self._chk_auto_kill        = self._chk("Auto-kill suspicious processes", "auto_kill_process")
        self._chk_auto_eject       = self._chk("Auto-eject USB on threat", "auto_eject_usb_on_threat")
        self._chk_notifications    = self._chk("Desktop notifications", "notifications_enabled")
        self._chk_sound_alerts     = self._chk("Sound alerts", "sound_alerts")
        self._chk_start_windows    = self._chk("Start with Windows", "start_with_windows")

        for chk in (self._chk_auto_quarantine, self._chk_auto_kill, self._chk_auto_eject,
                    self._chk_notifications, self._chk_sound_alerts, self._chk_start_windows):
            tgl.addWidget(chk)
        layout.addWidget(toggle_group)

        # --- Intervals ---
        int_group = QGroupBox("Update Intervals")
        int_group.setStyleSheet(GROUP_STYLE)
        int_form = QFormLayout(int_group)

        self._spin_blocklist = QSpinBox()
        self._spin_blocklist.setRange(1, 168)
        self._spin_blocklist.setValue(self.config.get("blocklist_refresh_hours", 6))
        self._spin_blocklist.setStyleSheet(INPUT_STYLE)

        self._spin_hash = QSpinBox()
        self._spin_hash.setRange(1, 168)
        self._spin_hash.setValue(self.config.get("hash_db_refresh_hours", 24))
        self._spin_hash.setStyleSheet(INPUT_STYLE)

        int_form.addRow("Blocklist refresh (hours):", self._spin_blocklist)
        int_form.addRow("Hash DB refresh (hours):", self._spin_hash)
        layout.addWidget(int_group)

        # --- Whitelist ---
        wl_group = QGroupBox("Process Whitelist")
        wl_group.setStyleSheet(GROUP_STYLE)
        wl_layout = QVBoxLayout(wl_group)

        self._wl_list = QListWidget()
        self._wl_list.setFixedHeight(140)
        self._wl_list.setStyleSheet(f"""
            QListWidget {{ background: {SURFACE}; color: {TEXT};
                border: 1px solid {BORDER}; border-radius: 8px; }}
            QListWidget::item:selected {{ background: #253050; }}
        """)
        for proc in self.config.get("whitelist_processes", []):
            self._wl_list.addItem(proc)

        wl_input_row = QHBoxLayout()
        self._wl_input = QLineEdit()
        self._wl_input.setPlaceholderText("Add process (e.g. myapp.exe)")
        self._wl_input.setStyleSheet(INPUT_STYLE)
        btn_wl_add = _btn("Add", SUCCESS)
        btn_wl_rem = _btn("Remove", DANGER)
        btn_wl_add.clicked.connect(self._add_whitelist)
        btn_wl_rem.clicked.connect(self._remove_whitelist)
        wl_input_row.addWidget(self._wl_input, 1)
        wl_input_row.addWidget(btn_wl_add)
        wl_input_row.addWidget(btn_wl_rem)

        wl_layout.addWidget(self._wl_list)
        wl_layout.addLayout(wl_input_row)
        layout.addWidget(wl_group)

        # --- Save button ---
        btn_row = QHBoxLayout()
        btn_save = _btn("💾 Save Settings", PRIMARY)
        btn_save.clicked.connect(self._save)
        btn_row.addStretch()
        btn_row.addWidget(btn_save)
        layout.addLayout(btn_row)
        layout.addStretch()

    def _chk(self, label: str, key: str) -> QCheckBox:
        cb = QCheckBox(label)
        cb.setChecked(self.config.get(key, False))
        cb.setStyleSheet(CHECKBOX_STYLE)
        cb.setProperty("config_key", key)
        return cb

    def _add_whitelist(self) -> None:
        proc = self._wl_input.text().strip()
        if proc:
            self._wl_list.addItem(proc)
            self._wl_input.clear()

    def _remove_whitelist(self) -> None:
        for item in self._wl_list.selectedItems():
            self._wl_list.takeItem(self._wl_list.row(item))

    def _save(self) -> None:
        self.config["virustotal_api_key"] = self._vt_key.text().strip()
        self.config["abuseipdb_api_key"]  = self._abuse_key.text().strip()
        self.config["auto_quarantine"]         = self._chk_auto_quarantine.isChecked()
        self.config["auto_kill_process"]       = self._chk_auto_kill.isChecked()
        self.config["auto_eject_usb_on_threat"]= self._chk_auto_eject.isChecked()
        self.config["notifications_enabled"]   = self._chk_notifications.isChecked()
        self.config["sound_alerts"]            = self._chk_sound_alerts.isChecked()
        self.config["start_with_windows"]      = self._chk_start_windows.isChecked()
        self.config["blocklist_refresh_hours"] = self._spin_blocklist.value()
        self.config["hash_db_refresh_hours"]   = self._spin_hash.value()
        self.config["whitelist_processes"] = [
            self._wl_list.item(i).text() for i in range(self._wl_list.count())
        ]
        try:
            CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(CONFIG_PATH, "w") as f:
                json.dump(self.config, f, indent=2)
            QMessageBox.information(self, "Saved", "Settings saved successfully.")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not save settings:\n{e}")

    def refresh(self) -> None:
        pass

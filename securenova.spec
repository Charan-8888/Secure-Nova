; SecureNova PyInstaller spec file
; Usage: pyinstaller securenova.spec

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('rules', 'rules'),
        ('config', 'config'),
        ('assets', 'assets'),
    ],
    hiddenimports=[
        'PyQt6.QtCore', 'PyQt6.QtGui', 'PyQt6.QtWidgets',
        'psutil', 'watchdog', 'yara', 'winreg', 'wmi',
        'win32api', 'win32con', 'win32process', 'win32job',
        'requests', 'sqlite3', 'pefile',
        'gui.main_window',
        'gui.widgets.overview_panel',
        'gui.widgets.filescan_panel',
        'gui.widgets.process_panel',
        'gui.widgets.network_panel',
        'gui.widgets.quarantine_panel',
        'gui.widgets.settings_panel',
        'gui.widgets.alert_banner',
        'scanner.file_scanner',
        'scanner.realtime_monitor',
        'scanner.virustotal',
        'monitor.process_monitor',
        'monitor.registry_watcher',
        'monitor.usb_monitor',
        'monitor.startup_manager',
        'network.connection_monitor',
        'network.blocklist_manager',
        'sandbox.executor',
        'utils.database',
        'utils.logger',
        'utils.updater',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='SecureNova',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,   # windowed — no console
    icon='assets/shield.ico',
)

@echo off
setlocal EnableDelayedExpansion

echo ============================================
echo  SecureNova -- Setup Script
echo ============================================
echo.

:: ── Step 1: Check Python ───────────────────────────────────────────────
python --version >nul 2>&1
if !errorlevel! neq 0 (
    echo [ERROR] Python not found. Install Python 3.11+ and add it to PATH.
    pause
    exit /b 1
)
echo [OK] Python found:
python --version

echo.
:: ── Step 2: Create virtual environment ────────────────────────────────
if exist .venv\Scripts\activate (
    echo [INFO] Virtual environment already exists, skipping creation.
    goto :activate
)

echo [1/4] Creating virtual environment (.venv)...
python -m venv .venv
if !errorlevel! neq 0 (
    echo [ERROR] Failed to create virtual environment.
    pause
    exit /b 1
)
echo [OK] Virtual environment created at .venv\

:activate
echo.
:: ── Step 3: Activate venv ─────────────────────────────────────────────
echo [2/4] Activating virtual environment...
call .venv\Scripts\activate
if !errorlevel! neq 0 (
    echo [ERROR] Could not activate virtual environment.
    pause
    exit /b 1
)
echo [OK] Venv active.

echo.
:: ── Step 4: Upgrade pip ────────────────────────────────────────────────
echo [3/4] Upgrading pip...
python -m pip install --upgrade pip

echo.
:: ── Step 5: Install dependencies ──────────────────────────────────────
echo [4/4] Installing all dependencies...
pip install yara-python watchdog psutil pywin32 PyQt6 wmi requests scapy pefile pyinstaller
if !errorlevel! neq 0 (
    echo [ERROR] pip install failed. Check your internet connection.
    pause
    exit /b 1
)

echo.
:: ── Step 6: pywin32 post-install ──────────────────────────────────────
echo Running pywin32 post-install...
python -m pywin32_postinstall -install 2>nul
echo [OK] pywin32 configured.

:: ── Step 7: Create project directories ────────────────────────────────
echo.
echo Creating project directories...
if not exist rules  mkdir rules
if not exist data   mkdir data
if not exist logs   mkdir logs
if not exist assets mkdir assets
echo [OK] Directories ready.

echo.
echo ============================================
echo  Setup complete!
echo.
echo  To activate venv manually (CMD):
echo    .venv\Scripts\activate
echo.
echo  To run SecureNova:
echo    Double-click  run.bat
echo    OR manually:  python main.py
echo.
echo  TIP: Run as Administrator for full features
echo       (hosts file, registry, USB eject)
echo ============================================
pause
endlocal

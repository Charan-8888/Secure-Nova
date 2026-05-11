@echo off
:: SecureNova launcher — activates .venv then runs main.py

if not exist .venv\Scripts\activate.bat (
    echo [ERROR] Virtual environment not found.
    echo Run setup.bat first to create it.
    pause
    exit /b 1
)

echo Activating virtual environment...
call .venv\Scripts\activate.bat

echo Starting SecureNova...
python main.py %*

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] SecureNova exited with an error.
    echo Check logs\securenova.log for details.
    pause
)

@echo off
setlocal EnableDelayedExpansion
title WinHardener - Host Security Posture & LPE Auditor

echo [WinHardener] Verifying Python 3.9+ runtime environment...
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python was not detected in the system PATH.
    echo Please install Python 3.9 or newer from https://www.python.org/downloads/ and ensure "Add Python to PATH" is enabled.
    pause
    exit /b 1
)

python -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] WinHardener requires Python 3.9 or newer.
    python --version
    pause
    exit /b 1
)

if not exist ".venv\Scripts\activate.bat" (
    echo [WinHardener] Creating isolated virtual environment in .venv ...
    python -m venv .venv
    if !errorlevel! neq 0 (
        echo [ERROR] Failed to initialize Python virtual environment.
        pause
        exit /b 1
    )
)

call .venv\Scripts\activate.bat
if %errorlevel% neq 0 (
    echo [ERROR] Failed to activate virtual environment.
    pause
    exit /b 1
)

if not exist ".venv\installed_marker.txt" (
    if exist "requirements.txt" (
        echo [WinHardener] Installing required Python dependencies...
        python -m pip install --upgrade pip >nul 2>&1
        pip install -r requirements.txt
        if !errorlevel! equ 0 (
            echo Dependencies installed on %DATE% %TIME% > ".venv\installed_marker.txt"
        ) else (
            echo [ERROR] Dependency installation failed. Check network connectivity or pip configuration.
            pause
            exit /b 1
        )
    )
)

echo [WinHardener] Launching full host security posture assessment...
python winhardener.py --audit-all %*

echo.
pause
endlocal

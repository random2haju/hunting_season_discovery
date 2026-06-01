@echo off
setlocal

echo ============================================================
echo  Threat Hunt Dashboard — Setup
echo ============================================================
echo.

:: ── Python dependencies ─────────────────────────────────────
echo [1/3] Installing Python dependencies...
python -m pip install -r web\requirements.txt
if errorlevel 1 (
    echo [ERROR] pip install failed. Make sure Python is on your PATH.
    pause
    exit /b 1
)
echo.

:: ── Node.js check ────────────────────────────────────────────
echo [2/3] Checking for Node.js...
where node >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js not found. Download it from https://nodejs.org and re-run setup.
    pause
    exit /b 1
)
node --version
echo.

:: ── Frontend build ───────────────────────────────────────────
echo [3/3] Installing and building the React frontend...
cd web\frontend
if not exist package.json (
    echo [ERROR] web\frontend\package.json not found.
    echo         Run the frontend scaffold step first (see README).
    pause
    exit /b 1
)
call npm install
if errorlevel 1 (
    echo [ERROR] npm install failed.
    pause
    exit /b 1
)
call npm run build
if errorlevel 1 (
    echo [ERROR] npm run build failed.
    pause
    exit /b 1
)
cd ..\..

echo.
echo ============================================================
echo  Setup complete.  Start the dashboard with:
echo    python web\app.py
echo ============================================================
pause

@echo off
setlocal
title 221B - Find the Intruder
cd /d "%~dp0"

echo.
echo   221B - Find the Intruder  (ALGOTHON'26, ALG-CYBER-01)
echo.

where python >nul 2>&1 || (echo [ERROR] Python not found. Install Python 3.11+ from https://python.org & goto :fail)
where npm >nul 2>&1 || (echo [ERROR] Node.js not found. Install Node 20+ from https://nodejs.org & goto :fail)

echo [1/3] Installing Python dependencies...
python -m pip install -e ".[dev]" --quiet || (echo [ERROR] pip install failed. & goto :fail)

echo [2/3] Building the frontend...
pushd frontend
if not exist node_modules (
    call npm ci || (popd & echo [ERROR] npm ci failed. & goto :fail)
)
call npm run build || (popd & echo [ERROR] Frontend build failed. & goto :fail)
popd

echo [3/3] Starting 221B at http://localhost:8221  (Ctrl+C to stop)
start "" /b cmd /c "timeout /t 3 >nul & start http://localhost:8221"
python -m uvicorn backend.api.app:app --port 8221
goto :eof

:fail
echo.
pause
exit /b 1

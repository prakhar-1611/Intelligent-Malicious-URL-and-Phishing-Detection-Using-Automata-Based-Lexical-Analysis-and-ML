@echo off
rem One-command start: API on :8000, dashboard on :5173, then open the browser.
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo .venv not found. Create it first: python -m venv .venv ^&^& .venv\Scripts\pip install -r requirements.txt
  pause & exit /b 1
)
if not exist "web\node_modules" (
  echo Installing dashboard packages...
  pushd web & call npm install & popd
)
rem the venv's own python, so the trained model (lightgbm) loads instead of the heuristic fallback
start "Phishing API" cmd /k ".venv\Scripts\python.exe -m uvicorn api.main:app --port 8000"
start "Phishing dashboard" cmd /k "cd web && npm run dev"
rem give Vite a few seconds to start before opening the page
ping -n 6 127.0.0.1 >nul
start "" http://localhost:5173

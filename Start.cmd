@echo off
cd /d "%~dp0"
where py >nul 2>nul
if not errorlevel 1 (
  py -3 "%~dp0scripts\GameNetCheck.py"
) else (
  python "%~dp0scripts\GameNetCheck.py"
)
if errorlevel 1 (
  echo Install Python 3.10+ from https://www.python.org/downloads/windows/
  pause
)

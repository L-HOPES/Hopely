@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul && (set PY=py) || (set PY=python)
%PY% "%~dp0hopely_launcher.py"
if errorlevel 1 pause
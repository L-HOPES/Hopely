@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul && (set PY=py) || (set PY=python)
if "%~1"=="" (
    echo Использование: run_hopely.bat "путь к файлу или папке"
    pause
    exit /b 3
)
%PY% "%~dp0hopely.py" --target "%~1"
pause
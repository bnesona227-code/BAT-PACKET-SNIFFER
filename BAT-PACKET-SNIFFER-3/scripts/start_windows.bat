@echo off
chcp 65001 >nul
cd /d "%~dp0.."
echo =================================================================
echo  BAT-PACKET-SNIFFER v1.3 // WINDOWS LAUNCHER (100%% ZERO-PIP)
echo =================================================================
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python не найден! Установите Python 3.8+ с python.org.
    pause
    exit /b 1
)
python src\server.py
pause

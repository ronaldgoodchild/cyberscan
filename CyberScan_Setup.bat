@echo off
title CyberScan 2026 - Setup ^& Launcher
color 0B
echo.
echo  =====================================================
echo     CYBERSCAN 2026 TITAN ULTIMATE - Setup ^& Launch
echo     Developed by Ronald Goodchild
echo  =====================================================
echo.

:: ===== SELF-ELEVATE TO ADMIN =====
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Requesting Administrator privileges...
    echo.
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo [OK] Running as Administrator
echo.

:: ===== SET SCRIPT DIR =====
cd /d "%~dp0"
set "SCRIPTDIR=%~dp0"
set "PSSCRIPT=%SCRIPTDIR%cyberscan.ps1"
set "SETUPPS=%SCRIPTDIR%_setup_helper.ps1"

if not exist "%PSSCRIPT%" (
    echo [ERROR] cyberscan.ps1 not found in %SCRIPTDIR%
    echo         Place this batch file in the same folder as cyberscan.ps1
    pause
    exit /b 1
)

:: ===== RUN POWERSHELL SETUP SCRIPT =====
echo  Running setup via PowerShell...
echo.
powershell -ExecutionPolicy Bypass -NoProfile -File "%SETUPPS%"

:: ===== LAUNCH CYBERSCAN =====
echo.
echo  ======================================================
echo   Launching CyberScan 2026...
echo  ======================================================
echo.
timeout /t 3 /nobreak >nul
powershell -ExecutionPolicy Bypass -File "%PSSCRIPT%"

echo.
echo  CyberScan has exited.
pause

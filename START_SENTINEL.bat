@echo off
title SentinelView Launcher
color 0F

echo.
echo  ============================================
echo   SentinelView SIEM + SOAR Platform
echo   Starting all engines...
echo  ============================================
echo.

:: Check admin rights
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo  ERROR: Please run as Administrator
    echo  Right-click this file and select Run as administrator
    pause
    exit
)

echo  [OK] Running as Administrator
echo  [OK] Starting SentinelView engines...
echo.

python C:\SentinelView\launcher.py

pause
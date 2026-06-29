@echo off
title SentinelView Agent
color 0B

echo.
echo  ============================================
echo   SentinelView Remote Agent
echo   Sending logs to central dashboard...
echo  ============================================
echo.

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Run as Administrator
    pause
    exit
)

python C:\SentinelView\agent.py
pause
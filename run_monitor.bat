@echo off
REM Leonida PR Security Monitor - Quick Run
REM Runs the monitor once and shows results

cd /d "%~dp0"
python monitor.py --once --limit 100 --since-pr 8500

echo.
echo Done. Press any key to exit...
pause >nul
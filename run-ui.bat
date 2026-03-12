@echo off
setlocal EnableExtensions
cd /d "%~dp0"

where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  py -3 "%~dp0ui.py"
  goto :eof
)

where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  python "%~dp0ui.py"
  goto :eof
)

echo Python 3 not found. Install Python 3.8+ and try again.
pause
endlocal

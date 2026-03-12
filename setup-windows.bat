@echo off
setlocal EnableExtensions
cd /d "%~dp0"

echo ======================================
echo  Portable LAN Share Kit - Win Setup
echo ======================================
echo.

if not exist "runtime" mkdir "runtime"
if not exist "profiles" mkdir "profiles"
if not exist "bin" mkdir "bin"

set "PY_CMD="
where py >nul 2>nul
if %ERRORLEVEL% EQU 0 set "PY_CMD=py -3"
if not defined PY_CMD (
  where python >nul 2>nul
  if %ERRORLEVEL% EQU 0 set "PY_CMD=python"
)

if not defined PY_CMD (
  echo [ERROR] Python 3 not found.
  echo Install Python 3.8+ then run this file again.
  echo.
  pause
  exit /b 1
)

echo [OK] Python command: %PY_CMD%
%PY_CMD% -c "import sys; print('Python version:', sys.version.split()[0])"
echo.

if exist "bin\\wireproxy.exe" (
  echo [OK] wireproxy.exe found in bin\\
) else (
  echo [INFO] wireproxy.exe not found.
  echo        If you want wireproxy mode on Windows, place wireproxy.exe in:
  echo        bin\\wireproxy.exe
)

if exist "profiles\\*.conf" (
  echo [OK] WireGuard profile found in profiles\\
) else (
  echo [INFO] No .conf found in profiles\\ yet.
  echo        Put your WG files here, or set WG directory from the UI.
)

echo.
echo Setup check complete.
echo To start UI now, run: run-ui.bat
echo.
pause
exit /b 0

@echo off
setlocal
set DIR=%~dp0
set PY=py -3
%PY% "%DIR%ui.py"
if errorlevel 1 (
  python "%DIR%ui.py"
)
endlocal

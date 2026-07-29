@echo off
REM Build the single-file exe -> dist\xc_export.exe
cd /d "%~dp0"
.venv\Scripts\pyinstaller.exe --clean --noconfirm main.spec
pause

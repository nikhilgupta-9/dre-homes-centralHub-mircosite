@echo off
cd /d "%~dp0"
where python >nul 2>nul || (echo Python 3 install karo: python.org/downloads & pause & exit /b 1)
python studio.py
pause

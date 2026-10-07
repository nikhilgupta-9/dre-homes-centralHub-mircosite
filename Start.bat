@echo off
cd /d "%~dp0"
where node >nul 2>nul || (echo Node.js install karo: https://nodejs.org & pause & exit /b 1)
if not exist node_modules call npm install --omit=dev --ignore-scripts --no-audit --no-fund
node bin\sg-web.js
pause

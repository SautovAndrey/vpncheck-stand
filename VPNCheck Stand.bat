@echo off
cd /d "%~dp0"
where pyw >nul 2>nul && (start "" pyw -3 app.py & exit /b)
start "" pythonw app.py

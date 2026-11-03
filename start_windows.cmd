@echo off
cd /d "%~dp0"
set "MULTIVPN_DATA_DIR=%~dp0local-user"
if not exist ".venv\Scripts\pythonw.exe" (
 echo Run: python -m venv .venv
 echo Then: .venv\Scripts\python -m pip install -e .
 pause
 exit /b 1
)
start "Multi VPN" ".venv\Scripts\pythonw.exe" -m multi_vpn

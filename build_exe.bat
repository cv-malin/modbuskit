@echo off
chcp 65001 >nul
title Build ModbusKit exe
cd /d "%~dp0"
set PY=D:\xtrain-venv\Scripts\python.exe
if not exist "%PY%" set PY=python
echo Building ModbusKit.exe ...
"%PY%" -m PyInstaller --onefile --clean --name "ModbusKit" --add-data "web;web" --hidden-import socket --hidden-import serial --hidden-import serial.tools.list_ports launcher.py
echo.
echo Done. Output: dist\ModbusKit.exe
pause

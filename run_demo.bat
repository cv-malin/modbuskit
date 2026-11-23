@echo off
chcp 65001 >nul
title ModbusKit - 多协议工业通讯调试台
cd /d "%~dp0"
set PY=D:\xtrain-venv\Scripts\python.exe
if not exist "%PY%" set PY=python
echo.
echo   ModbusKit v1.0.0
echo   多协议工业通讯调试台 - Modbus / 三菱 / 欧姆龙 / AB
echo.
start "" http://127.0.0.1:8767
"%PY%" server.py
pause

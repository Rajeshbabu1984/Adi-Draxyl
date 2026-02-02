@echo off
REM Simple script to start a local Python HTTP server for CORS-safe testing
cd /d "%~dp0"
python -m http.server 8000

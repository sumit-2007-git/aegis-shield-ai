@echo off
title AegisLocal AI - On-Device Security Sentinel (PS-05)
echo ======================================================================
echo    AEGIS LOCAL AI: On-Device Threat, Phishing and Scam Intelligence
echo    Hackathon Problem Statement PS-05
echo    100% Privacy-Preserving | Sub-15ms Latency | Zero Cloud Telemetry
echo ======================================================================
echo.
echo Starting local offline server at http://127.0.0.1:8000 ...
echo [MOBILE ACCESS] Open on your phone: http://192.168.1.8:8000
echo Opening browser in 3 seconds...
start "" http://127.0.0.1:8000
python -m uvicorn server:app --host 0.0.0.0 --port 8000 --reload
pause

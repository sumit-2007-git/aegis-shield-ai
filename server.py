import os
import time
from typing import Optional
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
import pyperclip

from core.threat_engine import UnifiedThreatEngine

app = FastAPI(
    title="AegisLocal - On-Device Threat Intelligence API",
    description="Offline, privacy-preserving AI assistant for phishing and scam detection",
    version="1.0.0"
)

# Initialize on-device engine
engine = UnifiedThreatEngine()

class ScanRequest(BaseModel):
    text: str

class ScanResponse(BaseModel):
    verdict: str
    threat_level: str
    risk_score: int
    badge_color: str
    category: str
    confidence: float
    input_text: str
    highlighted_html: str
    extracted_urls: list
    tactics_detected: list
    explanation: dict
    telemetry: dict

# Pre-defined test cases for Hackathon Judges
DEMO_SCENARIOS = [
    {
        "id": "sbi_kyc",
        "title": "SBI YONO Block Threat",
        "tag": "Banking Fraud",
        "type": "danger",
        "content": "Dear customer, your SBI YONO account has been suspended due to pending KYC update. Click here to update your PAN and Aadhaar immediately to avoid permanent deactivation: http://sbi-kyc-update.xyz/login"
    },
    {
        "id": "power_cut",
        "title": "Electricity Bill Cutoff",
        "tag": "Urgency / Panic",
        "type": "danger",
        "content": "Dear Customer, Your electricity power will be disconnected tonight at 9:30 PM from the electricity office because your previous month bill was not updated. Please immediately contact our electricity officer at 9876543210."
    },
    {
        "id": "homograph_paypal",
        "title": "Typosquat & Suspicious TLD",
        "tag": "Phishing Link",
        "type": "danger",
        "content": "Alert: Unauthorized login attempt to your PayPal account from Russia. Verify your identity now: http://paypa1-security-check.xyz/login"
    },
    {
        "id": "telegram_job",
        "title": "Telegram ₹5000 Daily Job",
        "tag": "Task Scam",
        "type": "warning",
        "content": "Urgent Part-time Job Offer! Earn Rs 3000 to Rs 8000 daily by simply liking YouTube videos. Daily instant payout to UPI. Contact manager on Telegram: t.me/fast_money_payouts"
    },
    {
        "id": "india_post",
        "title": "India Post Parcel Delivery",
        "tag": "Smishing",
        "type": "danger",
        "content": "India Post alert: Your package #IN9841289 could not be delivered due to incorrect street address. Please update your address within 12 hours: http://indiapost-parcel-redelivery.top/address"
    },
    {
        "id": "legit_otp",
        "title": "Authentic HDFC Bank OTP",
        "tag": "Safe / Authentic",
        "type": "safe",
        "content": "Dear Customer, 482910 is the OTP for transaction of Rs 1,250.00 on Swiggy with your HDFC Bank Card ending 4412. OTP valid for 5 mins. Do not share OTP with anyone."
    },
    {
        "id": "legit_irctc",
        "title": "Authentic IRCTC Ticket Alert",
        "tag": "Safe / Authentic",
        "type": "safe",
        "content": "Dear Passenger, your train 12952 MUMBAI RAJDHANI is scheduled to depart at 16:55 from Platform 3. Have a safe journey - IRCTC."
    }
]

@app.post("/api/scan")
async def scan_endpoint(payload: ScanRequest):
    """Scan arbitrary text or URL strictly on-device."""
    result = engine.scan(payload.text)
    return JSONResponse(content=result)

@app.get("/api/scenarios")
async def get_scenarios():
    """Return preloaded test scenarios for one-click demos."""
    return JSONResponse(content=DEMO_SCENARIOS)

@app.get("/api/clipboard")
async def check_clipboard():
    """
    On-device clipboard sentinel check.
    Reads local clipboard and scans without cloud transmission.
    """
    try:
        clipboard_content = pyperclip.paste().strip()
        if not clipboard_content:
            return JSONResponse(content={"has_content": False, "text": ""})
        
        # Scan clipboard content
        result = engine.scan(clipboard_content)
        return JSONResponse(content={
            "has_content": True,
            "text": clipboard_content[:150] + ("..." if len(clipboard_content) > 150 else ""),
            "scan_result": result
        })
    except Exception as e:
        return JSONResponse(content={"has_content": False, "error": str(e)})

@app.get("/api/stats")
async def get_engine_stats():
    """Return on-device engine operational metrics."""
    return JSONResponse(content={
        "status": "OPERATIONAL",
        "mode": "AIR_GAPPED_LOCAL",
        "privacy": "Zero Telemetry / 0 Cloud Requests",
        "known_brands_indexed": len(engine.url_detector.brands),
        "suspicious_tlds_monitored": len(engine.url_detector.suspicious_tlds),
        "hardware_acceleration": "Local CPU (Optimized Vectorization)",
        "model_format": "Calibrated Ensemble (scikit-learn + Heuristic Matrix)"
    })

import socket

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

@app.get("/api/network-ip")
async def get_network_ip():
    """Return local WiFi IP address for mobile connection."""
    ip = get_local_ip()
    return JSONResponse(content={
        "local_ip": ip,
        "port": 8000,
        "mobile_url": f"http://{ip}:8000"
    })

# Serve web UI & PWA assets
web_dir = os.path.join(os.path.dirname(__file__), "web")
app.mount("/static", StaticFiles(directory=os.path.join(web_dir, "static")), name="static")

@app.get("/manifest.json")
async def serve_manifest():
    return FileResponse(
        os.path.join(web_dir, "manifest.json"), 
        media_type="application/manifest+json",
        headers={"Cache-Control": "no-cache"}
    )

@app.get("/sw.js")
async def serve_sw():
    return FileResponse(
        os.path.join(web_dir, "sw.js"), 
        media_type="application/javascript",
        headers={
            "Service-Worker-Allowed": "/",
            "Cache-Control": "no-cache"
        }
    )

@app.get("/")
async def serve_index():
    return FileResponse(os.path.join(web_dir, "index.html"))

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=False)

from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import os
from .models import MFAEvent, ThreatAlert
from .detector import MFAFatigueDetector
from typing import List

app = FastAPI(title="MFA Fatigue Hunter", description="Real-time detection of MFA push spam/fatigue attacks.")

# Get absolute path for templates
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

detector = MFAFatigueDetector()

@app.post("/api/v1/events", response_model=dict, status_code=status.HTTP_201_CREATED)
async def receive_event(event: MFAEvent):
    """
    Webhook endpoint to receive MFA events from identity providers (e.g. Okta, Duo).
    """
    alert = detector.process_event(event)

    response = {"status": "processed", "event_id": str(event.timestamp.timestamp())}
    if alert:
        response["alert_triggered"] = True
        response["alert_severity"] = alert.severity

    return response

@app.get("/api/v1/alerts", response_model=List[ThreatAlert])
async def get_alerts():
    """
    API endpoint to retrieve all active alerts.
    """
    return detector.get_alerts()

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """
    Web UI Dashboard for SOC Analysts to view alerts.
    """
    alerts = detector.get_alerts()
    return templates.TemplateResponse("index.html", {"request": request, "alerts": alerts})

@app.get("/health")
async def health_check():
    return {"status": "ok"}

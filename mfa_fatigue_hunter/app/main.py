import os
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from app.models import AuthEvent, Alert
from app.detector import MFAFatigueDetector
from typing import List

app = FastAPI(title="MFA Fatigue Hunter")

# Setup templates
templates_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_dir)

# Initialize detector and state
detector = MFAFatigueDetector(time_window_seconds=300, fatigue_threshold=5)
alerts_db: List[Alert] = []

@app.post("/api/events", status_code=202)
async def ingest_event(event: AuthEvent):
    """
    Ingest an authentication event from the IdP (Identity Provider) webhooks.
    """
    alert = detector.process_event(event)
    if alert:
        alerts_db.insert(0, alert)  # Add to front so newest is first
        # Keep only the last 100 alerts in memory for the dashboard
        if len(alerts_db) > 100:
            alerts_db.pop()

    return {"status": "processed"}

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """
    SOC Dashboard to visualize MFA fatigue alerts.
    """
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "alerts": alerts_db}
    )

@app.get("/health")
async def health_check():
    return {"status": "ok"}

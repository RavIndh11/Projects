from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import os

from app.schemas import MFAEvent, Alert
from app.detector import MFADetector

app = FastAPI(title="MFA Fatigue Hunter", description="Real-time detection of MFA push spam and fatigue attacks.")

# Initialize the detector
detector = MFADetector()

# Setup templates
templates_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_dir)


@app.post("/api/v1/events", status_code=status.HTTP_202_ACCEPTED)
async def ingest_event(event: MFAEvent):
    """
    Ingest a new MFA event.
    """
    try:
        alert = detector.process_event(event)
        if alert:
            return {"status": "event_processed", "alert_generated": True, "alert_severity": alert.severity}
        return {"status": "event_processed", "alert_generated": False}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/alerts", response_model=list[Alert])
async def get_alerts(limit: int = 50):
    """
    Get recent alerts in JSON format.
    """
    return detector.get_recent_alerts(limit=limit)


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """
    Web UI Dashboard for SOC Analysts.
    """
    alerts = detector.get_recent_alerts()
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"alerts": alerts}
    )

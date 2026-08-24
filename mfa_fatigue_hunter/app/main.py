from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import logging
from pythonjsonlogger.json import JsonFormatter
import os

from .models import AuthEvent
from .detector import MFAFatigueDetector

# Setup JSON logging for SIEM ingestion
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logHandler = logging.StreamHandler()
formatter = JsonFormatter('%(asctime)s %(levelname)s %(message)s')
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)

app = FastAPI(title="MFA Fatigue Hunter API", description="Real-time detection of MFA Fatigue (MFA Bombing) attacks")

# Setup templates
# We create a templates directory in the app structure
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# Initialize Detector (In-memory for this project)
detector = MFAFatigueDetector()

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    alerts = detector.get_all_alerts()
    return templates.TemplateResponse(request=request, name="index.html", context={"alerts": alerts})

@app.post("/api/v1/events/ingest", status_code=201)
async def ingest_event(event: AuthEvent):
    try:
        logger.info("Ingesting event", extra={"event_data": event.model_dump()})
        alert = detector.ingest_event(event)

        if alert:
            logger.warning("MFA Fatigue Alert Triggered!", extra={"alert_data": alert.model_dump()})
            return {"status": "success", "message": "Event processed. Alert triggered.", "alert": alert}

        return {"status": "success", "message": "Event processed normally."}

    except Exception as e:
        logger.error("Failed to process event", extra={"error": str(e)})
        raise HTTPException(status_code=500, detail="Internal Server Error")

@app.get("/api/v1/alerts")
async def get_alerts():
    return {"alerts": detector.get_all_alerts()}

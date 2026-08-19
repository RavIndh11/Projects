from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
import logging
from pythonjsonlogger import jsonlogger
from .models import MFALog, Alert
from .analyzer import MFAAnalyzer
import os

# Configure structured JSON logging
logger = logging.getLogger("mfa_fatigue_hunter")
logger.setLevel(logging.INFO)
logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(message)s')
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)

app = FastAPI(title="MFA Fatigue Hunter", description="Real-time SOC tool to detect MFA Fatigue attacks.")

# In-memory alert store for dashboard
recent_alerts = []
analyzer = MFAAnalyzer(
    time_window_seconds=int(os.getenv("TIME_WINDOW_SECONDS", "300")),
    spam_threshold=int(os.getenv("SPAM_THRESHOLD", "5"))
)

templates = Jinja2Templates(directory="templates")

@app.post("/api/v1/mfa_logs", status_code=status.HTTP_201_CREATED)
async def ingest_mfa_log(log: MFALog):
    """
    Ingest a new MFA log event.
    """
    logger.info("Received MFA log", extra={"user_email": log.user_email, "ip": log.ip_address, "status": log.status})

    alert = analyzer.analyze(log)

    if alert:
        logger.warning("MFA Alert triggered", extra={"alert": alert.model_dump()})
        recent_alerts.insert(0, alert)
        # Keep only the latest 50 alerts in memory
        if len(recent_alerts) > 50:
            recent_alerts.pop()

    return {"status": "success", "alert_triggered": alert is not None}

@app.get("/api/v1/alerts")
def get_alerts():
    """
    Returns the latest alerts.
    """
    return {"alerts": recent_alerts}

@app.get("/health")
def health_check():
    """
    Health check endpoint for Docker container.
    """
    return {"status": "healthy"}

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """
    SOC Dashboard.
    """
    return templates.TemplateResponse("index.html", {"request": request, "alerts": recent_alerts})

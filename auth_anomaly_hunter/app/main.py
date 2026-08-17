from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import uvicorn
import os
from typing import List

from app.models import AuthLog, AnomalyAlert
from app.db import db
from app.analyzer import analyze_login
from app.utils import setup_logging

logger = setup_logging()

app = FastAPI(
    title="Auth Anomaly Hunter",
    description="Real-time impossible travel and authentication anomaly detection engine.",
    version="1.0.0"
)

# Template configuration for Dashboard
templates_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_dir)

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.post("/api/v1/logs", response_model=dict, status_code=200)
async def ingest_log(log: AuthLog):
    """
    Ingest a new authentication log. Analyzes against the previous log for the user.
    """
    logger.info("Ingesting log", extra={"user_id": log.user_id, "ip": str(log.ip_address)})

    # Only process successful logins for impossible travel
    if log.status.lower() == "success":
        previous_log = db.get_last_login(log.user_id)

        # Analyze
        alert = await analyze_login(log, previous_log)

        # Update last login state
        db.set_last_login(log.user_id, log)

        if alert:
            db.add_alert(alert)
            logger.warning("Anomaly generated", extra={"alert": alert.model_dump()})
            return {"status": "processed", "alert_generated": True, "alert_id": alert.alert_id}

    return {"status": "processed", "alert_generated": False}

@app.get("/api/v1/alerts", response_model=List[AnomalyAlert])
def get_alerts(limit: int = 50):
    """
    Retrieve recent anomaly alerts.
    """
    return db.get_alerts(limit)

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """
    SOC Dashboard showing recent anomalies.
    """
    alerts = db.get_alerts(limit=20)
    return templates.TemplateResponse("index.html", {"request": request, "alerts": alerts})

if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host=host, port=port)

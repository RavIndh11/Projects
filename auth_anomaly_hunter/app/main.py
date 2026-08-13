import os
import json
import uuid
import logging
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pythonjsonlogger import jsonlogger

from app.models import AuthEvent
from app.engine import AnomalyEngine

# Configure JSON Logging
logger = logging.getLogger("auth_anomaly_hunter")
logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

# Initialize FastAPI App
app = FastAPI(title="Auth Anomaly Hunter", description="Real-time authentication anomaly detection")

# Setup templates
templates = Jinja2Templates(directory="app/templates")

# Initialize Engine
impossible_speed = float(os.getenv("IMPOSSIBLE_TRAVEL_SPEED_KMH", 900))
brute_window = float(os.getenv("BRUTE_FORCE_TIME_WINDOW_SEC", 300))
brute_max = int(os.getenv("BRUTE_FORCE_MAX_FAILURES", 5))

engine = AnomalyEngine(
    impossible_travel_speed_kmh=impossible_speed,
    brute_force_time_window_sec=brute_window,
    brute_force_max_failures=brute_max
)

@app.post("/api/v1/events")
async def ingest_event(event: AuthEvent):
    """
    Ingest a new authentication event and process it for anomalies.
    """
    try:
        anomalies = engine.process_event(event)

        for anomaly in anomalies:
            anomaly.event_id = str(uuid.uuid4())
            # Log as JSON for SIEM
            logger.warning("Anomaly detected", extra={
                "anomaly_result": anomaly.model_dump(mode='json')
            })

        return {"status": "processed", "anomalies_detected": len(anomalies)}
    except Exception as e:
        logger.error(f"Error processing event: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """
    Render a simple dashboard showing recent anomalies.
    """
    recent_anomalies = engine.get_recent_anomalies(limit=50)
    return templates.TemplateResponse("dashboard.html", {"request": request, "anomalies": recent_anomalies})

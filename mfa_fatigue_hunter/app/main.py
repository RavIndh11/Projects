import logging
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from app.models import AuthEvent, DetectionResult
from app.analyzer import MFAFatigueAnalyzer
from typing import List
from pythonjsonlogger import jsonlogger
import os

# Configure structured JSON logging
logger = logging.getLogger("mfa_fatigue_hunter")
logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(message)s %(module)s %(funcName)s')
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)
logger.setLevel(logging.INFO)

app = FastAPI(title="MFA Fatigue Hunter", description="Real-time detection engine for MFA Fatigue attacks")

# Templates
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

# Global analyzer instance
analyzer = MFAFatigueAnalyzer()

# Store recent detections for the dashboard
recent_detections: List[DetectionResult] = []

@app.post("/api/events", response_model=DetectionResult, status_code=status.HTTP_200_OK)
async def ingest_event(event: AuthEvent):
    """
    Ingest a new authentication event.
    Returns a DetectionResult if an anomaly is detected, otherwise returns a 202 Accepted status implicitly.
    """
    try:
        logger.info(f"Ingesting event for user {event.user_id} with status {event.status}")
        result = analyzer.analyze_event(event)

        if result:
            logger.warning("MFA Fatigue anomaly detected", extra={"detection_result": result.model_dump()})
            # Keep the most recent 50 detections
            recent_detections.insert(0, result)
            if len(recent_detections) > 50:
                recent_detections.pop()
            return result

        # Return 202 if no detection triggered immediately
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=status.HTTP_202_ACCEPTED, content={"status": "Event logged successfully, no anomaly detected"})

    except Exception as e:
        logger.error(f"Error processing event: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """
    Render the web dashboard with recent detections.
    """
    # Use kwargs for newer starlette, fallback to positional if needed. Based on memory instructions for newer starlette (>=0.28.0), we should use keyword arguments.
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"detections": recent_detections}
    )

@app.get("/api/health")
async def health_check():
    return {"status": "ok"}

from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from pydantic import ValidationError
from typing import List, Dict, Any

from app.models import AuditEvent, AuditEventList
from app.analyzer import Analyzer
from app.logger import logger

app = FastAPI(
    title="Kube Audit Sentinel",
    description="Kubernetes Audit Log Analysis and Anomaly Detection",
    version="1.0.0"
)

# Set up templates
BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Initialize Analyzer
analyzer = Analyzer()

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Serve the Web Dashboard UI."""
    return templates.TemplateResponse(request, "index.html", context={"request": request})

@app.post("/api/v1/analyze", status_code=status.HTTP_202_ACCEPTED)
async def analyze_audit_log(payload: Dict[str, Any]):
    """
    Receive and analyze a Kubernetes Audit Log payload.
    It can be a single Event or an EventList.
    """
    try:
        # Determine if it's an EventList or a single Event
        kind = payload.get("kind")
        events_to_process = []

        if kind == "EventList":
            event_list = AuditEventList(**payload)
            events_to_process = event_list.items
        elif kind == "Event":
            event = AuditEvent(**payload)
            events_to_process = [event]
        else:
            raise HTTPException(status_code=400, detail="Invalid payload kind. Expected Event or EventList.")

        alerts_generated = 0
        for event in events_to_process:
            logger.info("Processing event", extra={"extra_info": {"auditID": event.auditID, "verb": event.verb, "user": event.user.username}})
            alerts = analyzer.analyze_event(event)
            if alerts:
                alerts_generated += len(alerts)

        return {"status": "success", "processed_events": len(events_to_process), "alerts_generated": alerts_generated}

    except ValidationError as e:
        logger.error(f"Validation error: {e}")
        raise HTTPException(status_code=400, detail=e.errors())
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/v1/alerts")
async def get_alerts():
    """Retrieve generated alerts."""
    return {"alerts": analyzer.get_alerts()}

@app.get("/health")
async def health_check():
    """Healthcheck endpoint."""
    return {"status": "healthy"}

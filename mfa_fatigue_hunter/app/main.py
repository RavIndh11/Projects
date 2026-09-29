from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from collections import deque
from .models import MFALogEvent, AlertEvent
from .analyzer import MFAAnalyzer
import uvicorn
import datetime
from pathlib import Path

app = FastAPI(title="MFA Fatigue Hunter", description="Detects MFA Fatigue (Bombing) attacks.")

# Setup templates directory
templates_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))

# Initialize the Analyzer and an in-memory queue for recent alerts to show on the dashboard
analyzer = MFAAnalyzer()
recent_alerts = deque(maxlen=50)

@app.post("/api/v1/logs", status_code=202)
def ingest_log(log_event: MFALogEvent):
    """
    Ingest an MFA event log.
    If the event triggers a fatigue alert, it is stored and logged.
    """
    alert = analyzer.process_event(log_event)

    if alert:
        recent_alerts.appendleft(alert)
        return {"status": "alert_triggered", "alert": alert.model_dump()}

    return {"status": "processed"}

@app.get("/api/v1/alerts")
def get_alerts():
    """Returns the most recent alerts in JSON format."""
    return {"alerts": [alert.model_dump() for alert in recent_alerts]}

@app.get("/health")
def health_check():
    """Health check endpoint for Docker."""
    return {"status": "healthy"}

@app.get("/", response_class=HTMLResponse)
def get_dashboard(request: Request):
    """
    SOC Dashboard view showing recent MFA fatigue alerts.
    """
    return templates.TemplateResponse(request=request, name="index.html", context={"alerts": list(recent_alerts)})

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)

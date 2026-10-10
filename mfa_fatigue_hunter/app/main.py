from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import APIKeyHeader
import os

from app.models import AuthEvent
from app.engine import DetectionEngine
from app.logger import logger

app = FastAPI(title="MFA Fatigue Hunter")

# Setup templates
templates = Jinja2Templates(directory="app/templates")

# Initialize Engine
engine = DetectionEngine()

# Optional API Key Authentication for ingestion
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

def get_api_key(api_key_header: str = Depends(api_key_header)):
    expected_api_key = os.environ.get("API_KEY")
    if expected_api_key:
        if api_key_header != expected_api_key:
            raise HTTPException(status_code=403, detail="Could not validate credentials")
    return api_key_header

@app.post("/api/v1/ingest", status_code=202)
async def ingest_event(event: AuthEvent, api_key: str = Depends(get_api_key)):
    """
    Ingest a new authentication event for analysis.
    """
    logger.info("Received event", extra={"event_data": event.model_dump()})

    # Process event through the engine
    alert = engine.process_event(event)

    if alert:
        return {"status": "accepted", "alert_generated": True, "alert_id": alert.alert_id}

    return {"status": "accepted", "alert_generated": False}

@app.get("/api/v1/alerts")
async def get_alerts():
    """
    Retrieve recent alerts (API format).
    """
    return engine.get_recent_alerts()

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """
    Render the SOC Dashboard.
    """
    alerts = engine.get_recent_alerts(limit=50)
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"alerts": alerts}
    )

if __name__ == "__main__":
    import uvicorn
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("app.main:app", host=host, port=port, reload=True)

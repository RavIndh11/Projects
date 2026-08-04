from fastapi import FastAPI, Request, HTTPException, Security, Depends
from fastapi.security.api_key import APIKeyHeader
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import os
import logging
from pythonjsonlogger import jsonlogger
from typing import List

from .models import ConnectionBatch, AnalysisResult, BeaconAlert
from .analyzer import BeaconAnalyzer

# Setup structured logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(message)s')
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)

app = FastAPI(title="C2 Beacon Hunter", description="Analyzes network logs to detect potential Command & Control beaconing.", version="1.0.0")

# Setup templates
# We assume main.py is in app/ and templates is in app/templates/
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

API_KEY = os.environ.get("API_KEY")
if not API_KEY and os.environ.get("PYTEST_CURRENT_TEST") is None:
    raise ValueError("API_KEY environment variable is not set. Ensure secure deployment.")
# fallback just for tests
API_KEY = API_KEY or "default-dev-key"

API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

analyzer = BeaconAnalyzer()

# In-memory storage for dashboard viewing
latest_alerts: List[BeaconAlert] = []

async def get_api_key(api_key_header: str = Security(api_key_header)):
    if api_key_header == API_KEY:
        return api_key_header
    raise HTTPException(status_code=403, detail="Could not validate credentials")

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Serve the SOC analyst dashboard"""
    return templates.TemplateResponse(request=request, name="index.html", context={"alerts": latest_alerts})

@app.post("/api/v1/analyze", response_model=AnalysisResult)
async def analyze_logs(batch: ConnectionBatch, api_key: str = Depends(get_api_key)):
    """Ingest a batch of network logs and analyze them for C2 beaconing"""
    global latest_alerts
    try:
        alerts = analyzer.analyze(batch.logs)

        if alerts:
            logger.warning(f"Detected {len(alerts)} potential C2 beacons")
            # Keep only latest 100 alerts in memory for dashboard
            latest_alerts = (alerts + latest_alerts)[:100]
        else:
            logger.info(f"Analyzed {len(batch.logs)} logs, no beacons detected.")

        return AnalysisResult(
            status="success",
            processed_logs=len(batch.logs),
            alerts_found=len(alerts),
            alerts=alerts
        )
    except Exception as e:
        logger.error(f"Error analyzing logs: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error during analysis")

@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint for Docker container"""
    return {"status": "healthy"}

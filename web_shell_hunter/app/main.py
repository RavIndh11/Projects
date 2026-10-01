import logging
import sys
import os
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pythonjsonlogger import jsonlogger
from typing import List

from app.models import ScanRequest, ScanResponse, Finding
from app.engine import scan_file_content

# Configure structured JSON logging
logger = logging.getLogger("web_shell_hunter")
logger.setLevel(logging.INFO)
logHandler = logging.StreamHandler(sys.stdout)
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)

app = FastAPI(
    title="Web Shell Hunter API",
    description="API for scanning files for web shells and obfuscation.",
    version="1.0.0"
)

# In-memory store for recent scans (for the UI)
recent_scans: List[ScanResponse] = []

# Get the absolute path to the templates directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

# Setup templates
templates = Jinja2Templates(directory=TEMPLATES_DIR)

@app.post("/api/v1/scan", response_model=ScanResponse)
async def scan_file(request: ScanRequest):
    logger.info("Scan request received", extra={"file_path": request.file_path})

    content = request.file_content

    if content is None:
        # In a real scenario, this would fetch from a file system, S3, etc.
        # For our API, if content isn't provided, we can't scan it.
        logger.warning("No file content provided for scan", extra={"file_path": request.file_path})
        raise HTTPException(status_code=400, detail="file_content must be provided for scanning via API.")

    try:
        findings = scan_file_content(content, request.file_path)

        status = "Clean"
        if any(f.severity in ["High", "Critical"] for f in findings):
            status = "Malicious"
        elif any(f.severity in ["Low", "Med"] for f in findings):
            status = "Suspicious"

        response = ScanResponse(
            file_path=request.file_path,
            status=status,
            findings=findings
        )

        # Keep the last 50 scans for the UI
        recent_scans.insert(0, response)
        if len(recent_scans) > 50:
            recent_scans.pop()

        logger.info("Scan complete", extra={
            "file_path": request.file_path,
            "status": status,
            "findings_count": len(findings)
        })

        return response

    except Exception as e:
        logger.error(f"Error during scan: {str(e)}", extra={"file_path": request.file_path})
        raise HTTPException(status_code=500, detail="Internal server error during scan.")

@app.get("/api/v1/recent", response_model=List[ScanResponse])
async def get_recent_scans():
    """Get recent scan results for the dashboard."""
    return recent_scans

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Render the dashboard UI."""
    return templates.TemplateResponse(request=request, name="index.html", context={"scans": recent_scans})

@app.get("/health")
async def health_check():
    """Health check endpoint for Docker."""
    return {"status": "ok"}

from fastapi import FastAPI, UploadFile, File, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import os

from app.models import ScanResponse
from app.analyzer import analyze_file
from app.logger import get_logger

logger = get_logger(__name__)

app = FastAPI(title="Secure Upload Gateway", description="Analyzes file uploads for security threats.")

# Ensure templates directory exists and setup Jinja2
templates_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_dir)

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Serves the main dashboard."""
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/analyze", response_model=ScanResponse)
async def analyze_upload(file: UploadFile = File(...)):
    """Accepts a file upload and returns analysis results."""
    try:
        content = await file.read()
        filename = file.filename or "unknown"

        logger.info(f"Received file upload for analysis: {filename}", extra={"scan_filename": filename})

        # Analyze file from memory
        result = analyze_file(filename, content)

        return result
    except Exception as e:
        logger.error(f"Failed to process upload: {e}")
        raise HTTPException(status_code=500, detail="Internal server error during analysis")

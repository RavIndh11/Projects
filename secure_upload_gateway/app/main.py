from fastapi import FastAPI, UploadFile, File, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import logging
from pythonjsonlogger import jsonlogger
from .analyzer import analyzer
import os
import uvicorn

# Set up JSON Logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)

app = FastAPI(
    title="Secure Upload Gateway",
    description="Real-time security analyzer for file uploads.",
    version="1.0.0"
)

# Get current directory for template resolution
current_dir = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(current_dir, "templates"))

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """Serve the Web Dashboard."""
    return templates.TemplateResponse(request=request, name="index.html", context={})

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok"}

@app.post("/api/v1/analyze")
async def analyze_file(file: UploadFile = File(...)):
    """
    Analyze an uploaded file for vulnerabilities.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    try:
        content = await file.read()
        logger.info(f"Received file for analysis: {file.filename}")

        result = analyzer.analyze(file.filename, content)

        # Log the analysis result in JSON format for SIEM
        log_data = {
            "scan_filename": file.filename,
            "is_safe": result.is_safe,
            "risk_score": result.risk_score,
            "threats_found": result.threats_found,
            "file_type": result.file_type
        }

        if result.is_safe:
            logger.info("File analysis passed", extra=log_data)
        else:
            logger.warning("File analysis failed security checks", extra=log_data)

        return result

    except Exception as e:
        logger.error("Error analyzing file", extra={"scan_filename": file.filename, "error": str(e)})
        raise HTTPException(status_code=500, detail="Internal server error during analysis")

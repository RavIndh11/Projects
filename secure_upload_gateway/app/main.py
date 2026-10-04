from fastapi import FastAPI, UploadFile, File, Request, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
import logging
from pythonjsonlogger import jsonlogger
import os
import re

from app.analyzer import SecureUploadAnalyzer

# Structured JSON Logging
logger = logging.getLogger("secure_upload_gateway")
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))
logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
logHandler.setFormatter(formatter)
if not logger.handlers:
    logger.addHandler(logHandler)

app = FastAPI(title="Secure Upload Gateway", description="Defensive security microservice for analyzing file uploads.")
templates = Jinja2Templates(directory="app/templates")
analyzer = SecureUploadAnalyzer()

# Input Validation Schema for report
class AnalysisReport(BaseModel):
    filename: str
    status: str
    threats: list
    severity: str

def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal or injection in logs/storage."""
    # Keep only alphanumeric chars, dots, dashes, and underscores
    sanitized = re.sub(r'[^a-zA-Z0-9.\-_]', '', filename)
    # Prevent empty filename or pure dots
    if not sanitized or sanitized.replace('.', '') == '':
        return "unnamed_file"
    return sanitized

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html", context={})

@app.post("/api/analyze", response_model=AnalysisReport)
async def analyze_upload(file: UploadFile = File(...)):
    if not file.filename:
         raise HTTPException(status_code=400, detail="No file provided")

    sanitized_filename = sanitize_filename(file.filename)

    # Read file content
    try:
        content = await file.read()
    except Exception as e:
        logger.error(f"Error reading file: {e}")
        raise HTTPException(status_code=500, detail="Internal server error while reading file")

    # Enforce MAX_UPLOAD_SIZE if set (in bytes)
    max_size = int(os.getenv("MAX_UPLOAD_SIZE", 5242880)) # Default 5MB
    if len(content) > max_size:
         logger.warning("File upload exceeded size limit", extra={"scan_filename": sanitized_filename, "size": len(content)})
         raise HTTPException(status_code=413, detail="File too large")

    # Analyze the file
    report = analyzer.analyze_file(sanitized_filename, content)

    # Structured logging based on result
    if report["status"] == "malicious":
        logger.warning("Malicious file upload detected", extra={"scan_filename": sanitized_filename, "threats": report["threats"], "severity": report["severity"]})
    else:
        logger.info("Clean file uploaded", extra={"scan_filename": sanitized_filename})

    return JSONResponse(status_code=status.HTTP_200_OK, content=report)

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

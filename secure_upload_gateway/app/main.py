from fastapi import FastAPI, File, UploadFile, Request, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
import os
import uuid
from typing import List

from .analyzer import analyze_file
from .logger import logger

app = FastAPI(
    title="Secure Upload Gateway",
    description="Analyzes file uploads for vulnerabilities like Zip Slip, Extension Spoofing, and Polyglots",
    version="1.0.0"
)

# Use absolute path to templates directory for reliability
templates_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")
templates = Jinja2Templates(directory=templates_dir)

MAX_UPLOAD_SIZE = int(os.getenv("MAX_UPLOAD_SIZE", 5242880)) # 5MB Default

class UploadResult(BaseModel):
    id: str = Field(..., description="Unique ID for the scan")
    filename: str
    is_safe: bool
    threats: List[str]
    mime_type: str
    size: int

# In-memory store for recent scans to display on dashboard
recent_scans: List[UploadResult] = []

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """
    SOC Dashboard showing recent uploads and their security status.
    """
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "scans": recent_scans[:50]} # show top 50 recent
    )

@app.post("/upload", response_model=UploadResult)
async def upload_file(file: UploadFile = File(...)):
    """
    Endpoint to receive and analyze a file.
    """
    # 1. Size Validation (check size before reading into memory)
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename not provided")

    if file.size and file.size > MAX_UPLOAD_SIZE:
        logger.warning("Upload rejected: File too large", extra={"scan_filename": file.filename, "size": file.size})
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large. Maximum size is {MAX_UPLOAD_SIZE} bytes."
        )

    content = await file.read()
    if len(content) > MAX_UPLOAD_SIZE:
         logger.warning("Upload rejected: File too large", extra={"scan_filename": file.filename, "size": len(content)})
         raise HTTPException(
             status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
             detail=f"File too large. Maximum size is {MAX_UPLOAD_SIZE} bytes."
         )

    scan_id = str(uuid.uuid4())

    # 2. Analyze the file
    analysis = analyze_file(file.filename, content)

    result = UploadResult(
        id=scan_id,
        filename=file.filename,
        is_safe=analysis["is_safe"],
        threats=analysis["threats"],
        mime_type=analysis["mime_type"],
        size=analysis["size"]
    )

    # 3. Log results for SIEM
    log_data = result.model_dump()
    # rename filename in log to avoid conflicts with standard log attributes
    log_data["scan_filename"] = log_data.pop("filename")

    if result.is_safe:
        logger.info("File upload safe", extra=log_data)
    else:
        logger.error("File upload malicious", extra=log_data)

    # 4. Store in memory for dashboard (insert at top)
    recent_scans.insert(0, result)

    # Keep only the last 100 for memory constraint
    if len(recent_scans) > 100:
        recent_scans.pop()

    return result

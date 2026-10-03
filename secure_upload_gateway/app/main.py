from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from app.validators import analyze_file
from app.schemas import ScanResponse, ScanResult
from app.logger import logger
import os

app = FastAPI(
    title="Secure Upload Gateway",
    description="Microservice to analyze file uploads for polyglots, Zip Slip, and extension spoofing.",
    version="1.0.0"
)

# Setup templates
templates_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
templates = Jinja2Templates(directory=templates_dir)

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """Serves the Web Dashboard."""
    # Note: Depending on Starlette version, kwargs might be required.
    # Using the positional arguments with context dict for compatibility with older versions.
    # We will test this during verification.
    try:
        return templates.TemplateResponse("index.html", {"request": request})
    except TypeError:
         return templates.TemplateResponse(request=request, name="index.html", context={})

@app.post("/api/v1/scan", response_model=ScanResponse)
async def scan_file(file: UploadFile = File(...)):
    """Scans an uploaded file for vulnerabilities."""
    try:
        content = await file.read()
        filename = file.filename or "unknown"

        logger.info("Starting file scan", extra={"scan_filename": filename, "file_size": len(content)})

        analysis = analyze_file(filename, content)

        result = ScanResult(
            filename=filename,
            is_safe=analysis["is_safe"],
            severity=analysis["severity"],
            matched_rules=analysis["matched_rules"],
            details=analysis["details"]
        )

        logger.info("File scan completed", extra={
            "scan_filename": filename,
            "is_safe": result.is_safe,
            "severity": result.severity,
            "matched_rules": result.matched_rules
        })

        return ScanResponse(status="success", result=result)

    except Exception as e:
        logger.error("Error scanning file", extra={"error": str(e)})
        raise HTTPException(status_code=500, detail="Internal server error during file analysis")

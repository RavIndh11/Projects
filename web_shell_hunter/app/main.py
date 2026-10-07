import logging
import sys
from fastapi import FastAPI, UploadFile, File, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pythonjsonlogger import jsonlogger

from app.schemas import TextAnalysisRequest, ScanResult
from app.detector import analyze_content

# --- Logging Setup ---
logger = logging.getLogger("web_shell_hunter")
logger.setLevel(logging.INFO)
logHandler = logging.StreamHandler(sys.stdout)
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)
# Avoid double logging if uvicorn also logs
logger.propagate = False


# --- FastAPI App ---
app = FastAPI(title="Web Shell Hunter API", version="1.0.0")

templates = Jinja2Templates(directory="app/templates")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html", context={})


@app.post("/api/scan/text", response_model=ScanResult)
async def scan_text(request: TextAnalysisRequest):
    try:
        result = analyze_content(request.content, request.filename)

        # Log the result
        logger.info(
            "Text scan completed",
            extra={
                "scan_filename": request.filename,
                "is_malicious": result["is_malicious"],
                "risk_score": result["risk_score"],
                "threat_level": result["threat_level"],
                "entropy": result["entropy"]
            }
        )

        return result
    except Exception as e:
        logger.error(f"Error scanning text: {str(e)}", extra={"scan_filename": request.filename})
        raise HTTPException(status_code=500, detail="Internal server error during analysis")


@app.post("/api/scan/file", response_model=ScanResult)
async def scan_file(file: UploadFile = File(...)):
    try:
        content_bytes = await file.read()

        # Attempt to decode, fallback to basic text representation if it's binary
        try:
            content = content_bytes.decode('utf-8')
        except UnicodeDecodeError:
            # If it's heavily obfuscated or binary, decode with replace
            content = content_bytes.decode('utf-8', errors='replace')

        result = analyze_content(content, file.filename or "uploaded_file")

        # Log the result
        logger.info(
            "File scan completed",
            extra={
                "scan_filename": file.filename,
                "is_malicious": result["is_malicious"],
                "risk_score": result["risk_score"],
                "threat_level": result["threat_level"],
                "entropy": result["entropy"]
            }
        )

        return result
    except Exception as e:
        logger.error(f"Error scanning file: {str(e)}", extra={"scan_filename": file.filename})
        raise HTTPException(status_code=500, detail="Internal server error during analysis")

@app.get("/health")
async def health_check():
    return {"status": "ok"}

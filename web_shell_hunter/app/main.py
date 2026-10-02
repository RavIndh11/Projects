import logging
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pythonjsonlogger import jsonlogger

from app.schemas import ScanRequest, ScanResponse
from app.analyzer import analyze_content

# Configure JSON logging
logger = logging.getLogger("web_shell_hunter")
logger.setLevel(logging.INFO)
logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)

app = FastAPI(title="Web Shell Hunter", version="1.0.0")

templates = Jinja2Templates(directory="app/templates")

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/scan", response_model=ScanResponse)
async def scan_payload(request: ScanRequest):
    content = request.content
    is_malicious, entropy, matched_signatures, severity = analyze_content(content)

    response_data = ScanResponse(
        is_malicious=is_malicious,
        entropy=entropy,
        matched_signatures=matched_signatures,
        severity=severity
    )

    logger.info("Scan completed", extra={
        "is_malicious": is_malicious,
        "entropy": entropy,
        "matched_signatures": matched_signatures,
        "severity": severity,
        "content_length": len(content)
    })

    return response_data

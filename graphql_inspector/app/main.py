import logging
from pythonjsonlogger import jsonlogger
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from .models import ScanRequest, ScanResult
from .scanner import run_scan

# Configure structured JSON logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(message)s')
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)

app = FastAPI(title="GraphQL Inspector", description="Automated GraphQL Introspection & Security Scanner")

templates = Jinja2Templates(directory="app/templates")

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse(request=request, name="index.html", context={})

@app.post("/scan", response_model=ScanResult)
async def scan_endpoint(request: ScanRequest):
    logger.info(f"Initiating scan for URL: {request.url}")
    result = await run_scan(str(request.url))
    logger.info(f"Scan completed for URL: {request.url} - Status: {result.status}")
    return result

@app.post("/scan_ui", response_class=HTMLResponse)
async def scan_ui_endpoint(request: Request, url: str = Form(...)):
    try:
        # Validate URL using pydantic manually for the form
        scan_req = ScanRequest(url=url)
    except Exception as e:
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={"error": "Invalid URL provided."}
        )

    result = await run_scan(str(scan_req.url))
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"result": result.model_dump()}
    )

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

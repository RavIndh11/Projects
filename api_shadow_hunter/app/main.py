from fastapi import FastAPI, File, UploadFile, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import os

from app.analyzer import parse_openapi_spec, parse_logs, analyze_endpoints
from app.schemas import AnalysisReport
from app.logger import logger

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting API Shadow Hunter application")
    yield
    logger.info("Shutting down API Shadow Hunter application")

app = FastAPI(title="API Shadow Hunter", description="Detects undocumented (Shadow) and unused (Zombie) API endpoints.", version="1.0.0", lifespan=lifespan)

# Setup templates
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """
    Renders the main dashboard upload page.
    """
    # Fastapi templates need request object explicitly passed as kwargs or context dict
    return templates.TemplateResponse(request=request, name="index.html", context={"report": None})

@app.post("/analyze", response_class=HTMLResponse)
async def analyze(
    request: Request,
    openapi_file: UploadFile = File(...),
    log_file: UploadFile = File(...)
):
    """
    Ingests OpenAPI spec and logs, analyzes them, and renders the results.
    """
    try:
        logger.info(f"Received analysis request with spec: {openapi_file.filename} and logs: {log_file.filename}")
        openapi_content = (await openapi_file.read()).decode("utf-8")
        log_content = (await log_file.read()).decode("utf-8")

        documented_paths = parse_openapi_spec(openapi_content)
        logs = parse_logs(log_content)

        report = analyze_endpoints(documented_paths, logs)
        logger.info(f"Analysis completed successfully. Total logs: {report.total_logs}, Shadow: {report.shadow_count}, Zombie: {report.zombie_count}")

        return templates.TemplateResponse(request=request, name="index.html", context={"report": report})
    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}", exc_info=True)
        return templates.TemplateResponse(request=request, name="index.html", context={"error": str(e), "report": None})

@app.get("/api/health")
def health_check():
    """
    Health check endpoint for Docker and orchestration.
    """
    return {"status": "ok"}

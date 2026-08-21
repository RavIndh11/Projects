import logging
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pythonjsonlogger import jsonlogger
from app.models import AnalyzeRequest, AnalyzeResponse
from app.core import analyze_graphql_endpoint

# Configure JSON logging
logger = logging.getLogger()
logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)
logger.setLevel(logging.INFO)

app = FastAPI(title="GraphQL Inspector", description="Detect exposed GraphQL introspection and sensitive schema fields.")

# Setup templates
templates = Jinja2Templates(directory="app/templates")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Serves the main UI."""
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/health")
async def health_check():
    """Healthcheck endpoint for Docker."""
    return {"status": "ok"}

@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze_endpoint(request: AnalyzeRequest):
    """Analyzes a GraphQL endpoint for exposed introspection and sensitive fields."""
    logger.info(f"Analyzing GraphQL endpoint: {request.url}")
    return await analyze_graphql_endpoint(request)

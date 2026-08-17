from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from contextlib import asynccontextmanager
import os

from app.analyzer import analyze_graphql_endpoint
from app.schemas import AnalyzeRequest, AnalysisReport
from app.logger import logger

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting GraphQL Inspector application")
    yield
    logger.info("Shutting down GraphQL Inspector application")

app = FastAPI(
    title="GraphQL Inspector",
    description="Detects exposed GraphQL introspection and sensitive schema fields.",
    version="1.0.0",
    lifespan=lifespan
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "report": None})

@app.post("/", response_class=HTMLResponse)
async def analyze_form(request: Request, url: str = Form(...)):
    report = await analyze_graphql_endpoint(url)
    return templates.TemplateResponse("index.html", {"request": request, "report": report})

@app.post("/api/analyze", response_model=AnalysisReport)
async def analyze_api(request_data: AnalyzeRequest):
    url = str(request_data.url)
    report = await analyze_graphql_endpoint(url)
    return report

@app.get("/api/health")
def health_check():
    return {"status": "ok"}

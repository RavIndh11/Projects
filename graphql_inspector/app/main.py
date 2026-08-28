from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError
from pythonjsonlogger import jsonlogger as json
import logging
import sys

from app.schemas import AnalyzeRequest, AnalyzeResponse
from app.analyzer import analyze_query

# Setup structured logging
logger = logging.getLogger("graphql_inspector")
logger.setLevel(logging.INFO)
logHandler = logging.StreamHandler(sys.stdout)
formatter = json.JsonFormatter('%(asctime)s %(levelname)s %(message)s')
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)

app = FastAPI(title="GraphQL Inspector", description="A security tool to inspect and analyze GraphQL queries for DoS vectors and introspection risks.")

templates = Jinja2Templates(directory="app/templates")

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    logger.info("Accessing root UI.")
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze_graphql(request: AnalyzeRequest):
    logger.info("Received query for analysis", extra={"query_length": len(request.query)})

    result = analyze_query(
        query=request.query,
        max_depth_limit=request.max_depth_limit,
        max_alias_limit=request.max_alias_limit,
        allow_introspection=request.allow_introspection
    )

    if result["status"] == "error":
        logger.warning("Query analysis failed", extra={"error": result.get("message")})
        return result

    logger.info("Query analyzed successfully", extra={"risk_score": result["risk_score"], "severity": result["severity"]})
    return result

@app.get("/health")
async def health_check():
    return {"status": "ok"}

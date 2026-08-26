from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from typing import List, Union
import logging
from pythonjsonlogger import json as jsonlogger
import os

from app.inspector import GraphQLInspector

# Setup structured JSON logging
logger = logging.getLogger("graphql_inspector")
logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)
logger.setLevel(logging.INFO)

app = FastAPI(
    title="GraphQL Inspector",
    description="Defensive Security tool for inspecting GraphQL queries for DoS vectors and info leaks.",
    version="1.0.0"
)

templates_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_dir)

inspector = GraphQLInspector(max_depth=5, max_aliases=10)

class GraphQLQuery(BaseModel):
    query: str = Field(..., description="The GraphQL query string to inspect")
    operationName: Union[str, None] = None
    variables: Union[dict, None] = None

class InspectionResult(BaseModel):
    is_safe: bool
    findings: List[str]
    metrics: dict

class BatchInspectionRequest(BaseModel):
    queries: List[GraphQLQuery]

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.post("/api/inspect", response_model=InspectionResult)
def inspect_query(request: GraphQLQuery):
    """Inspects a single GraphQL query for vulnerabilities."""
    logger.info("Inspecting query", extra={"operation": request.operationName})
    result = inspector.analyze_query(request.query)

    if not result["is_safe"]:
        logger.warning("Vulnerability detected in query", extra={"findings": result["findings"], "metrics": result["metrics"]})

    return result

@app.post("/api/inspect/batch", response_model=List[InspectionResult])
def inspect_batch(request: BatchInspectionRequest):
    """Inspects a batch of GraphQL queries."""
    results = []
    for q in request.queries:
        res = inspector.analyze_query(q.query)
        if not res["is_safe"]:
            logger.warning("Vulnerability detected in batch query", extra={"findings": res["findings"], "metrics": res["metrics"]})
        results.append(res)
    return results

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Renders the dashboard UI."""
    # We pass 'request=request' to avoid TypeErrors with newer Jinja2Templates
    return templates.TemplateResponse(request=request, name="index.html", context={"title": "GraphQL Inspector Dashboard"})

if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host=host, port=port)

import logging
import sys
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from pythonjsonlogger.jsonlogger import JsonFormatter
from app.models import InspectRequest, InspectResponse, SecurityFlag
from app.inspector import GraphQLInspector

# Setup structured JSON logging
logger = logging.getLogger("graphql_inspector")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
formatter = JsonFormatter('%(asctime)s %(levelname)s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

app = FastAPI(title="GraphQL Inspector", description="Security tool to inspect GraphQL queries for vulnerabilities")
templates = Jinja2Templates(directory="app/templates")
inspector = GraphQLInspector()

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    # Using positional arguments for Starlette < 0.28.0 (fastapi 0.103.1 uses starlette 0.27.0)
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.post("/api/v1/inspect", response_model=InspectResponse)
async def inspect_query(request: InspectRequest):
    logger.info(f"Inspecting query", extra={"query_length": len(request.query)})
    risk_score, flags, metrics = inspector.inspect(request.query)

    security_flags = [SecurityFlag(**flag) for flag in flags]

    response = InspectResponse(
        status="success",
        risk_score=risk_score,
        flags=security_flags,
        metrics=metrics
    )

    logger.info("Inspection complete", extra={
        "risk_score": risk_score,
        "flags_count": len(flags),
        "depth": metrics["depth"],
        "aliases": metrics["aliases"]
    })

    return response

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception", extra={"error": str(exc)})
    return JSONResponse(
        status_code=500,
        content={"message": "Internal Server Error"}
    )

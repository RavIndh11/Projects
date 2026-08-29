from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
import logging
from pythonjsonlogger import jsonlogger

from app.models import InspectRequest, InspectResponse
from app.inspector import GraphQLInspector

# Setup structured logging
logger = logging.getLogger("graphql_inspector")
logger.setLevel(logging.INFO)
log_handler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter(
    fmt="%(asctime)s %(levelname)s %(name)s %(message)s"
)
log_handler.setFormatter(formatter)
logger.addHandler(log_handler)

app = FastAPI(title="GraphQL Security Inspector", description="Detects malicious GraphQL queries.")
templates = Jinja2Templates(directory="app/templates")

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/inspect", response_model=InspectResponse)
def inspect_query(request: InspectRequest):
    logger.info("Received GraphQL inspection request", extra={
        "max_depth": request.max_depth,
        "max_aliases": request.max_aliases,
        "allow_introspection": request.allow_introspection
    })

    inspector = GraphQLInspector(
        max_depth=request.max_depth,
        max_aliases=request.max_aliases,
        allow_introspection=request.allow_introspection
    )

    result = inspector.inspect(request.query)

    if not result["is_valid"]:
        logger.warning("GraphQL query rejected", extra={"violations": result.get("violations", []), "error": result.get("error")})
    else:
        logger.info("GraphQL query passed inspection")

    return InspectResponse(**result)

@app.post("/ui/inspect", response_class=HTMLResponse)
def ui_inspect(
    request: Request,
    query: str = Form(...),
    max_depth: int = Form(5),
    max_aliases: int = Form(3),
    allow_introspection: bool = Form(False)
):
    try:
        req = InspectRequest(
            query=query,
            max_depth=max_depth,
            max_aliases=max_aliases,
            allow_introspection=allow_introspection
        )
    except ValidationError as e:
        return templates.TemplateResponse("index.html", {
            "request": request,
            "query": query,
            "error": "Invalid input parameters.",
            "max_depth": max_depth,
            "max_aliases": max_aliases,
            "allow_introspection": allow_introspection
        })

    inspector = GraphQLInspector(
        max_depth=req.max_depth,
        max_aliases=req.max_aliases,
        allow_introspection=req.allow_introspection
    )

    result = inspector.inspect(req.query)

    return templates.TemplateResponse("index.html", {
        "request": request,
        "query": query,
        "max_depth": max_depth,
        "max_aliases": max_aliases,
        "allow_introspection": allow_introspection,
        "result": result
    })

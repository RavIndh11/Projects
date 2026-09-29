import logging
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pythonjsonlogger import jsonlogger
from pathlib import Path

from app.schemas import TokenInput, AnalysisResult
from app.analyzer import JWTAnalyzer

# Setup structured logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)

app = FastAPI(
    title="JWT Security Analyzer",
    description="A Defensive Security tool for analyzing JWTs for common vulnerabilities.",
    version="1.0.0"
)

# Setup templates
BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

analyzer = JWTAnalyzer()

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """Render the main dashboard."""
    # Handle older Starlette correctly: positional args
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/analyze", response_model=AnalysisResult)
async def analyze_token(token_input: TokenInput):
    """Analyze a JWT token and return security findings."""
    logging.info(f"Analyzing token (length: {len(token_input.token)})")

    result = analyzer.analyze(token_input.token)

    if not result.is_valid_format:
        # We still return the object, frontend will handle the error
        logging.warning("Invalid token format submitted")

    return result

@app.get("/health")
async def health_check():
    """Health check endpoint for Docker container."""
    return {"status": "ok"}

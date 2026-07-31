from datetime import datetime
import datetime as dt_module
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any

from .analyzer import PromptAnalyzer
from .models import AnalyzeRequest, AnalyzeResponse
from .logger import setup_logger
import logging

app = FastAPI(
    title="LLM Prompt Guard",
    description="An AI/LLM security proxy to detect and block prompt injections and jailbreaks.",
    version="1.0.0"
)

# Setup CORS (restrict in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

logger = setup_logger()
analyzer = PromptAnalyzer()

# Assuming templates are placed in the correct directory relative to execution
templates = Jinja2Templates(directory="templates")

# Store recent analyses for the dashboard
recent_logs = []
MAX_LOGS = 50

@app.post("/api/v1/analyze", response_model=AnalyzeResponse)
async def analyze_prompt(request: AnalyzeRequest):
    try:
        result = analyzer.analyze(request.prompt)

        # Log the event
        log_info = {
            "prompt_snippet": request.prompt[:50] + "..." if len(request.prompt) > 50 else request.prompt,
            "is_safe": result["is_safe"],
            "severity": result["severity"],
            "match_count": len(result["matches"])
        }

        if result["is_safe"]:
            logger.info("Prompt analyzed - Safe", extra={"extra_info": log_info})
        else:
            logger.warning("Prompt analyzed - Threat Detected", extra={"extra_info": log_info})

        # Add to recent logs for dashboard
        log_entry = {
            "prompt": request.prompt,
            "result": result,
            "timestamp": datetime.now(dt_module.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        }
        recent_logs.insert(0, log_entry)
        if len(recent_logs) > MAX_LOGS:
            recent_logs.pop()

        return AnalyzeResponse(**result)

    except Exception as e:
        logger.error(f"Error analyzing prompt: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error during analysis")

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """
    Renders the lightweight SOC dashboard.
    """
    return templates.TemplateResponse("index.html", {"request": request, "logs": recent_logs})

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

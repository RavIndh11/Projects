from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import os

from .models import PromptRequest, AnalyzeResponse
from .security import PromptAnalyzer
from .logger import get_json_logger

app = FastAPI(
    title="LLM Prompt Guard API",
    description="API for detecting prompt injections and jailbreaks in LLM prompts.",
    version="1.0.0"
)

# Setup Templates
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

logger = get_json_logger()
analyzer = PromptAnalyzer()

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """Serve the Web Dashboard."""
    return templates.TemplateResponse(name="index.html", request=request)

@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze_prompt_api(request: PromptRequest):
    """Analyze a given prompt for malicious content."""
    try:
        result = analyzer.analyze_prompt(request.prompt)

        # Log the analysis for SIEM consumption
        log_data = {
            "event_type": "prompt_analysis",
            "prompt_length": len(request.prompt),
            "is_safe": result.is_safe,
            "threat_score": result.threat_score,
            "threat_level": result.threat_level,
            "matched_rules": result.matched_rules
        }

        if not result.is_safe:
            logger.warning("Malicious prompt detected", extra={"extra_info": log_data})
        else:
            logger.info("Safe prompt processed", extra={"extra_info": log_data})

        return result
    except Exception as e:
        logger.error(f"Error analyzing prompt: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error during analysis")

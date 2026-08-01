from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from app.models import AnalyzeRequest, AnalyzeResponse
from app.analyzer import PromptAnalyzer
from app.logger import setup_logger
import os

logger = setup_logger()
app = FastAPI(title="LLM Prompt Guard API", description="Security proxy for AI prompts", version="1.0.0")
analyzer = PromptAnalyzer()

# Make templates directory path robust
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

@app.post("/api/v1/analyze", response_model=AnalyzeResponse)
async def analyze_prompt(request: AnalyzeRequest):
    try:
        logger.info("Analyzing new prompt", extra={"extra_data": {"session_id": request.session_id}})
        response = analyzer.analyze(request)
        logger.info("Analysis complete", extra={"extra_data": {"is_safe": response.is_safe, "risk_score": response.risk_score}})
        return response
    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during analysis")

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "result": None})

@app.post("/", response_class=HTMLResponse)
async def web_analyze(request: Request, prompt: str = Form(...)):
    if not prompt or len(prompt.strip()) == 0:
        return templates.TemplateResponse("index.html", {"request": request, "result": None, "error": "Prompt cannot be empty"})

    try:
        analyze_req = AnalyzeRequest(prompt=prompt)
        response = analyzer.analyze(analyze_req)
        return templates.TemplateResponse("index.html", {"request": request, "result": response.model_dump(), "prompt": prompt})
    except Exception as e:
         logger.error(f"Error in web interface: {str(e)}", exc_info=True)
         return templates.TemplateResponse("index.html", {"request": request, "result": None, "error": "An error occurred while analyzing the prompt."})

@app.get("/health")
async def health_check():
    return {"status": "ok"}

from fastapi import FastAPI, UploadFile, File, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic_settings import BaseSettings
import os
import json
from pythonjsonlogger import jsonlogger
import logging

from app.analyzer import analyze_file

class Settings(BaseSettings):
    api_key: str = "default_test_key"
    max_upload_size: int = 10 * 1024 * 1024 # 10MB

    class Config:
        env_file = ".env"

settings = Settings()

# Configure JSON Logging
logger = logging.getLogger("secure_upload_gateway")
logger.setLevel(logging.INFO)
logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)

app = FastAPI(title="Secure Upload Gateway")

templates_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
templates = Jinja2Templates(directory=templates_dir)

# Store recent analyses for the dashboard
recent_analyses = []

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"analyses": recent_analyses}
    )

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    try:
        content = await file.read()

        if len(content) > settings.max_upload_size:
            raise HTTPException(status_code=413, detail="File too large")

        analysis_result = analyze_file(file.filename, content)

        # Log the result
        logger.info("File upload analyzed", extra={"analysis": analysis_result})

        # Add to dashboard data (keep last 50)
        recent_analyses.insert(0, analysis_result)
        if len(recent_analyses) > 50:
            recent_analyses.pop()

        return JSONResponse(content=analysis_result)

    except Exception as e:
        logger.error(f"Error processing file upload: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error during analysis")

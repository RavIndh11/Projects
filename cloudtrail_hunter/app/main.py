from fastapi import FastAPI, UploadFile, File, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import json
import logging
from pydantic import ValidationError
from .models import CloudTrailLogFile, CloudTrailEvent
from .analyzer import CloudTrailAnalyzer

app = FastAPI(title="CloudTrail Hunter", description="AWS CloudTrail Security Analyzer")
templates = Jinja2Templates(directory="app/templates")

analyzer = CloudTrailAnalyzer()

# Configure logging for JSON output suitable for SIEM
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "findings": None, "error": None})

@app.post("/analyze", response_class=HTMLResponse)
async def analyze_logs(request: Request, file: UploadFile = File(...)):
    if not file.filename.endswith('.json'):
        return templates.TemplateResponse("index.html", {"request": request, "findings": None, "error": "Invalid file type. Please upload a JSON file."})

    try:
        content = await file.read()
        json_data = json.loads(content.decode("utf-8"))

        # Validate JSON structure against Pydantic models
        log_file = CloudTrailLogFile(**json_data)

        # Analyze the parsed logs
        findings = analyzer.analyze(log_file.Records)

        # Log findings to stdout in JSON format for potential SIEM collection
        for finding in findings:
            logger.warning(finding.model_dump_json())

        # Sort findings by severity (Critical first)
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        findings.sort(key=lambda x: severity_order.get(x.severity, 4))

        return templates.TemplateResponse("index.html", {"request": request, "findings": findings, "error": None})

    except json.JSONDecodeError:
        return templates.TemplateResponse("index.html", {"request": request, "findings": None, "error": "Failed to parse JSON file."})
    except ValidationError as e:
         return templates.TemplateResponse("index.html", {"request": request, "findings": None, "error": f"Invalid CloudTrail log format. Missing required fields. {str(e)}"})
    except Exception as e:
         return templates.TemplateResponse("index.html", {"request": request, "findings": None, "error": f"An unexpected error occurred: {str(e)}"})

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

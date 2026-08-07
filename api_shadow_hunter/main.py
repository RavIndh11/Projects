from fastapi import FastAPI, Request, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from analyzer import APIAnalyzer
import os
import logging
from pythonjsonlogger import jsonlogger

logger = logging.getLogger("api_shadow_hunter")
logger.setLevel(logging.INFO)
logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)


app = FastAPI(title="API Shadow Hunter", description="Detect Shadow and Zombie APIs")

# Initialize templates
templates_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_dir)

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """Serves the main web UI."""
    return templates.TemplateResponse(name="index.html", context={"request": request}, request=request)

@app.post("/api/analyze")
async def analyze_files(
    spec_file: UploadFile = File(..., description="OpenAPI Specification file (YAML/JSON)"),
    log_file: UploadFile = File(..., description="Access Logs file (JSON/text)")
):
    """Analyzes the uploaded spec and logs and returns JSON results."""

    # Read files
    try:
        spec_content = (await spec_file.read()).decode("utf-8")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read spec file: {str(e)}")

    try:
        log_content = (await log_file.read()).decode("utf-8")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read log file: {str(e)}")

    if not spec_content.strip():
        raise HTTPException(status_code=400, detail="Spec file is empty.")
    if not log_content.strip():
        raise HTTPException(status_code=400, detail="Log file is empty.")

    # Analyze
    try:
        result = APIAnalyzer.analyze(spec_content, log_content)
        logger.info("Analysis completed successfully", extra={"total_documented": result.total_documented, "total_accessed": result.total_accessed, "shadow_apis_count": len(result.shadow_apis), "zombie_apis_count": len(result.zombie_apis)})
        return result.model_dump()
    except Exception as e:
        logger.error("Analysis failed", extra={"error": str(e)})
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

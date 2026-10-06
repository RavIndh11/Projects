from fastapi import FastAPI, Request, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from app.models import AnalysisResult
from app.analyzer import FileAnalyzer
from app.logger import logger

app = FastAPI(
    title="Secure Upload Gateway",
    description="A defensive security microservice to intercept and analyze file uploads for vulnerabilities.",
    version="1.0.0"
)

# Setup templates
BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

analyzer = FileAnalyzer()

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """Render the main dashboard."""
    # Use keyword args for TemplateResponse in newer Starlette
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/analyze", response_model=AnalysisResult)
async def analyze_upload(file: UploadFile = File(...)):
    """Analyze an uploaded file for security threats."""
    if not file.filename:
        logger.warning("Upload attempted without filename")
        raise HTTPException(status_code=400, detail="Filename missing")

    try:
        content = await file.read()
        logger.info("File upload received", extra={"scan_filename": file.filename})

        # Analyze file content
        result = analyzer.analyze(file.filename, content)
        return result
    except Exception as e:
        logger.error(f"Error analyzing file: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during analysis")
    finally:
        await file.close()

@app.get("/health")
async def health_check():
    """Health check endpoint for Docker container."""
    return {"status": "ok"}

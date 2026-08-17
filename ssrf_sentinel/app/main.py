import logging
from fastapi import FastAPI, Form, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, HttpUrl
from app.ssrf import URLValidator, SSRFError

# Structured logging setup
from pythonjsonlogger import jsonlogger

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
logHandler.setFormatter(formatter)
if not logger.handlers:
    logger.addHandler(logHandler)

app = FastAPI(title="SSRF Sentinel", description="An SSRF-safe fetching service.")
templates = Jinja2Templates(directory="app/templates")

class FetchRequest(BaseModel):
    url: HttpUrl

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.post("/api/fetch")
async def fetch_url(url: str = Form(...)):
    try:
        logging.info(f"Received fetch request for URL: {url}")
        content = await URLValidator.safe_fetch(url)
        return {"status": "success", "url": url, "content_preview": content[:1000]} # return preview to avoid massive payloads
    except SSRFError as e:
        logging.warning(f"SSRF attempted or failed fetch: {e} - URL: {url}")
        return {"status": "error", "message": str(e)}
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return {"status": "error", "message": "An unexpected error occurred."}

from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from app.api.routes import router
from app.core.config import settings
import os

app = FastAPI(title="MFA Fatigue Hunter", version="1.0.0")

app.include_router(router, prefix="/api/v1")

# Setup templates
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

@app.get("/")
async def serve_dashboard(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {"request": request}
    )

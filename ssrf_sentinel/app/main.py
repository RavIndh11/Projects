from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl
from typing import Optional, Dict, Any, List
import datetime

from app.core.proxy import safe_fetch
from app.core.logger import logger

app = FastAPI(title="SSRF Sentinel", description="A safe HTTP proxy that prevents Server-Side Request Forgery.")

templates = Jinja2Templates(directory="templates")

# In-memory store for demo dashboard (in production use a real DB/Redis)
request_logs = []

class ProxyRequest(BaseModel):
    url: str
    method: str = "GET"
    headers: Optional[Dict[str, str]] = None
    body: Optional[str] = None

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """
    Renders the simple UI Dashboard.
    """
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"logs": request_logs[-20:][::-1]}
    )

@app.post("/api/proxy")
async def api_proxy(req: ProxyRequest):
    """
    API endpoint to perform a safe proxy fetch.
    """
    logger.info(f"Received proxy request for {req.url}")

    result = await safe_fetch(
        url=req.url,
        method=req.method,
        headers=req.headers,
        body=req.body
    )

    # Log for the UI
    log_entry = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "url": req.url,
        "method": req.method,
        "status": result["status"],
        "reason": result["reason"],
        "status_code": result.get("status_code", "-")
    }
    request_logs.append(log_entry)

    if result["status"] == "blocked":
        return JSONResponse(status_code=403, content=result)
    elif result["status"] == "error":
        return JSONResponse(status_code=500, content=result)

    return JSONResponse(status_code=200, content=result)

@app.post("/proxy-form", response_class=HTMLResponse)
async def proxy_form(request: Request, url: str = Form(...), method: str = Form("GET")):
    """
    Form submission handler for the UI dashboard.
    """
    result = await safe_fetch(url=url, method=method)

    log_entry = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "url": url,
        "method": method,
        "status": result["status"],
        "reason": result["reason"],
        "status_code": result.get("status_code", "-")
    }
    request_logs.append(log_entry)

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "logs": request_logs[-20:][::-1],
            "last_result": result
        }
    )

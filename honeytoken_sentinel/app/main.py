from fastapi import FastAPI, Request, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from app.models import TokenCreate, TokenResponse, AlertResponse
from app import db
from app.config import logger
from typing import List

app = FastAPI(title="Honeytoken Sentinel")

templates = Jinja2Templates(directory="templates")

@app.on_event("startup")
def startup_event():
    db.init_db()
    logger.info("Honeytoken Sentinel started")

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    tokens = db.get_tokens()
    alerts = db.get_alerts()
    return templates.TemplateResponse(request=request, name="index.html", context={"tokens": tokens, "alerts": alerts})

@app.post("/api/tokens", response_model=TokenResponse)
def create_token(token_in: TokenCreate):
    try:
        token_id = db.create_token(token_in.name, token_in.description, token_in.severity)
        token = db.get_token(token_id)
        if not token:
            raise HTTPException(status_code=500, detail="Failed to create token")
        logger.info("Honeytoken created", extra={"token_id": token_id, "token_name": token_in.name})
        return token
    except Exception as e:
        logger.error("Error creating token", extra={"error": str(e)})
        raise HTTPException(status_code=400, detail="Invalid token data")

@app.get("/api/tokens", response_model=List[TokenResponse])
def get_tokens():
    return db.get_tokens()

@app.get("/api/alerts", response_model=List[AlertResponse])
def get_alerts():
    return db.get_alerts()

@app.get("/t/{token_id}")
async def trigger_token(token_id: str, request: Request, background_tasks: BackgroundTasks):
    token = db.get_token(token_id)
    if not token:
        # Prevent info disclosure on invalid tokens
        return RedirectResponse(url="https://google.com")

    ip_address = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    headers = dict(request.headers)

    # Run db insert in background to respond fast
    background_tasks.add_task(db.record_alert, token_id, ip_address, user_agent, headers)

    logger.warning(
        "Honeytoken triggered",
        extra={
            "token_id": token_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "severity": token["severity"],
            "token_name": token["name"]
        }
    )

    # Decoy response
    return HTMLResponse(content="<html><body>Not Found</body></html>", status_code=404)

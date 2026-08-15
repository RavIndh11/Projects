import os
import yaml
import secrets
from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import APIKeyHeader
from contextlib import asynccontextmanager

from .schemas import ToolRequest, EvaluationResponse
from .policy_engine import PolicyEngine
from .logger import logger, get_recent_logs, clear_logs

policy_engine = None
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def get_api_key():
    return os.getenv("API_KEY", "dev_api_key")

def verify_api_key(api_key: str = Depends(api_key_header)):
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API Key"
        )
    # Use secrets.compare_digest to prevent timing attacks
    if not secrets.compare_digest(api_key, get_api_key()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key"
        )
    return api_key

@asynccontextmanager
async def lifespan(app: FastAPI):
    global policy_engine
    logger.info("Starting up AI Agent Policy Guard...")
    policy_path = os.getenv("POLICY_PATH", "policies/default.yaml")
    policy_engine = PolicyEngine(policy_path)
    yield
    logger.info("Shutting down AI Agent Policy Guard...")

app = FastAPI(
    title="AI Agent Policy Guard",
    description="Security proxy to enforce policies on AI Agent tool executions",
    version="1.0.0",
    lifespan=lifespan
)

templates_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
templates = Jinja2Templates(directory=templates_dir)

@app.get("/health")
def health_check():
    return {"status": "healthy", "policy_loaded": policy_engine is not None}

@app.post("/api/v1/evaluate", response_model=EvaluationResponse)
async def evaluate_tool(request: ToolRequest, api_key: str = Depends(verify_api_key)):
    is_allowed, reason, matched_rule = policy_engine.evaluate(request.tool_name, request.parameters)

    log_level = "INFO" if is_allowed else "WARNING"
    log_data = {
        "event": "tool_evaluation",
        "agent_id": request.agent_id,
        "tool_name": request.tool_name,
        "parameters": request.parameters,
        "reasoning": request.reasoning,
        "is_allowed": is_allowed,
        "reason": reason,
        "matched_rule": matched_rule
    }

    if is_allowed:
        logger.info(f"Tool execution allowed: {request.tool_name}", extra=log_data)
    else:
        logger.warning(f"Tool execution BLOCKED: {request.tool_name}", extra=log_data)

    return EvaluationResponse(
        allowed=is_allowed,
        reason=reason,
        matched_rule=matched_rule
    )

@app.get("/api/v1/logs")
def get_logs(api_key: str = Depends(verify_api_key)):
    return {"logs": get_recent_logs()}

@app.post("/api/v1/reload-policy")
def reload_policy(api_key: str = Depends(verify_api_key)):
    try:
        policy_engine.reload()
        logger.info("Policy reloaded successfully via API")
        return {"status": "success", "message": "Policy reloaded successfully"}
    except Exception as e:
        logger.error(f"Failed to reload policy: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to reload policy: {str(e)}")

@app.get("/api/v1/policy")
def get_policy(api_key: str = Depends(verify_api_key)):
    return {"policy": policy_engine.policies}

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

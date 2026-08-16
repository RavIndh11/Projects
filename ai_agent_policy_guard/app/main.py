from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from typing import List, Dict, Any
from datetime import datetime

from .schemas import ToolExecutionRequest, EvaluationResult
from .policy import PolicyEngine
from .logger import logger
import os

app = FastAPI(title="AI Agent Policy Guard")

# Initialize templates and policy engine
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))
policy_engine = PolicyEngine()

# In-memory store for recent evaluations (for dashboard)
recent_evaluations: List[Dict[str, Any]] = []
MAX_EVALS_STORED = 100

@app.post("/evaluate", response_model=EvaluationResult)
async def evaluate_tool(request: ToolExecutionRequest):
    try:
        result = policy_engine.evaluate(request)

        # Log the evaluation
        log_data = {
            "agent_id": request.agent_id,
            "tool_name": request.tool_name,
            "arguments": request.arguments,
            "allowed": result.allowed,
            "reason": result.reason,
            "matched_rule": result.matched_rule,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

        if result.allowed:
            logger.info("Tool execution allowed", extra=log_data)
        else:
            logger.warning("Tool execution denied", extra=log_data)

        # Store for dashboard
        recent_evaluations.insert(0, log_data)
        if len(recent_evaluations) > MAX_EVALS_STORED:
            recent_evaluations.pop()

        return result
    except Exception as e:
        logger.error(f"Error evaluating policy: {str(e)}", extra={"agent_id": request.agent_id, "tool_name": request.tool_name})
        raise HTTPException(status_code=500, detail="Internal server error during evaluation")

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    # Calculate stats
    total = len(recent_evaluations)
    allowed = sum(1 for e in recent_evaluations if e["allowed"])
    denied = total - allowed

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "evaluations": recent_evaluations,
            "stats": {
                "total": total,
                "allowed": allowed,
                "denied": denied
            }
        }
    )

@app.get("/health")
async def health_check():
    return {"status": "ok"}

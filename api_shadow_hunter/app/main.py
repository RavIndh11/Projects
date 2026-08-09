from fastapi import FastAPI, UploadFile, File, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import os
from .analyzer import parse_openapi_spec, parse_access_logs, detect_shadow_zombie_apis
from .logger import setup_json_logger

app = FastAPI(title="API Shadow Hunter", description="Identify Shadow and Zombie APIs")
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))
logger = setup_json_logger()

# In-memory storage for simplicity in this demo tool
# In production, this would be a database or cache
STATE = {
    "spec_endpoints": [],
    "log_traffic": [],
    "results": {
        "shadow_apis": [],
        "zombie_apis": []
    }
}

class StatusResponse(BaseModel):
    message: str
    count: int

@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    logger.info("Dashboard accessed")
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"results": STATE["results"]}
    )

@app.post("/api/upload-spec", response_model=StatusResponse)
async def upload_spec(file: UploadFile = File(...)):
    try:
        content = (await file.read()).decode("utf-8")
        endpoints = parse_openapi_spec(content)
        if not endpoints:
            logger.warning(f"Failed to parse OpenAPI spec or no endpoints found in file: {file.filename}")
            raise HTTPException(status_code=400, detail="Invalid OpenAPI spec or no endpoints found.")

        STATE["spec_endpoints"] = endpoints
        _update_results()

        logger.info(f"Successfully processed OpenAPI spec: {file.filename}", extra={"endpoint_count": len(endpoints)})
        return {"message": "Spec uploaded successfully", "count": len(endpoints)}
    except Exception as e:
        logger.error(f"Error processing spec: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/upload-logs", response_model=StatusResponse)
async def upload_logs(file: UploadFile = File(...)):
    try:
        content = (await file.read()).decode("utf-8")
        traffic = parse_access_logs(content)

        # Append to existing traffic or replace? For simplicity, we replace.
        STATE["log_traffic"] = traffic
        _update_results()

        logger.info(f"Successfully processed access logs: {file.filename}", extra={"traffic_count": len(traffic)})
        return {"message": "Logs uploaded successfully", "count": len(traffic)}
    except Exception as e:
        logger.error(f"Error processing logs: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

def _update_results():
    if STATE["spec_endpoints"] and STATE["log_traffic"]:
        results = detect_shadow_zombie_apis(STATE["spec_endpoints"], STATE["log_traffic"])
        STATE["results"] = results
        logger.info("Updated analysis results", extra={
            "shadow_count": len(results["shadow_apis"]),
            "zombie_count": len(results["zombie_apis"])
        })

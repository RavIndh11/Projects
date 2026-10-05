from fastapi import APIRouter, Depends, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
from app.models.schemas import BatchLogIngest, AnalyzeResponse
from app.services.analyzer import analyze_logs, recent_alerts
from app.core.config import settings
from app.core.logger import setup_logger

logger = setup_logger(__name__)

router = APIRouter()
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True)

import secrets

def verify_api_key(api_key: str = Security(api_key_header)):
    if not secrets.compare_digest(api_key, settings.API_KEY):
        logger.warning("Failed authentication attempt")
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return api_key

@router.post("/logs", response_model=AnalyzeResponse)
async def ingest_logs(payload: BatchLogIngest, api_key: str = Depends(verify_api_key)):
    logger.info(f"Received batch of {len(payload.logs)} logs")
    alerts = analyze_logs(payload.logs)

    return AnalyzeResponse(
        status="success",
        processed_logs=len(payload.logs),
        alerts_found=len(alerts),
        alerts=alerts
    )

@router.get("/health")
async def health_check():
    return {"status": "healthy"}

@router.get("/alerts")
async def get_alerts():
    # In a real app this would use session auth for the dashboard
    return {"alerts": recent_alerts}

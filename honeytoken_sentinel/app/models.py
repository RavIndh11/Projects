from pydantic import BaseModel, Field
from typing import Optional, Dict
from datetime import datetime

class TokenCreate(BaseModel):
    name: str = Field(..., max_length=100, pattern=r"^[a-zA-Z0-9_\-\s]+$")
    description: Optional[str] = Field(None, max_length=500)
    severity: str = Field("Medium", pattern="^(Low|Medium|High|Critical)$")

class TokenResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    severity: str
    created_at: str
    triggered_count: int

class AlertResponse(BaseModel):
    id: int
    token_id: str
    token_name: str
    severity: str
    ip_address: str
    user_agent: Optional[str]
    headers: str
    timestamp: str

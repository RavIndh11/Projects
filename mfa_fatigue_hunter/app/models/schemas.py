from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field

class LogEntry(BaseModel):
    timestamp: datetime
    user_id: str = Field(..., min_length=1, max_length=255)
    action: str = Field(..., description="Action like 'mfa_prompt_denied', 'mfa_prompt_ignored', 'mfa_prompt_accepted'")
    ip_address: Optional[str] = None

class BatchLogIngest(BaseModel):
    logs: List[LogEntry]

class Alert(BaseModel):
    user_id: str
    attack_detected: bool
    severity: str
    description: str
    prompt_count: int

class AnalyzeResponse(BaseModel):
    status: str
    processed_logs: int
    alerts_found: int
    alerts: List[Alert]

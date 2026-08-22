from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from typing import Optional

class MFAEvent(BaseModel):
    user_email: EmailStr
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    ip_address: Optional[str] = None
    event_type: str = Field(..., pattern=r"^(push_sent|push_approved|push_denied|push_timeout)$")
    user_agent: Optional[str] = None

class ThreatAlert(BaseModel):
    user_email: EmailStr
    severity: str = Field(..., pattern=r"^(Low|Medium|High|Critical)$")
    push_count: int
    time_window_seconds: int
    first_event_time: datetime
    last_event_time: datetime
    description: str

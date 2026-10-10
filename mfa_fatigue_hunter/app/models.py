from pydantic import BaseModel, Field, field_validator
from typing import Optional
from datetime import datetime

class AuthEvent(BaseModel):
    user_id: str = Field(..., description="Unique identifier for the user (e.g., email or ID)")
    event_type: str = Field(..., description="Type of event, e.g., 'mfa_push_sent', 'mfa_push_accepted', 'mfa_push_rejected'")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Time the event occurred")
    ip_address: Optional[str] = Field(None, description="IP address originating the request")
    device_id: Optional[str] = Field(None, description="Device ID originating the request")

    @field_validator('event_type')
    @classmethod
    def validate_event_type(cls, v: str) -> str:
        v = v.lower().strip()
        allowed = {'mfa_push_sent', 'mfa_push_accepted', 'mfa_push_rejected'}
        if v not in allowed:
            raise ValueError(f"Invalid event_type. Must be one of: {', '.join(allowed)}")
        return v

class Alert(BaseModel):
    alert_id: str
    user_id: str
    severity: str = Field(..., description="Severity of the alert (Low, Medium, High, Critical)")
    timestamp: datetime
    description: str
    event_count: int
    time_window_seconds: int
    related_ips: list[str]

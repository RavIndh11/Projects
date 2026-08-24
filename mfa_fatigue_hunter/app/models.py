from pydantic import BaseModel, Field, EmailStr, IPvAnyAddress
from datetime import datetime
from enum import Enum
from typing import Optional

class EventType(str, Enum):
    MFA_PUSH_SENT = "mfa_push_sent"
    MFA_PUSH_REJECTED = "mfa_push_rejected"
    MFA_PUSH_APPROVED = "mfa_push_approved"
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"

class AuthEvent(BaseModel):
    user_email: EmailStr = Field(..., description="Email of the user attempting to authenticate")
    event_type: EventType = Field(..., description="Type of authentication event")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Time the event occurred")
    ip_address: IPvAnyAddress = Field(..., description="IP address of the client triggering the event")
    device_id: Optional[str] = Field(None, description="Optional identifier for the device")
    location: Optional[str] = Field(None, description="Geographic location (e.g., 'US', 'IE')")

class AlertSeverity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class ThreatAlert(BaseModel):
    alert_id: str
    user_email: str
    severity: AlertSeverity
    reason: str
    event_count: int
    first_event_time: datetime
    last_event_time: datetime
    status: str = "open"

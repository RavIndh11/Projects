from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from enum import Enum
from typing import Optional


class MFAStatus(str, Enum):
    PENDING = "PENDING"
    DENIED = "DENIED"
    APPROVED = "APPROVED"


class MFAEvent(BaseModel):
    user_email: EmailStr = Field(..., description="Email address of the user")
    ip_address: str = Field(..., description="IP address of the device making the request")
    status: MFAStatus = Field(..., description="Status of the MFA request")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Time of the event")
    device_id: Optional[str] = Field(None, description="Optional device identifier")


class AlertSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Alert(BaseModel):
    user_email: EmailStr
    severity: AlertSeverity
    message: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    details: dict = Field(default_factory=dict)
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime
from typing import Optional, List
from enum import Enum

class EventStatus(str, Enum):
    PENDING = "PENDING"
    REJECTED = "REJECTED"
    SUCCESS = "SUCCESS"

class AuthEvent(BaseModel):
    user_id: str = Field(..., description="Unique identifier for the user (e.g., email or username)")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Timestamp of the event in UTC")
    status: EventStatus = Field(..., description="Status of the MFA request")
    source_ip: str = Field(..., description="IP address initiating the request")
    device_info: Optional[str] = Field(None, description="Information about the device")

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class DetectionResult(BaseModel):
    user_id: str
    severity: Severity
    message: str
    event_count: int
    time_window_seconds: int
    first_event_time: datetime
    last_event_time: datetime
    source_ips: List[str]
    is_compromised: bool = False # Set to true if a success event happens after many rejections

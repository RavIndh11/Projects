from pydantic import BaseModel, Field, IPvAnyAddress, field_validator
from datetime import datetime
from typing import Optional

class MFALogEvent(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=100, description="The unique identifier for the user.")
    event_type: str = Field(..., description="The type of MFA event, e.g., 'push_notification', 'sms', 'totp'.")
    ip_address: IPvAnyAddress = Field(..., description="The IP address from which the event originated.")
    timestamp: datetime = Field(..., description="The timestamp of the event in ISO 8601 format.")
    status: str = Field(..., description="The status of the MFA event (e.g., 'pending', 'approved', 'denied').")
    device_id: Optional[str] = Field(None, max_length=255, description="An optional device identifier.")

    @field_validator('event_type')
    def validate_event_type(cls, v):
        allowed_types = ['push_notification', 'sms', 'totp', 'email']
        if v not in allowed_types:
            raise ValueError(f"event_type must be one of {allowed_types}")
        return v

    @field_validator('status')
    def validate_status(cls, v):
        allowed_statuses = ['pending', 'approved', 'denied', 'timeout']
        if v not in allowed_statuses:
            raise ValueError(f"status must be one of {allowed_statuses}")
        return v

class AlertEvent(BaseModel):
    user_id: str
    alert_type: str = "MFA_FATIGUE_DETECTED"
    severity: str
    message: str
    event_count: int
    time_window: int
    timestamp: datetime

from pydantic import BaseModel, Field, IPvAnyAddress, field_validator
from typing import Optional
from datetime import datetime

class Coordinates(BaseModel):
    lat: float = Field(..., ge=-90, le=90, description="Latitude must be between -90 and 90")
    lon: float = Field(..., ge=-180, le=180, description="Longitude must be between -180 and 180")

class AuthEvent(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=255, description="Unique identifier for the user")
    timestamp: datetime = Field(..., description="Timestamp of the authentication attempt")
    ip_address: IPvAnyAddress = Field(..., description="IP address of the client")
    status: str = Field(..., description="Status of the authentication (e.g., 'success' or 'failure')")
    location: Optional[Coordinates] = None

    @field_validator('status')
    @classmethod
    def validate_status(cls, v: str) -> str:
        v_lower = v.lower()
        if v_lower not in ["success", "failure"]:
            raise ValueError("status must be 'success' or 'failure'")
        return v_lower

class AnomalyResult(BaseModel):
    event_id: Optional[str] = None
    user_id: str
    anomaly_type: str = Field(..., description="Type of anomaly (e.g., 'impossible_travel', 'brute_force')")
    severity: str = Field(..., description="Severity of the anomaly (e.g., 'Low', 'Medium', 'High', 'Critical')")
    description: str
    timestamp: datetime

from pydantic import BaseModel, IPvAnyAddress, Field
from datetime import datetime
from typing import Optional

class AuthLog(BaseModel):
    user_id: str = Field(..., description="Unique identifier for the user", min_length=1)
    ip_address: IPvAnyAddress = Field(..., description="IP address of the login attempt")
    timestamp: datetime = Field(..., description="Timestamp of the login attempt (ISO 8601)")
    user_agent: Optional[str] = Field(None, description="User agent string")
    status: str = Field(..., description="Status of the login (e.g., 'success', 'failed')")

    class Config:
        json_schema_extra = {
            "example": {
                "user_id": "alice123",
                "ip_address": "192.168.1.1",
                "timestamp": "2023-10-27T10:00:00Z",
                "user_agent": "Mozilla/5.0...",
                "status": "success"
            }
        }

class AnomalyAlert(BaseModel):
    alert_id: str
    user_id: str
    severity: str = Field(..., description="Severity of the alert: Low, Medium, High, Critical")
    description: str
    timestamp: datetime
    details: dict

    class Config:
        json_schema_extra = {
            "example": {
                "alert_id": "uuid-1234",
                "user_id": "alice123",
                "severity": "High",
                "description": "Impossible travel detected",
                "timestamp": "2023-10-27T10:05:00Z",
                "details": {
                    "distance_km": 5000.0,
                    "time_diff_hours": 1.0,
                    "speed_kmh": 5000.0
                }
            }
        }

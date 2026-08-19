from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Literal
from datetime import datetime
import ipaddress

class MFALog(BaseModel):
    user_email: EmailStr
    ip_address: str
    timestamp: datetime
    status: Literal["pending", "approved", "denied", "timeout"]
    device_info: str = Field(default="Unknown Device")

    @field_validator("ip_address")
    def validate_ip(cls, v):
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError("Invalid IP address format")

class Alert(BaseModel):
    alert_id: str
    severity: Literal["Low", "Medium", "High", "Critical"]
    user_email: str
    message: str
    timestamp: datetime
    trigger_count: int

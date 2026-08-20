from pydantic import BaseModel, EmailStr, Field
from typing import Literal
from datetime import datetime
import time

class AuthEvent(BaseModel):
    user_email: EmailStr
    event_type: Literal["mfa_prompt", "mfa_success", "mfa_denied"]
    source_ip: str
    timestamp: float = Field(default_factory=time.time)

class Alert(BaseModel):
    id: str
    user_email: str
    severity: Literal["Low", "Medium", "High", "Critical"]
    description: str
    timestamp: float = Field(default_factory=time.time)

    @property
    def time_formatted(self) -> str:
        return datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S")

from pydantic import BaseModel, HttpUrl, Field, field_validator
from typing import List, Optional

class AnalyzeRequest(BaseModel):
    url: HttpUrl = Field(..., description="Target GraphQL endpoint URL (http/https only)")
    headers: Optional[dict] = Field(default_factory=dict, description="Optional headers (e.g., Authorization)")

    @field_validator('url')
    @classmethod
    def check_scheme(cls, v):
        if v.scheme not in ('http', 'https'):
            raise ValueError('URL scheme must be http or https')
        return v

class ThreatSeverity(str):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class AnalyzeResponse(BaseModel):
    url: str
    introspection_enabled: bool
    sensitive_fields: List[str] = []
    mutations: List[str] = []
    severity: str
    error: Optional[str] = None

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class TokenInput(BaseModel):
    token: str = Field(
        ...,
        description="The JWT token to analyze",
        pattern=r"^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$",
        min_length=10,
        max_length=8192
    )

class Vulnerability(BaseModel):
    id: str = Field(..., description="Unique identifier for the vulnerability")
    name: str = Field(..., description="Name of the vulnerability")
    severity: str = Field(..., description="Severity level: High, Medium, Low")
    description: str = Field(..., description="Description of the vulnerability")
    remediation: str = Field(..., description="How to fix it")

class AnalysisResult(BaseModel):
    is_valid_format: bool
    header: Optional[Dict[str, Any]] = None
    payload: Optional[Dict[str, Any]] = None
    signature: Optional[str] = None
    vulnerabilities: List[Vulnerability] = []
    error: Optional[str] = None

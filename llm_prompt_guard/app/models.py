from pydantic import BaseModel, Field
from typing import List, Optional

class AnalyzeRequest(BaseModel):
    prompt: str = Field(..., description="The user prompt to analyze", min_length=1, max_length=50000)
    session_id: Optional[str] = Field(None, description="Optional session ID for tracking")

class SecurityViolation(BaseModel):
    type: str = Field(..., description="Type of violation (e.g., Prompt Injection, Jailbreak)")
    severity: str = Field(..., description="Severity level: Low, Medium, High, Critical")
    description: str = Field(..., description="Description of the violation")

class AnalyzeResponse(BaseModel):
    is_safe: bool = Field(..., description="Whether the prompt is safe to process")
    violations: List[SecurityViolation] = Field(default_factory=list, description="List of detected violations")
    risk_score: int = Field(..., description="Calculated risk score from 0-100")

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class AnalyzeRequest(BaseModel):
    prompt: str = Field(..., description="The user prompt to analyze for injection or jailbreak attempts", min_length=1, max_length=10000)
    context: Optional[str] = Field(None, description="Optional conversation context or system prompt", max_length=10000)

class DetectionResult(BaseModel):
    is_malicious: bool
    score: float = Field(..., description="Risk score from 0.0 to 1.0", ge=0.0, le=1.0)
    reasons: List[str] = Field(default_factory=list, description="Reasons for the classification")
    severity: str = Field(..., description="Severity level: Low, Medium, High, Critical")

class AnalyzeResponse(BaseModel):
    request_id: str
    prompt_length: int
    result: DetectionResult
    metadata: Dict[str, Any] = Field(default_factory=dict)

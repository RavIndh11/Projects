from pydantic import BaseModel, Field, constr
from typing import List

class AnalyzeRequest(BaseModel):
    # Strict validation: prevent massive payloads, allow a generous but safe prompt size
    prompt: constr(min_length=1, max_length=10000) = Field(
        ...,
        description="The prompt to analyze for potential injection or jailbreak."
    )

class MatchDetail(BaseModel):
    rule_id: str = Field(..., description="The unique identifier of the matched rule.")
    rule_name: str = Field(..., description="The name of the matched rule.")
    severity: str = Field(..., description="The severity of the match (e.g., Low, Medium, High, Critical).")

class AnalyzeResponse(BaseModel):
    is_safe: bool = Field(..., description="True if no threats were detected, False otherwise.")
    severity: str = Field(..., description="The highest severity level detected.")
    matches: List[MatchDetail] = Field(default_factory=list, description="List of detected threats.")

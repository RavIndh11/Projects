from pydantic import BaseModel, Field

class PromptRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=10000, description="The LLM prompt to analyze")

class AnalyzeResponse(BaseModel):
    is_safe: bool = Field(..., description="True if prompt is considered safe, False otherwise")
    threat_score: float = Field(..., description="Threat score between 0.0 (safe) and 1.0 (certain attack)")
    threat_level: str = Field(..., description="Severity of the threat: Low, Medium, High, Critical")
    matched_rules: list[str] = Field(default_factory=list, description="List of rule names that were triggered")

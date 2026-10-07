from pydantic import BaseModel, Field

class TextAnalysisRequest(BaseModel):
    content: str = Field(..., max_length=100000, description="The text content to analyze")
    filename: str = Field(default="unknown.txt", max_length=255, description="The filename of the content being analyzed")

class ScanResult(BaseModel):
    filename: str
    is_malicious: bool
    risk_score: float
    entropy: float
    matched_signatures: list[str]
    threat_level: str

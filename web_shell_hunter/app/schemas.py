from pydantic import BaseModel, Field
from typing import List

class ScanRequest(BaseModel):
    content: str = Field(..., description="The content of the file or payload to scan for web shell patterns.")

class ScanResponse(BaseModel):
    is_malicious: bool = Field(..., description="Indicates if the content is flagged as a web shell.")
    entropy: float = Field(..., description="Shannon entropy of the content.")
    matched_signatures: List[str] = Field(..., description="List of signature names that matched the content.")
    severity: str = Field(..., description="Severity of the threat (Low, Medium, High, Critical).")

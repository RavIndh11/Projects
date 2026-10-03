from pydantic import BaseModel, Field
from typing import List

class ScanResult(BaseModel):
    filename: str = Field(..., description="The name of the analyzed file")
    is_safe: bool = Field(..., description="Whether the file is considered safe to process")
    severity: str = Field(..., description="Threat severity (Low, Medium, High, Critical)")
    matched_rules: List[str] = Field(default_factory=list, description="Rules that triggered during analysis")
    details: List[str] = Field(default_factory=list, description="Detailed explanation of the findings")

class ScanResponse(BaseModel):
    status: str = Field(..., description="Status of the scan operation (success/error)")
    result: ScanResult | None = None
    message: str | None = None

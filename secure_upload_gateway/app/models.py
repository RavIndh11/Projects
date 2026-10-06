from pydantic import BaseModel, Field
from typing import List
from enum import Enum

class ThreatSeverity(str, Enum):
    NONE = "None"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class Finding(BaseModel):
    vulnerability: str = Field(..., description="Name of the vulnerability found")
    severity: ThreatSeverity = Field(..., description="Severity of the finding")
    description: str = Field(..., description="Detailed description of the finding")

class AnalysisResult(BaseModel):
    filename: str = Field(..., description="Original name of the uploaded file")
    is_safe: bool = Field(..., description="True if no high/critical threats were found")
    overall_severity: ThreatSeverity = Field(..., description="Highest severity among findings")
    findings: List[Finding] = Field(default_factory=list, description="List of specific security findings")
    mime_type: str = Field(..., description="Detected MIME type based on magic bytes")
    extension: str = Field(..., description="File extension extracted from filename")

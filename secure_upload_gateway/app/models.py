from pydantic import BaseModel, Field
from enum import Enum
from typing import List, Optional

class RiskSeverity(str, Enum):
    SAFE = "Safe"
    LOW = "Low"
    MED = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class ThreatFinding(BaseModel):
    threat_type: str = Field(..., description="The type of threat detected (e.g., zip_slip, extension_spoofing)")
    description: str = Field(..., description="Detailed description of the finding")

class ScanResponse(BaseModel):
    filename: str = Field(..., description="The name of the scanned file")
    actual_mime: str = Field(..., description="The detected MIME type using python-magic")
    severity: RiskSeverity = Field(..., description="The overall risk severity of the file")
    findings: List[ThreatFinding] = Field(default_factory=list, description="List of specific threat findings")

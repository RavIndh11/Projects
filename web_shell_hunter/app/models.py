from pydantic import BaseModel, Field, field_validator
import re
from typing import List, Optional

class ScanRequest(BaseModel):
    file_path: str = Field(..., description="Path to the file to scan")
    file_content: Optional[str] = Field(None, description="Raw content of the file (optional)")

    @field_validator('file_path')
    def validate_file_path(cls, v):
        # Basic path traversal prevention for input validation
        if '..' in v or v.startswith('/'):
            raise ValueError("Invalid file path: path traversal detected or absolute path used.")
        if not re.match(r'^[\w\-\./]+$', v):
            raise ValueError("Invalid file path: contains invalid characters.")
        return v

class Finding(BaseModel):
    severity: str = Field(..., description="Severity of the finding (Low, Med, High, Critical)")
    type: str = Field(..., description="Type of finding (e.g., Obfuscation, Known Signature)")
    description: str = Field(..., description="Description of the finding")
    match_string: Optional[str] = Field(None, description="The specific string or pattern that matched")

    @field_validator('severity')
    def validate_severity(cls, v):
        allowed = ['Low', 'Med', 'High', 'Critical']
        if v not in allowed:
            raise ValueError(f"Severity must be one of {allowed}")
        return v

class ScanResponse(BaseModel):
    file_path: str = Field(..., description="Path to the scanned file")
    status: str = Field(..., description="Status of the scan (Clean, Suspicious, Malicious, Error)")
    findings: List[Finding] = Field(default_factory=list, description="List of findings")
    error_message: Optional[str] = None

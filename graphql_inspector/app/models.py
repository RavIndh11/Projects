from pydantic import BaseModel, HttpUrl
from typing import List, Optional

class ScanRequest(BaseModel):
    url: HttpUrl

class Vulnerability(BaseModel):
    title: str
    severity: str
    description: str

class ScanResult(BaseModel):
    url: str
    introspection_enabled: bool
    sensitive_fields_found: List[str]
    vulnerabilities: List[Vulnerability]
    status: str
    error_message: Optional[str] = None

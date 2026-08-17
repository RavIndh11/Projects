from pydantic import BaseModel, HttpUrl
from typing import List, Optional

class AnalyzeRequest(BaseModel):
    url: HttpUrl

class SensitiveField(BaseModel):
    type_name: str
    field_name: str
    reason: str

class AnalysisReport(BaseModel):
    url: str
    introspection_enabled: bool
    error_message: Optional[str] = None
    sensitive_fields: List[SensitiveField] = []
    total_types: int = 0

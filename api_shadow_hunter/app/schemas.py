from pydantic import BaseModel, Field
from typing import List, Dict, Optional
from enum import Enum


class EndpointCategory(str, Enum):
    DOCUMENTED = "Documented"
    SHADOW = "Shadow"
    ZOMBIE = "Zombie"

class Severity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class AnalyzedEndpoint(BaseModel):
    method: str
    path: str
    category: EndpointCategory
    severity: Optional[Severity] = None
    access_count: int = 0
    matched_documented_path: Optional[str] = None

class AnalysisReport(BaseModel):
    total_logs: int
    documented_count: int
    shadow_count: int
    zombie_count: int
    endpoints: List[AnalyzedEndpoint]

class LogEntry(BaseModel):
    method: str
    path: str

class OpenAPIPath(BaseModel):
    path: str
    methods: List[str]
    regex_pattern: str

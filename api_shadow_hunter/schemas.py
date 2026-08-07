from pydantic import BaseModel, Field
from typing import List

class APIEndpoint(BaseModel):
    method: str = Field(..., description="HTTP Method")
    path: str = Field(..., description="Endpoint path")

class AnalysisResult(BaseModel):
    total_documented: int = Field(0, description="Total documented endpoints")
    total_accessed: int = Field(0, description="Total accessed endpoints")
    shadow_apis: List[APIEndpoint] = Field(default_factory=list, description="Undocumented APIs found in logs")
    zombie_apis: List[APIEndpoint] = Field(default_factory=list, description="Documented APIs not found in logs")

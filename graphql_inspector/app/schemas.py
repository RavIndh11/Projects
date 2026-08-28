from pydantic import BaseModel, Field, constr
from typing import List, Optional

class AnalyzeRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=10000, description="The GraphQL query string to analyze.")
    max_depth_limit: int = Field(default=5, ge=1, le=50, description="Maximum allowed nesting depth.")
    max_alias_limit: int = Field(default=5, ge=0, le=100, description="Maximum allowed aliases.")
    allow_introspection: bool = Field(default=False, description="Whether introspection queries are permitted.")

class AnalyzeResponse(BaseModel):
    status: str = Field(..., description="Success or error status.")
    message: Optional[str] = Field(None, description="Error message if applicable.")
    depth: Optional[int] = Field(None, description="Detected maximum nesting depth.")
    aliases: Optional[int] = Field(None, description="Detected total alias count.")
    introspection: Optional[bool] = Field(None, description="Whether introspection was detected.")
    field_count: Optional[int] = Field(None, description="Total number of fields requested.")
    issues: Optional[List[str]] = Field(None, description="List of identified security issues.")
    risk_score: int = Field(..., description="Calculated risk score.")
    severity: str = Field(..., description="Risk severity level (Low, Medium, High, Critical).")
    is_safe: Optional[bool] = Field(None, description="Boolean flag indicating if the query is considered safe.")

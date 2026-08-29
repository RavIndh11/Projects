from pydantic import BaseModel, Field
from typing import List, Optional

class InspectRequest(BaseModel):
    query: str = Field(..., description="The GraphQL query to inspect")
    max_depth: Optional[int] = Field(5, ge=1, le=20, description="Maximum allowed query depth")
    max_aliases: Optional[int] = Field(3, ge=0, le=50, description="Maximum allowed aliases")
    allow_introspection: Optional[bool] = Field(False, description="Whether to allow introspection queries")

class Violation(BaseModel):
    issue_type: str
    message: str
    severity: str

class InspectResponse(BaseModel):
    is_valid: bool
    violations: List[Violation] = []
    error: Optional[str] = None

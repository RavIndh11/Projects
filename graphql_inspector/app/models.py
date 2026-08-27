from pydantic import BaseModel, Field
from typing import List, Optional

class InspectRequest(BaseModel):
    query: str = Field(..., description="The GraphQL query to inspect")

class SecurityFlag(BaseModel):
    rule_id: str
    description: str
    severity: str

class InspectResponse(BaseModel):
    status: str
    risk_score: str
    flags: List[SecurityFlag]
    metrics: dict

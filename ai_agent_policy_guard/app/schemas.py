from pydantic import BaseModel, Field, validator
from typing import Dict, Any, Optional

class ToolExecutionRequest(BaseModel):
    agent_id: str = Field(..., description="Unique identifier for the agent requesting execution.")
    tool_name: str = Field(..., description="The name of the tool to be executed.")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Arguments to be passed to the tool.")

    @validator('tool_name')
    def validate_tool_name(cls, v):
        if not v.replace('_', '').isalnum():
            raise ValueError('tool_name must only contain alphanumeric characters and underscores')
        return v

class EvaluationResult(BaseModel):
    allowed: bool = Field(..., description="Whether the execution is allowed.")
    reason: str = Field(..., description="The reason for the decision.")
    matched_rule: Optional[str] = Field(None, description="The name of the rule that matched.")

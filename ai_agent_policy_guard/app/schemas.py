from pydantic import BaseModel, Field, validator
from typing import Dict, Any, Optional

class ToolRequest(BaseModel):
    tool_name: str = Field(..., description="The name of the tool to execute (e.g., 'shell_execute', 'read_file')")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Parameters to pass to the tool")
    agent_id: Optional[str] = Field(default="unknown", description="Identifier for the agent requesting the action")
    reasoning: Optional[str] = Field(default="", description="The agent's reasoning for requesting this action")

class EvaluationResponse(BaseModel):
    allowed: bool = Field(..., description="Whether the tool execution is allowed by policy")
    reason: str = Field(..., description="The reason for the evaluation result")
    matched_rule: Optional[str] = Field(default=None, description="The specific rule that was matched, if any")

import yaml
import re
from typing import Dict, Any, List
from pathlib import Path
from .schemas import ToolExecutionRequest, EvaluationResult

class PolicyEngine:
    def __init__(self, policy_dir: str = "policies"):
        self.policy_dir = Path(policy_dir)
        self.policies = self.load_policies()

    def load_policies(self) -> Dict[str, Any]:
        policies = {}
        if not self.policy_dir.exists():
            return policies

        for p in self.policy_dir.glob("*.yaml"):
            with open(p, "r") as f:
                try:
                    policy = yaml.safe_load(f)
                    if policy and "agent_id" in policy:
                        policies[policy["agent_id"]] = policy
                except Exception as e:
                    print(f"Error loading policy {p}: {e}")
        return policies

    def evaluate(self, request: ToolExecutionRequest) -> EvaluationResult:
        if request.agent_id not in self.policies:
            # Default deny if no policy is defined for the agent
            return EvaluationResult(
                allowed=False,
                reason=f"No policy defined for agent_id: {request.agent_id}",
                matched_rule=None
            )

        policy = self.policies[request.agent_id]

        # 1. Check globally denied tools
        if request.tool_name in policy.get("denied_tools", []):
            return EvaluationResult(
                allowed=False,
                reason=f"Tool '{request.tool_name}' is explicitly denied.",
                matched_rule="global_deny"
            )

        # 2. Check if tool is allowed and validate arguments
        allowed_tools = policy.get("allowed_tools", {})
        if request.tool_name not in allowed_tools:
            return EvaluationResult(
                allowed=False,
                reason=f"Tool '{request.tool_name}' is not in allowed list.",
                matched_rule="default_deny"
            )

        tool_policy = allowed_tools[request.tool_name]

        # 3. Check required arguments
        required_args = tool_policy.get("required_args", [])
        for arg in required_args:
            if arg not in request.arguments:
                return EvaluationResult(
                    allowed=False,
                    reason=f"Missing required argument: {arg}",
                    matched_rule=f"require_{arg}"
                )

        # 4. Check argument constraints (regex matching)
        arg_constraints = tool_policy.get("arg_constraints", {})
        for arg, pattern in arg_constraints.items():
            if arg in request.arguments:
                val = str(request.arguments[arg])
                if not re.match(pattern, val):
                    return EvaluationResult(
                        allowed=False,
                        reason=f"Argument '{arg}' does not match constraint '{pattern}'",
                        matched_rule=f"constraint_{arg}"
                    )

        # Passed all checks
        return EvaluationResult(
            allowed=True,
            reason="All policy checks passed.",
            matched_rule="allow"
        )

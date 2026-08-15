import yaml
import re
from typing import Dict, Any, Tuple, Optional
import os
from .logger import logger

class PolicyEngine:
    def __init__(self, policy_path: str):
        self.policy_path = policy_path
        self.policies = self._load_policies()

    def _load_policies(self) -> Dict[str, Any]:
        if not os.path.exists(self.policy_path):
            logger.warning("Policy file not found, creating a default deny-all policy", extra={"path": self.policy_path})
            return {"default_action": "deny", "tools": {}}
        try:
            with open(self.policy_path, 'r') as f:
                policy = yaml.safe_load(f)
                logger.info("Successfully loaded policy configuration", extra={"path": self.policy_path})
                return policy or {"default_action": "deny", "tools": {}}
        except yaml.YAMLError as e:
            logger.error("Error parsing YAML policy file", extra={"error": str(e)})
            return {"default_action": "deny", "tools": {}}

    def reload(self):
        self.policies = self._load_policies()

    def evaluate(self, tool_name: str, parameters: Dict[str, Any]) -> Tuple[bool, str, Optional[str]]:
        tools_policy = self.policies.get("tools", {})
        default_action = self.policies.get("default_action", "deny").lower()

        if tool_name not in tools_policy:
            if default_action == "allow":
                return True, "Tool not explicitly defined, allowed by default policy", "default_allow"
            else:
                return False, f"Tool '{tool_name}' not defined in policy and default action is deny", "default_deny"

        tool_rules = tools_policy[tool_name]
        tool_action = tool_rules.get("action", default_action).lower()
        if tool_action == "deny":
            return False, f"Tool '{tool_name}' is explicitly denied", "tool_deny"

        rules = tool_rules.get("rules", [])
        if tool_action == "allow" and not rules:
            return True, f"Tool '{tool_name}' explicitly allowed with no parameter constraints", "tool_allow"

        for rule in rules:
            rule_name = rule.get("name", "unnamed_rule")
            param_name = rule.get("parameter")

            if not param_name or param_name not in parameters:
                if rule.get("required", False):
                    return False, f"Required parameter '{param_name}' missing for rule '{rule_name}'", rule_name
                continue

            param_value = str(parameters[param_name])
            match_type = rule.get("match_type", "exact")

            if match_type == "exact":
                allowed_values = rule.get("allowed_values", [])
                if param_value not in allowed_values:
                    return False, f"Value '{param_value}' for '{param_name}' not in allowed list", rule_name
            elif match_type == "regex":
                pattern = rule.get("pattern", "")
                try:
                    if not re.search(pattern, param_value):
                        return False, f"Value '{param_value}' for '{param_name}' does not match allowed pattern", rule_name
                except re.error as e:
                    logger.error(f"Invalid regex pattern in policy: {pattern}", extra={"error": str(e)})
                    return False, f"Server configuration error (invalid regex in rule '{rule_name}')", rule_name
            elif match_type == "regex_deny":
                pattern = rule.get("pattern", "")
                try:
                    if re.search(pattern, param_value):
                        return False, f"Value '{param_value}' for '{param_name}' matched a deny pattern", rule_name
                except re.error as e:
                    logger.error(f"Invalid regex pattern in policy: {pattern}", extra={"error": str(e)})
                    return False, f"Server configuration error (invalid regex in rule '{rule_name}')", rule_name

        return True, "Passed all policy checks", "policy_pass"

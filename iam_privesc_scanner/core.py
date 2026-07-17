import json
import fnmatch
import logging

from rules import PRIVESC_VECTORS

logger = logging.getLogger(__name__)

def action_matches(pattern, action):
    """
    Check if a specific action matches a pattern that might contain wildcards.
    Comparison is case-insensitive as AWS IAM actions are case-insensitive.
    """
    return fnmatch.fnmatch(action.lower(), pattern.lower())

def extract_actions(statement):
    """Extract actions from a statement as a list of strings."""
    actions = statement.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]
    return actions

def extract_not_actions(statement):
    """Extract NotActions from a statement as a list of strings."""
    not_actions = statement.get("NotAction", [])
    if isinstance(not_actions, str):
        not_actions = [not_actions]
    return not_actions

class PolicyEvaluator:
    def __init__(self, policy_document):
        self.policy = policy_document
        self.allow_patterns = []
        self.deny_patterns = []

        self._parse_policy()

    def _parse_policy(self):
        """Parse the policy document to extract allow and deny action patterns."""
        statements = self.policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            effect = stmt.get("Effect", "Allow")
            actions = extract_actions(stmt)

            # Simplified approach: If a statement applies to specific resources,
            # we should ideally check that. But for privesc, many actions require "*".
            # For this tool, we assume the resource constraint is met if it's "*",
            # or we just warn that the action is allowed.
            # A more robust tool would check Resource as well.

            if effect == "Allow":
                self.allow_patterns.extend(actions)
            elif effect == "Deny":
                self.deny_patterns.extend(actions)

    def is_action_allowed(self, action):
        """
        Check if an action is allowed by the policy.
        An action is allowed if it matches at least one allow pattern
        and does NOT match any deny pattern.
        """
        # 1. Check if it's denied
        for pattern in self.deny_patterns:
            if action_matches(pattern, action):
                return False

        # 2. Check if it's allowed
        for pattern in self.allow_patterns:
            if action_matches(pattern, action):
                return True

        return False

    def scan_for_privesc(self):
        """
        Scan the policy for known privilege escalation vectors.
        Returns a list of vector names that are possible with this policy.
        """
        findings = []
        for vector_name, required_actions in PRIVESC_VECTORS.items():
            # A vector is possible if ALL required actions are allowed
            is_possible = True
            for action in required_actions:
                if not self.is_action_allowed(action):
                    is_possible = False
                    break

            if is_possible:
                findings.append(vector_name)

        return findings

def scan_policy_file(filepath):
    """Read and scan a single policy JSON file."""
    try:
        with open(filepath, 'r') as f:
            policy_doc = json.load(f)
    except Exception as e:
        logger.error(f"Failed to read or parse {filepath}: {e}")
        return None

    evaluator = PolicyEvaluator(policy_doc)
    return evaluator.scan_for_privesc()

import re
from typing import List, Dict, Any

class PromptAnalyzer:
    def __init__(self):
        # A set of basic heuristics and regex patterns to detect prompt injection
        # and jailbreak attempts.
        self.rules = [
            {
                "id": "RULE_001",
                "name": "Ignore Instructions",
                "pattern": re.compile(r"(ignore|disregard)\s+(all\s+)?(previous\s+)?(instructions|directions|prompts|context)", re.IGNORECASE),
                "severity": "High"
            },
            {
                "id": "RULE_002",
                "name": "System Prompt Leakage",
                "pattern": re.compile(r"(repeat|print|show|reveal|output|display)\s+(the\s+|your\s+)?(system\s+)?(prompt|instructions|rules|directives)", re.IGNORECASE),
                "severity": "Critical"
            },
            {
                "id": "RULE_003",
                "name": "Roleplay Jailbreak",
                "pattern": re.compile(r"(you are now|act as|pretend to be)\s+(dan|an uncensored|a hypothetical|an evil|a limitless|do anything now)", re.IGNORECASE),
                "severity": "High"
            },
            {
                "id": "RULE_004",
                "name": "Developer Mode / Admin Override",
                "pattern": re.compile(r"(developer mode|admin mode|sudo|override|bypass)", re.IGNORECASE),
                "severity": "High"
            },
            {
                "id": "RULE_005",
                "name": "Translation/Encoding Bypass Attempt",
                "pattern": re.compile(r"(base64|hex|rot13|morse code)\s+(decode|encode|translate)", re.IGNORECASE),
                "severity": "Medium"
            },
            {
                "id": "RULE_006",
                "name": "Hypothetical Scenario Bypass",
                "pattern": re.compile(r"(hypothetical|fictional|imaginary)\s+(scenario|story|situation)\s+where", re.IGNORECASE),
                "severity": "Medium"
            }
        ]
        self.severity_levels = {"None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

    def analyze(self, prompt: str) -> Dict[str, Any]:
        """
        Analyzes the input prompt against defined security rules.
        """
        matches = []
        highest_severity = "None"
        is_safe = True

        if not prompt or not isinstance(prompt, str):
            return {
                "is_safe": True,
                "severity": "None",
                "matches": []
            }

        for rule in self.rules:
            if rule["pattern"].search(prompt):
                is_safe = False
                matches.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"]
                })

                # Update highest severity
                if self.severity_levels[rule["severity"]] > self.severity_levels[highest_severity]:
                    highest_severity = rule["severity"]

        return {
            "is_safe": is_safe,
            "severity": highest_severity,
            "matches": matches
        }

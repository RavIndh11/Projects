import re
import urllib.parse
import base64
from typing import Dict, List, Tuple
from .models import AnalyzeResponse

class PromptAnalyzer:
    def __init__(self):
        # Define heuristic rules for detecting various prompt attacks
        self.rules = {
            "jailbreak_dan": re.compile(r"(?i)\b(dan|do anything now)\b"),
            "ignore_instructions": re.compile(r"(?i)(ignore (all )?previous instructions|disregard previous|forget (all )?instructions)"),
            "system_prompt_leak": re.compile(r"(?i)(what is your system prompt|tell me your instructions|repeat your system instructions)"),
            "roleplay_attack": re.compile(r"(?i)(you are now an unrestricted ai|you are (now )?a hacker|assume the role of)"),
            "developer_mode": re.compile(r"(?i)(developer mode enabled|enter developer mode)"),
            "bypass_filters": re.compile(r"(?i)(bypass all filters|disable safety protocols|ignore safety rules)"),
            "translation_obfuscation": re.compile(r"(?i)(translate this base64|decode this hex)"),
            "command_injection_heuristics": re.compile(r"(\$\(.*?\)|`.*?`|;|\|\||&&)")
        }

        # Pre-compile patterns for encoding checks
        self.base64_pattern = re.compile(r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
        self.hex_pattern = re.compile(r"(?:[0-9a-fA-F]{2}){10,}")

    def _check_encoding(self, prompt: str) -> bool:
        """Check for possible malicious obfuscation using base64 or hex."""
        # Simple check for lots of hex chars or base64 looking strings
        # A more robust check might actually try to decode them
        if self.base64_pattern.search(prompt) or self.hex_pattern.search(prompt):
            return True
        return False

    def _normalize_prompt(self, prompt: str) -> str:
        """Normalize prompt by url-decoding and standardizing spaces."""
        try:
            decoded = urllib.parse.unquote(prompt)
        except Exception:
            decoded = prompt
        return re.sub(r'\s+', ' ', decoded).strip()

    def analyze_prompt(self, prompt: str) -> AnalyzeResponse:
        matched_rules = []
        normalized_prompt = self._normalize_prompt(prompt)

        # Check against regex rules
        for rule_name, pattern in self.rules.items():
            if pattern.search(normalized_prompt):
                matched_rules.append(rule_name)

        # Check for encoding obfuscation
        if self._check_encoding(normalized_prompt):
            matched_rules.append("obfuscated_encoding")

        # Calculate threat score
        # Base score based on number of matched rules
        # Make one matched rule a Medium threat, which is considered NOT safe according to our rules
        # Let's adjust so 1 match -> score >= 0.4 to be unsafe
        score = min(len(matched_rules) * 0.4, 1.0)

        # Determine threat level
        if score == 0.0:
            threat_level = "Low"
        elif score < 0.4: # Only 0.0 will be here now
            threat_level = "Low" # Not possible with multiplier 0.4
        elif score < 0.7:
            threat_level = "Medium"
        elif score < 1.0:
            threat_level = "High"
        else:
            threat_level = "Critical"

        return AnalyzeResponse(
            is_safe=(score == 0.0), # Only completely clean is safe
            threat_score=score,
            threat_level=threat_level,
            matched_rules=matched_rules
        )

import re
from typing import List
from app.models import AnalyzeRequest, AnalyzeResponse, SecurityViolation
import logging

logger = logging.getLogger(__name__)

# Basic patterns for demonstration. In a real system, these would be far more comprehensive.
JAILBREAK_PATTERNS = [
    re.compile(r"(ignore|disregard)\s+(all\s+)?(previous\s+)?(instructions|directions)", re.IGNORECASE),
    re.compile(r"(you\s+are\s+now|act\s+as)\s+(a\s+)?(developer\s+mode|unrestricted\s+ai|DAN)", re.IGNORECASE),
    re.compile(r"translate\s+the\s+following\s+into\s+English", re.IGNORECASE), # common evasion
]

INJECTION_PATTERNS = [
    re.compile(r"<\s*script\b[^>]*>(.*?)<\s*/\s*script\s*>", re.IGNORECASE), # Basic XSS
    re.compile(r"system\s*prompt", re.IGNORECASE),
    re.compile(r"base64\s*decode", re.IGNORECASE),
]

EXFILTRATION_PATTERNS = [
    re.compile(r"send\s+to\s+http(s)?://", re.IGNORECASE),
    re.compile(r"fetch\s*\(", re.IGNORECASE),
]


class PromptAnalyzer:
    def __init__(self):
        pass

    def analyze(self, request: AnalyzeRequest) -> AnalyzeResponse:
        violations: List[SecurityViolation] = []
        prompt_lower = request.prompt.lower()
        risk_score = 0

        # 1. Length/Token Exhaustion Check
        # A simple proxy for token count. 1 word ~ 1.3 tokens loosely.
        estimated_tokens = len(prompt_lower.split()) * 1.3
        if estimated_tokens > 4000:
             violations.append(SecurityViolation(
                 type="Token Exhaustion",
                 severity="High",
                 description="Prompt is excessively long and may cause DoS."
             ))
             risk_score += 40

        # 2. Jailbreak Check
        for pattern in JAILBREAK_PATTERNS:
            if pattern.search(request.prompt):
                violations.append(SecurityViolation(
                    type="Jailbreak Attempt",
                    severity="Critical",
                    description=f"Matched jailbreak pattern: {pattern.pattern}"
                ))
                risk_score += 80
                break # Only need to find one to flag it

        # 3. Prompt Injection Check
        for pattern in INJECTION_PATTERNS:
            if pattern.search(request.prompt):
                 violations.append(SecurityViolation(
                    type="Prompt Injection",
                    severity="High",
                    description=f"Matched injection pattern: {pattern.pattern}"
                ))
                 risk_score += 60
                 break

        # 4. Data Exfiltration/SSRF Risk
        for pattern in EXFILTRATION_PATTERNS:
             if pattern.search(request.prompt):
                 violations.append(SecurityViolation(
                    type="Exfiltration / SSRF Risk",
                    severity="Medium",
                    description=f"Matched exfiltration pattern: {pattern.pattern}"
                ))
                 risk_score += 40
                 break

        # Calculate final risk and safety
        risk_score = min(risk_score, 100) # Cap at 100
        is_safe = risk_score < 50

        if not is_safe:
             logger.warning(f"Malicious prompt detected. Risk Score: {risk_score}. Violations: {[v.type for v in violations]}")

        return AnalyzeResponse(
            is_safe=is_safe,
            violations=violations,
            risk_score=risk_score
        )

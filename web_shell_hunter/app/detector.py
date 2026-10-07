import math
import re
from typing import List, Dict, Any

# Pre-compile regex for common web shell signatures
# Optimizations: Cheap checks could be done first (string containment), but for a robust tool regexes are fine
SIGNATURES = {
    "eval_payload": re.compile(r'eval\s*\(\s*base64_decode\s*\('),
    "system_exec": re.compile(r'(system|shell_exec|exec|passthru|proc_open|popen)\s*\('),
    "cmd_shell": re.compile(r'cmd\.exe\s*/c'),
    "python_subprocess": re.compile(r'subprocess\.(Popen|run|call|check_output)\s*\('),
    "python_os_system": re.compile(r'os\.(system|popen)\s*\('),
    "jsp_runtime": re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\('),
    "php_assert": re.compile(r'assert\s*\(\s*\$_(POST|GET|REQUEST)'),
    "php_preg_replace": re.compile(r'preg_replace\s*\(\s*\'/.*/e\''),
    "python_pty": re.compile(r'pty\.spawn\s*\(')
}

def calculate_shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0.0

    entropy = 0.0
    length = len(data)
    occurrences = {}

    for char in data:
        occurrences[char] = occurrences.get(char, 0) + 1

    for count in occurrences.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy

def analyze_content(content: str, filename: str) -> Dict[str, Any]:
    """Analyzes content for web shell signatures and high entropy."""
    matched_signatures = []

    # 1. Signature Matching
    for sig_name, pattern in SIGNATURES.items():
        if pattern.search(content):
            matched_signatures.append(sig_name)

    # 2. Entropy Analysis
    entropy = calculate_shannon_entropy(content)

    # 3. Risk Scoring & Threat Level
    risk_score = 0.0
    is_malicious = False

    # Add risk for signatures
    risk_score += len(matched_signatures) * 30.0

    # Add risk for high entropy (typically Base64 or obfuscated payloads have > 5.5 entropy)
    if entropy > 5.5:
        # Scale entropy risk: 5.5 -> 0, 8.0 -> ~50
        entropy_risk = (entropy - 5.5) * 20.0
        risk_score += min(entropy_risk, 50.0)

    # Cap risk score at 100
    risk_score = min(risk_score, 100.0)

    if risk_score > 40.0 or len(matched_signatures) > 0:
        is_malicious = True

    threat_level = "Low"
    if risk_score > 80.0:
        threat_level = "Critical"
    elif risk_score > 60.0:
        threat_level = "High"
    elif risk_score > 30.0:
        threat_level = "Medium"

    return {
        "filename": filename,
        "is_malicious": is_malicious,
        "risk_score": round(risk_score, 2),
        "entropy": round(entropy, 2),
        "matched_signatures": matched_signatures,
        "threat_level": threat_level
    }

import math
import re
from typing import Dict, List, Tuple

SIGNATURES = {
    "eval_execution": re.compile(r"eval\s*\("),
    "base64_decode": re.compile(r"base64_decode\s*\("),
    "system_execution": re.compile(r"system\s*\("),
    "shell_exec": re.compile(r"shell_exec\s*\("),
    "passthru": re.compile(r"passthru\s*\("),
    "exec": re.compile(r"exec\s*\("),
    "assert": re.compile(r"assert\s*\("),
    "preg_replace_e": re.compile(r"preg_replace\s*\(\s*['\"].*?e['\"]"),
    "backticks": re.compile(r"`.*?`"),
    "php_info": re.compile(r"phpinfo\s*\("),
    "socket_create": re.compile(r"socket_create\s*\("),
}

def calculate_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy -= p_x * math.log(p_x, 2)
    return entropy

def analyze_content(content: str) -> Tuple[bool, float, List[str], str]:
    """
    Analyze the given content for web shell signatures and high entropy.
    Returns: (is_malicious, entropy, matched_signatures, severity)
    """
    entropy = calculate_entropy(content)
    matched_signatures = []

    for name, pattern in SIGNATURES.items():
        if pattern.search(content):
            matched_signatures.append(name)

    is_malicious = False
    severity = "Low"

    if len(matched_signatures) > 0 or entropy > 5.5:
        is_malicious = True

    if len(matched_signatures) >= 3 or (len(matched_signatures) >= 1 and entropy > 5.8):
        severity = "Critical"
    elif len(matched_signatures) == 2 or entropy > 5.5:
        severity = "High"
    elif len(matched_signatures) == 1:
        severity = "Medium"

    return is_malicious, entropy, matched_signatures, severity

import math
import re
from typing import List, Tuple
from app.models import Finding

# Common Web Shell Signatures
# Note: These are simplified for demonstration purposes.
SIGNATURES = {
    'php': [
        (re.compile(r'eval\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)'), 'Critical', 'PHP Eval Web Shell'),
        (re.compile(r'system\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)'), 'Critical', 'PHP System Web Shell'),
        (re.compile(r'shell_exec\s*\('), 'High', 'PHP Shell Exec Function'),
        (re.compile(r'base64_decode\s*\(\s*\$_'), 'High', 'PHP Base64 Decode from Request'),
        (re.compile(r'passthru\s*\('), 'High', 'PHP Passthru Function'),
        (re.compile(r'preg_replace\s*\(\s*["\']/.*/e["\']'), 'Critical', 'PHP preg_replace /e Exec'),
        (re.compile(r'assert\s*\(\s*\$_'), 'Critical', 'PHP Assert Web Shell'),
    ],
    'jsp': [
        (re.compile(r'Runtime\.getRuntime\(\)\.exec\('), 'Critical', 'JSP Runtime Exec'),
        (re.compile(r'ProcessBuilder\('), 'High', 'JSP ProcessBuilder'),
    ],
    'asp': [
        (re.compile(r'execute\s*request\('), 'Critical', 'ASP Execute Request'),
        (re.compile(r'eval\s*request\('), 'Critical', 'ASP Eval Request'),
    ]
}

def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

def scan_file_content(content: str, filename: str) -> List[Finding]:
    """Scan file content for web shell signatures and high entropy."""
    findings = []

    # 1. Signature Scanning
    ext = filename.split('.')[-1].lower() if '.' in filename else ''

    # Check specific extensions, or try all if unknown
    sigs_to_check = SIGNATURES.get(ext, [])
    if not sigs_to_check:
        # If unknown extension but we want to scan anyway, we could check all,
        # but for performance we might just check PHP as it's common.
        sigs_to_check = SIGNATURES.get('php', [])

    for regex, severity, description in sigs_to_check:
        match = regex.search(content)
        if match:
            findings.append(Finding(
                severity=severity,
                type="Known Signature",
                description=description,
                match_string=match.group(0)[:50] # Truncate for safety/log size
            ))

    # 2. Entropy Check (Obfuscation Detection)
    # Long strings with high entropy often indicate base64/hex encoded payloads
    # Let's find long continuous alphanumeric/base64-like strings
    long_strings = re.findall(r'[A-Za-z0-9+/=]{100,}', content)
    for s in long_strings:
        ent = calculate_shannon_entropy(s)
        if ent > 5.5: # Threshold for high entropy
            findings.append(Finding(
                severity="Med",
                type="Obfuscation",
                description=f"High entropy string detected (entropy: {ent:.2f})",
                match_string=s[:20] + "..." # Truncate
            ))
            # Don't flood findings if there are many long strings
            if len([f for f in findings if f.type == "Obfuscation"]) > 3:
                break

    return findings

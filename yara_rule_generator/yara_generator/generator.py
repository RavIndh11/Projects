import hashlib
from typing import Dict, List, Optional
import os

from .string_extractor import extract_strings, get_interesting_strings

def calculate_hashes(data: bytes) -> Dict[str, str]:
    """Calculates common hashes for the given data."""
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

def generate_yara_rule(
    rule_name: str,
    data: bytes,
    file_name: Optional[str] = None,
    author: str = "AutoGenerator"
) -> str:
    """
    Analyzes the data and generates a YARA rule.
    """
    # 1. Generate Metadata
    hashes = calculate_hashes(data)
    file_size = len(data)

    meta_lines = [
        f'        author = "{author}"',
        f'        description = "Auto-generated YARA rule for {file_name or "unknown file"}"',
    ]
    if file_name:
        meta_lines.append(f'        filename = "{file_name}"')

    meta_lines.extend([
        f'        md5 = "{hashes["md5"]}"',
        f'        sha1 = "{hashes["sha1"]}"',
        f'        sha256 = "{hashes["sha256"]}"',
        f'        size = {file_size}'
    ])

    # 2. Extract and format strings
    all_strings = extract_strings(data)
    interesting_strings = get_interesting_strings(all_strings)

    # We will pick the top 20 interesting strings to avoid massive rules
    max_strings = 20
    selected_strings = interesting_strings[:max_strings]

    string_lines = []
    for i, s in enumerate(selected_strings):
        # Escape backslashes and double quotes for valid YARA syntax
        escaped_string = s.replace("\\", "\\\\").replace('"', '\\"')
        string_lines.append(f'        $s{i} = "{escaped_string}" ascii wide')

    # 3. Create conditions
    condition_lines = []

    # Magic bytes (PE file check)
    if data.startswith(b"MZ"):
        condition_lines.append("uint16(0) == 0x5a4d")
    elif data.startswith(b"\x7fELF"):
        condition_lines.append("uint32(0) == 0x464c457f")

    # String conditions
    if len(selected_strings) > 0:
        # Require a certain number of strings to match
        match_threshold = max(1, len(selected_strings) // 3) # require 1/3rd of the strings
        condition_lines.append(f"{match_threshold} of ($s*)")
    else:
        # Fallback if no interesting strings found
        condition_lines.append("filesize < 100MB")

    # 4. Assemble Rule
    nl = "\n"

    rule = f"""rule {rule_name} {{
    meta:
{nl.join(meta_lines)}

    strings:
{nl.join(string_lines) if string_lines else '        // No interesting strings found'}

    condition:
        {' and '.join(condition_lines)}
}}
"""
    return rule

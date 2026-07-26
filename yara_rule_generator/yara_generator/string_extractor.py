import re
from typing import List, Set

def extract_strings(data: bytes, min_length: int = 6) -> Set[str]:
    """
    Extracts ASCII and UTF-16LE (wide) strings from binary data.
    """
    ascii_regex = rb"[\x20-\x7E]{" + str(min_length).encode() + rb",}"
    ascii_strings = [s.decode('ascii') for s in re.findall(ascii_regex, data)]

    # Match printable ascii followed by \x00, repeated
    utf16_regex = rb"(?:[\x20-\x7E]\x00){" + str(min_length).encode() + rb",}"
    utf16_strings = []
    for s in re.findall(utf16_regex, data):
        try:
            utf16_strings.append(s.decode('utf-16le'))
        except UnicodeDecodeError:
            pass

    return set(ascii_strings + utf16_strings)

def get_interesting_strings(strings: Set[str]) -> List[str]:
    """
    Filters a set of strings for interesting patterns like URLs, IPs,
    emails, and common suspicious Windows API calls or registry keys.
    """
    interesting = []

    # Patterns to match interesting artifacts
    patterns = {
        "url": re.compile(r"https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"),
        "ip": re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
        "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        "windows_path": re.compile(r"[a-zA-Z]:\\[a-zA-Z0-9_\-\\]+"),
        "api_call": re.compile(r"\b(VirtualAlloc|CreateProcessA|CreateProcessW|CreateRemoteThread|WriteProcessMemory|LoadLibraryA|LoadLibraryW|GetProcAddress|CreateFileW|RegOpenKeyExA|HttpSendRequestA|InternetOpenA)\b"),
        "registry": re.compile(r"(HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[a-zA-Z0-9_\-\\]+")
    }

    for s in strings:
        for cat, pattern in patterns.items():
            if pattern.search(s):
                interesting.append(s)
                break

    # Sort for deterministic output
    return sorted(interesting)

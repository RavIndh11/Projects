import re

# Regex patterns for detecting common web attacks in log URLs/Payloads.
# These patterns are simplified for demonstration purposes and balance detection
# capability with avoiding excessive false positives on standard logs.

ATTACK_PATTERNS = {
    "SQL_INJECTION": re.compile(
        r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from|drop\s+table|--\s*$|;\s*(sleep|waitfor)|['\"]\s*(or|and)\s*['\"]\d['\"]\s*=\s*['\"]\d)",
        re.IGNORECASE,
    ),
    "CROSS_SITE_SCRIPTING": re.compile(
        r"(?i)(<script.*?>.*?</script>|javascript:|on(load|error|click|mouseover|focus|blur)\s*=|<.*?%00.*?>|alert\s*\(|document\.cookie|window\.location)",
        re.IGNORECASE,
    ),
    "PATH_TRAVERSAL": re.compile(
        r"(?i)(\.\./\.\./|%2e%2e%2f|%2e%2e/|\.\.%2f|/etc/passwd|/windows/win\.ini|/boot\.ini|cmd\.exe|/bin/sh)",
        re.IGNORECASE,
    ),
}

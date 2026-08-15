## 2025-02-28 - Regex Catastrophic Backtracking in Log Parsing
**Learning:** Python's `re` module can suffer from massive performance degradation due to non-greedy wildcards (e.g., `.*?`) when parsing structured formats like access logs. This creates an unoptimized cold path where parsing can take several times longer than necessary.
**Action:** When extracting fields from string-based formats, replace non-greedy wildcards with negated character classes (e.g., `[^\]]+` or `[^"]*?`) and anchor the string with `^` to prevent heavy backtracking overhead, significantly improving parse time per line.

## 2024-05-24 - Optimization: Skip regex evaluations for placeholder log fields
**Learning:** In standard Apache/Nginx logs, missing fields like referrers or user agents are often represented by a single hyphen (`-`). Passing these single hyphens to complex regular expressions for attack detection introduces significant overhead.
**Action:** Before running expensive regex searches on log fields, add a simple check (`if not target or target == "-": continue`) to skip evaluation for empty or placeholder fields, leading to noticeable performance gains on large files without affecting detection logic.

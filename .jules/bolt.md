## 2025-02-28 - Regex Catastrophic Backtracking in Log Parsing
**Learning:** Python's `re` module can suffer from massive performance degradation due to non-greedy wildcards (e.g., `.*?`) when parsing structured formats like access logs. This creates an unoptimized cold path where parsing can take several times longer than necessary.
**Action:** When extracting fields from string-based formats, replace non-greedy wildcards with negated character classes (e.g., `[^\]]+` or `[^"]*?`) and anchor the string with `^` to prevent heavy backtracking overhead, significantly improving parse time per line.

## 2025-02-28 - Pre-compiling regexes in hot paths
**Learning:** Instantiating and compiling regular expressions inside frequently called methods (e.g. prompt analysis for LLMs) causes unnecessary overhead. Pre-compiling static patterns in `__init__` and utilizing `pattern.search()` instead of `re.search()` significantly reduces the computational cost of repetitive matching.
**Action:** Always pre-compile static regex rules and patterns in class initializers (`__init__`) or at the module level to avoid compiling the same pattern multiple times in an application's hot path.

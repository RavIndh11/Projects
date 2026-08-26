## 2025-02-28 - Regex Catastrophic Backtracking in Log Parsing
**Learning:** Python's `re` module can suffer from massive performance degradation due to non-greedy wildcards (e.g., `.*?`) when parsing structured formats like access logs. This creates an unoptimized cold path where parsing can take several times longer than necessary.
**Action:** When extracting fields from string-based formats, replace non-greedy wildcards with negated character classes (e.g., `[^\]]+` or `[^"]*?`) and anchor the string with `^` to prevent heavy backtracking overhead, significantly improving parse time per line.
## 2024-05-24 - Python Hot Loop Optimization

**Learning:** In heavily executed log parsing loops (like standard access logs), constructing temporary lists and calling `dict.items()` inside the loop introduces significant overhead. Replacing `targets = [a, b, c]` and `for k, v in PATTERNS.items()` with a pre-calculated class-level tuple and explicitly ordered sequential evaluations avoids thousands of small, unnecessary allocations and yields a 10%+ performance boost.

**Action:** Whenever iterating over dicts or building transient lists within hot paths (especially >10k iterations), hoist transformations to the module or class level and flatten nested loops to explicit conditional blocks if small enough.
## 2024-05-25 - Safe Log Regex Optimization
**Learning:** While replacing non-greedy `.*?` with strict negated character classes like `[^"]+` improves regex performance, doing so blindly on HTTP path matching can break if the logs contain spaces (common in SQL injection payloads). The regex engine must correctly handle whitespace inside malicious paths while still skipping backtracking in safe fields.
**Action:** Optimize surrounding log fields (IP, timestamps, status codes, size) using strict negated classes (`[^ ]+`), but keep safe, slightly flexible quantifiers (`[^"]+?`) for fields that might contain unexpected syntax to preserve security scanning capability while still securing a 20%+ performance win.

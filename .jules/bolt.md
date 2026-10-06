## 2025-02-28 - Regex Catastrophic Backtracking in Log Parsing
**Learning:** Python's `re` module can suffer from massive performance degradation due to non-greedy wildcards (e.g., `.*?`) when parsing structured formats like access logs. This creates an unoptimized cold path where parsing can take several times longer than necessary.
**Action:** When extracting fields from string-based formats, replace non-greedy wildcards with negated character classes (e.g., `[^\]]+` or `[^"]*?`) and anchor the string with `^` to prevent heavy backtracking overhead, significantly improving parse time per line.
## 2024-05-24 - Python Hot Loop Optimization

**Learning:** In heavily executed log parsing loops (like standard access logs), constructing temporary lists and calling `dict.items()` inside the loop introduces significant overhead. Replacing `targets = [a, b, c]` and `for k, v in PATTERNS.items()` with a pre-calculated class-level tuple and explicitly ordered sequential evaluations avoids thousands of small, unnecessary allocations and yields a 10%+ performance boost.

**Action:** Whenever iterating over dicts or building transient lists within hot paths (especially >10k iterations), hoist transformations to the module or class level and flatten nested loops to explicit conditional blocks if small enough.
## 2024-05-24 - Fast regex filtering
**Learning:** Short-circuiting expensive regex searches in hot loops with string membership checks significantly improves performance.
**Action:** Prioritize evaluating computationally cheap checks before expensive operations in Python hot loops.
## 2025-02-28 - Regex Pre-compilation and Short-Circuiting in Log Analysis
**Learning:** In applications like log analyzers that process large volumes of entries (e.g., `analyze_endpoints`), executing uncompiled `re.match` within nested hot loops and performing cheap string comparisons *after* expensive regex searches severely degrades performance (processing 50k logs took ~3.3s).
**Action:** By explicitly pre-compiling regex patterns outside the loop, moving computationally cheap checks (like list membership `log.method in doc_path.methods`) before expensive regex evaluations to enable short-circuiting, and adding dictionary caching for repeated identical log paths, the execution time was reduced by >90% (to ~0.2s for 50k logs). Always pre-compile regexes and order loop conditionals by computational cost.

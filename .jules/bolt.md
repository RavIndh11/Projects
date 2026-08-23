## 2025-02-28 - Regex Catastrophic Backtracking in Log Parsing
**Learning:** Python's `re` module can suffer from massive performance degradation due to non-greedy wildcards (e.g., `.*?`) when parsing structured formats like access logs. This creates an unoptimized cold path where parsing can take several times longer than necessary.
**Action:** When extracting fields from string-based formats, replace non-greedy wildcards with negated character classes (e.g., `[^\]]+` or `[^"]*?`) and anchor the string with `^` to prevent heavy backtracking overhead, significantly improving parse time per line.
## 2024-05-24 - Python Hot Loop Optimization

**Learning:** In heavily executed log parsing loops (like standard access logs), constructing temporary lists and calling `dict.items()` inside the loop introduces significant overhead. Replacing `targets = [a, b, c]` and `for k, v in PATTERNS.items()` with a pre-calculated class-level tuple and explicitly ordered sequential evaluations avoids thousands of small, unnecessary allocations and yields a 10%+ performance boost.

**Action:** Whenever iterating over dicts or building transient lists within hot paths (especially >10k iterations), hoist transformations to the module or class level and flatten nested loops to explicit conditional blocks if small enough.
## 2025-02-28 - Regex and Loop Optimization in Log Analysis
**Learning:** Checking each entry in a large list of logs against a list of regular expressions without compilation and cache, like in `api_shadow_hunter/app/analyzer.py`, causes massive performance overhead due to recompilation on the fly, redundant method checking, and identical O(M*N) string evaluations on duplicated log paths.
**Action:** Always pre-compile regexes, group them (e.g., by HTTP method) to filter the search space, and add an exact string-match cache mapping `(log.method, log.path)` to its computed regex result, reducing typical O(N) regex checks to O(1) dictionary lookups.

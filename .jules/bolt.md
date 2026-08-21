## 2025-02-28 - Regex Catastrophic Backtracking in Log Parsing
**Learning:** Python's `re` module can suffer from massive performance degradation due to non-greedy wildcards (e.g., `.*?`) when parsing structured formats like access logs. This creates an unoptimized cold path where parsing can take several times longer than necessary.
**Action:** When extracting fields from string-based formats, replace non-greedy wildcards with negated character classes (e.g., `[^\]]+` or `[^"]*?`) and anchor the string with `^` to prevent heavy backtracking overhead, significantly improving parse time per line.
## 2024-05-24 - Python Hot Loop Optimization

**Learning:** In heavily executed log parsing loops (like standard access logs), constructing temporary lists and calling `dict.items()` inside the loop introduces significant overhead. Replacing `targets = [a, b, c]` and `for k, v in PATTERNS.items()` with a pre-calculated class-level tuple and explicitly ordered sequential evaluations avoids thousands of small, unnecessary allocations and yields a 10%+ performance boost.

**Action:** Whenever iterating over dicts or building transient lists within hot paths (especially >10k iterations), hoist transformations to the module or class level and flatten nested loops to explicit conditional blocks if small enough.
## 2024-05-23 - Pre-compiling Regex in Tight Loops
**Learning:** In `api_shadow_hunter`, dynamically compiling regex strings using `re.match(string, ...)` inside an O(N*M) loop (where N is the number of logs and M is the number of endpoints) creates a significant performance bottleneck. Even though Python's `re` module has an internal cache, the overhead of checking the cache and creating the match object repeatedly is high when iterating over thousands of logs.
**Action:** Always pre-compile regular expressions using `re.compile()` before entering tight loops that perform pattern matching against large datasets.

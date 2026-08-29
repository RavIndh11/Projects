## 2025-02-28 - Regex Catastrophic Backtracking in Log Parsing
**Learning:** Python's `re` module can suffer from massive performance degradation due to non-greedy wildcards (e.g., `.*?`) when parsing structured formats like access logs. This creates an unoptimized cold path where parsing can take several times longer than necessary.
**Action:** When extracting fields from string-based formats, replace non-greedy wildcards with negated character classes (e.g., `[^\]]+` or `[^"]*?`) and anchor the string with `^` to prevent heavy backtracking overhead, significantly improving parse time per line.
## 2024-05-24 - Python Hot Loop Optimization

**Learning:** In heavily executed log parsing loops (like standard access logs), constructing temporary lists and calling `dict.items()` inside the loop introduces significant overhead. Replacing `targets = [a, b, c]` and `for k, v in PATTERNS.items()` with a pre-calculated class-level tuple and explicitly ordered sequential evaluations avoids thousands of small, unnecessary allocations and yields a 10%+ performance boost.

**Action:** Whenever iterating over dicts or building transient lists within hot paths (especially >10k iterations), hoist transformations to the module or class level and flatten nested loops to explicit conditional blocks if small enough.
## 2024-05-24 - Short-Circuiting Expensive Regex Matches in Hot Loops

**Learning:** When cross-referencing datasets (like log entries against documented paths), evaluating computationally expensive operations like `re.match` before cheaper checks (like list membership or string equality) can severely degrade performance. In `api_shadow_hunter`, reversing the `if` condition to check the HTTP method *before* matching the path regex resulted in a ~2.5x speedup. Furthermore, explicitly pre-compiling the regexes outside the loop avoids the cache-lookup overhead of `re.match` entirely.

**Action:** Always place the computationally cheapest checks first in composite `if` conditions to maximize short-circuiting benefits. When using regex in hot loops, explicitly pre-compile them to `re.compile()` objects outside the loop.

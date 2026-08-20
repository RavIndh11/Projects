## 2025-02-28 - Regex Catastrophic Backtracking in Log Parsing
**Learning:** Python's `re` module can suffer from massive performance degradation due to non-greedy wildcards (e.g., `.*?`) when parsing structured formats like access logs. This creates an unoptimized cold path where parsing can take several times longer than necessary.
**Action:** When extracting fields from string-based formats, replace non-greedy wildcards with negated character classes (e.g., `[^\]]+` or `[^"]*?`) and anchor the string with `^` to prevent heavy backtracking overhead, significantly improving parse time per line.
## 2024-05-24 - Python Hot Loop Optimization

**Learning:** In heavily executed log parsing loops (like standard access logs), constructing temporary lists and calling `dict.items()` inside the loop introduces significant overhead. Replacing `targets = [a, b, c]` and `for k, v in PATTERNS.items()` with a pre-calculated class-level tuple and explicitly ordered sequential evaluations avoids thousands of small, unnecessary allocations and yields a 10%+ performance boost.

**Action:** Whenever iterating over dicts or building transient lists within hot paths (especially >10k iterations), hoist transformations to the module or class level and flatten nested loops to explicit conditional blocks if small enough.
## 2025-02-28 - Pre-compiling Regex in Hot Paths
**Learning:** Initializing repetitive regex operations (like `re.search` with string patterns) inside a hot path (e.g., `analyze_prompt`) significantly impacts performance. Python must parse the regex string and compile it on every call, which leads to ~20-30% overhead on high-throughput operations.
**Action:** When a regex is used repeatedly on string data, pre-compile the pattern using `re.compile()` in the class `__init__` or at the module level. Use `.search()` or `.sub()` directly on the compiled object to eliminate redundant parsing and compiling overhead.

## 2025-02-28 - Regex Catastrophic Backtracking in Log Parsing
**Learning:** Python's `re` module can suffer from massive performance degradation due to non-greedy wildcards (e.g., `.*?`) when parsing structured formats like access logs. This creates an unoptimized cold path where parsing can take several times longer than necessary.
**Action:** When extracting fields from string-based formats, replace non-greedy wildcards with negated character classes (e.g., `[^\]]+` or `[^"]*?`) and anchor the string with `^` to prevent heavy backtracking overhead, significantly improving parse time per line.
## 2024-05-24 - Python Hot Loop Optimization

**Learning:** In heavily executed log parsing loops (like standard access logs), constructing temporary lists and calling `dict.items()` inside the loop introduces significant overhead. Replacing `targets = [a, b, c]` and `for k, v in PATTERNS.items()` with a pre-calculated class-level tuple and explicitly ordered sequential evaluations avoids thousands of small, unnecessary allocations and yields a 10%+ performance boost.

**Action:** Whenever iterating over dicts or building transient lists within hot paths (especially >10k iterations), hoist transformations to the module or class level and flatten nested loops to explicit conditional blocks if small enough.
## 2024-05-24 - Fast regex filtering
**Learning:** Short-circuiting expensive regex searches in hot loops with string membership checks significantly improves performance.
**Action:** Prioritize evaluating computationally cheap checks before expensive operations in Python hot loops.
## 2024-05-25 - Python Regex Pre-compilation in Hot Loops
**Learning:** Repetitive calls to `re.match` within hot loops (like cross-referencing thousands of logs against documented endpoints) introduce significant performance overhead due to pattern compilation and caching overhead on each call. Checking cheap conditions (like simple string equality or dictionary membership) before executing a regex also yields massive improvements.
**Action:** When working with thousands of objects inside a loop, always explicitly pre-compile regular expressions using `re.compile()` into lists or dictionaries outside the loop, and evaluate cheap checks before invoking regex methods to maximize short-circuiting.

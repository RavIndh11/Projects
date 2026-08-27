## 2025-02-28 - Regex Catastrophic Backtracking in Log Parsing
**Learning:** Python's `re` module can suffer from massive performance degradation due to non-greedy wildcards (e.g., `.*?`) when parsing structured formats like access logs. This creates an unoptimized cold path where parsing can take several times longer than necessary.
**Action:** When extracting fields from string-based formats, replace non-greedy wildcards with negated character classes (e.g., `[^\]]+` or `[^"]*?`) and anchor the string with `^` to prevent heavy backtracking overhead, significantly improving parse time per line.
## 2024-05-24 - Python Hot Loop Optimization

**Learning:** In heavily executed log parsing loops (like standard access logs), constructing temporary lists and calling `dict.items()` inside the loop introduces significant overhead. Replacing `targets = [a, b, c]` and `for k, v in PATTERNS.items()` with a pre-calculated class-level tuple and explicitly ordered sequential evaluations avoids thousands of small, unnecessary allocations and yields a 10%+ performance boost.

**Action:** Whenever iterating over dicts or building transient lists within hot paths (especially >10k iterations), hoist transformations to the module or class level and flatten nested loops to explicit conditional blocks if small enough.
## 2025-02-28 - Regex compilation in hot loops
**Learning:** Calling `re.match` repeatedly inside a hot double-loop incurs internal lookup and processing overhead, even when Python caches the compiled regexes. Evaluating expensive operations like regex matching before simpler subset evaluations wastes computing cycles.
**Action:** When cross-referencing logs against a list of paths using regex inside a loop, pre-compile the regex objects via `re.compile()` into a tuple/list beforehand. Also, convert list-based string checks to sets and execute `in set()` evaluations before `regex.match()` checks, ensuring early exit for non-matching payloads and yielding significant (~3x) speedup.

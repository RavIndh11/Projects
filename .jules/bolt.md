## 2025-02-28 - Regex Catastrophic Backtracking in Log Parsing
**Learning:** Python's `re` module can suffer from massive performance degradation due to non-greedy wildcards (e.g., `.*?`) when parsing structured formats like access logs. This creates an unoptimized cold path where parsing can take several times longer than necessary.
**Action:** When extracting fields from string-based formats, replace non-greedy wildcards with negated character classes (e.g., `[^\]]+` or `[^"]*?`) and anchor the string with `^` to prevent heavy backtracking overhead, significantly improving parse time per line.
## 2024-05-24 - Python Hot Loop Optimization

**Learning:** In heavily executed log parsing loops (like standard access logs), constructing temporary lists and calling `dict.items()` inside the loop introduces significant overhead. Replacing `targets = [a, b, c]` and `for k, v in PATTERNS.items()` with a pre-calculated class-level tuple and explicitly ordered sequential evaluations avoids thousands of small, unnecessary allocations and yields a 10%+ performance boost.

**Action:** Whenever iterating over dicts or building transient lists within hot paths (especially >10k iterations), hoist transformations to the module or class level and flatten nested loops to explicit conditional blocks if small enough.

## 2025-02-28 - Regex Recompilation in Hot Loops

**Learning:** Re-compiling multiple regular expressions inside a function that is called repeatedly or loops over a large dataset (like checking millions of extracted strings) causes measurable performance degradation. In Python, while `re` module does have a small internal cache for recently compiled patterns, recreating a dictionary and calling `re.compile` or implicitly relying on the cache in a hot loop adds unnecessary dictionary lookups and object overhead.

**Action:** Whenever a function executes string pattern matching over large arrays or is called frequently, hoist the dictionary of compiled regex patterns (e.g., `re.compile()`) to the module level. Furthermore, if you only need to iterate over the regex objects (e.g., `patterns.values()`), pre-calculate a tuple of those values at the module level to avoid the `.values()` call overhead within the loop.

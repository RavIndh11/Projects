## 2025-02-28 - Regex Catastrophic Backtracking in Log Parsing
**Learning:** Python's `re` module can suffer from massive performance degradation due to non-greedy wildcards (e.g., `.*?`) when parsing structured formats like access logs. This creates an unoptimized cold path where parsing can take several times longer than necessary.
**Action:** When extracting fields from string-based formats, replace non-greedy wildcards with negated character classes (e.g., `[^\]]+` or `[^"]*?`) and anchor the string with `^` to prevent heavy backtracking overhead, significantly improving parse time per line.

## 2025-03-05 - Redundant regex compilation in loop
**Learning:** Using `re.match(string_pattern, string)` inside a hot loop forces Python's regex engine to look up or compile the regex pattern on every iteration, leading to significant overhead. This is especially true when matching many logs against many dynamic OpenAPI paths.
**Action:** When a regular expression pattern is known and reused across many iterations, pre-compile it using `re.compile(pattern)` before the loop and use `compiled_pattern.match(string)` inside the loop. This can yield ~100x speedups for large scale log analysis.

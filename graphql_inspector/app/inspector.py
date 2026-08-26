import re
from typing import Dict, Any

class GraphQLInspector:
    def __init__(self, max_depth: int = 5, max_aliases: int = 10):
        self.max_depth = max_depth
        self.max_aliases = max_aliases

    def analyze_query(self, query: str) -> Dict[str, Any]:
        """Analyzes a GraphQL query for potential security risks."""
        if not query or not isinstance(query, str):
            return {
                "is_safe": False,
                "findings": ["Invalid query format"],
                "metrics": {"depth": 0, "aliases": 0, "has_introspection": False}
            }

        findings = []
        is_safe = True

        # 1. Introspection Check
        has_introspection = self._has_introspection(query)
        if has_introspection:
            findings.append("Introspection query detected")
            is_safe = False

        # 2. Depth Check
        depth = self._calculate_depth(query)
        if depth > self.max_depth:
            findings.append(f"Excessive nesting depth detected (depth: {depth}, max: {self.max_depth})")
            is_safe = False

        # 3. Alias Check
        aliases = self._count_aliases(query)
        if aliases > self.max_aliases:
            findings.append(f"Excessive aliases detected (count: {aliases}, max: {self.max_aliases})")
            is_safe = False

        return {
            "is_safe": is_safe,
            "findings": findings,
            "metrics": {
                "depth": depth,
                "aliases": aliases,
                "has_introspection": has_introspection
            }
        }

    def _has_introspection(self, query: str) -> bool:
        """Detects if the query is an introspection query."""
        return bool(re.search(r'\b__(schema|type)\b', query))

    def _calculate_depth(self, query: str) -> int:
        """Calculates the maximum nesting depth of the query."""
        current_depth = 0
        max_depth = 0
        for char in query:
            if char == '{':
                current_depth += 1
                if current_depth > max_depth:
                    max_depth = current_depth
            elif char == '}':
                current_depth = max(0, current_depth - 1)
        return max_depth

    def _count_aliases(self, query: str) -> int:
        """Estimates the number of aliases in the query."""
        # Strip strings to avoid false positives inside quotes
        query_no_strings = re.sub(r'"(?:\\.|[^"\\])*"', '', query)

        # Strip arguments to avoid counting colons in arguments
        # This handles non-nested parentheses reasonably well
        query_no_args = re.sub(r'\([^)]*\)', '', query_no_strings)

        # Count remaining colons
        return query_no_args.count(':')

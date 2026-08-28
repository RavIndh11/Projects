from graphql.language.visitor import Visitor, visit
from graphql.language.parser import parse
from graphql.error.syntax_error import GraphQLSyntaxError
from typing import Dict, Any, Tuple

class SecurityVisitor(Visitor):
    def __init__(self):
        self.max_depth = 0
        self.current_depth = 0
        self.alias_count = 0
        self.is_introspection = False
        self.field_count = 0
        super().__init__()

    def enter_field(self, node, key, parent, path, ancestors):
        self.current_depth += 1
        self.field_count += 1
        if self.current_depth > self.max_depth:
            self.max_depth = self.current_depth
        if node.alias:
            self.alias_count += 1
        if node.name.value.startswith('__'):
            self.is_introspection = True

    def leave_field(self, node, key, parent, path, ancestors):
        self.current_depth -= 1

def analyze_query(query: str, max_depth_limit: int = 10, max_alias_limit: int = 10, allow_introspection: bool = False) -> Dict[str, Any]:
    """Analyzes a GraphQL query for security risks."""
    try:
        ast = parse(query)
    except GraphQLSyntaxError as e:
        return {
            "status": "error",
            "message": f"Syntax Error: {str(e)}",
            "risk_score": 0,
            "severity": "Low"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Parsing Error: {str(e)}",
            "risk_score": 0,
            "severity": "Low"
        }

    visitor = SecurityVisitor()
    try:
        visit(ast, visitor)
    except Exception as e:
         return {
            "status": "error",
            "message": f"Analysis Error: {str(e)}",
            "risk_score": 0,
            "severity": "Low"
        }

    issues = []
    risk_score = 0
    severity = "Low"

    # Evaluate Depth
    if visitor.max_depth > max_depth_limit:
        issues.append(f"Query depth ({visitor.max_depth}) exceeds limit ({max_depth_limit}). Potential DoS.")
        risk_score += (visitor.max_depth - max_depth_limit) * 10

    # Evaluate Aliases
    if visitor.alias_count > max_alias_limit:
        issues.append(f"Alias count ({visitor.alias_count}) exceeds limit ({max_alias_limit}). Potential DoS.")
        risk_score += (visitor.alias_count - max_alias_limit) * 5

    # Evaluate Introspection
    if visitor.is_introspection and not allow_introspection:
        issues.append("Introspection query detected. Potential Information Disclosure.")
        risk_score += 50

    if risk_score > 70:
        severity = "Critical"
    elif risk_score > 40:
        severity = "High"
    elif risk_score > 15:
        severity = "Medium"

    return {
        "status": "success",
        "depth": visitor.max_depth,
        "aliases": visitor.alias_count,
        "introspection": visitor.is_introspection,
        "field_count": visitor.field_count,
        "issues": issues,
        "risk_score": risk_score,
        "severity": severity,
        "is_safe": len(issues) == 0
    }

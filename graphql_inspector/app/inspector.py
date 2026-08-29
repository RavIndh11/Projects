from typing import List, Dict, Any, Optional
from graphql import parse, GraphQLError
from graphql.language.visitor import Visitor, visit
from graphql.language.ast import Node, FieldNode, FragmentSpreadNode, FragmentDefinitionNode

class SecurityViolation:
    def __init__(self, issue_type: str, message: str, severity: str):
        self.issue_type = issue_type
        self.message = message
        self.severity = severity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "issue_type": self.issue_type,
            "message": self.message,
            "severity": self.severity
        }

class GraphQLSecurityVisitor(Visitor):
    def __init__(self, max_depth: int = 5, max_aliases: int = 3, allow_introspection: bool = False):
        super().__init__()
        self.max_depth = max_depth
        self.max_aliases = max_aliases
        self.allow_introspection = allow_introspection

        self.violations: List[SecurityViolation] = []

        self.current_depth = 0
        self.alias_count = 0

        # Track fragments to prevent infinite loops in fragment spreads (though not strictly evaluating them deeply yet,
        # we focus on basic depth and aliases)

    def enter_field(self, node: FieldNode, key: Any, parent: Any, path: List[Any], ancestors: List[Any]) -> None:
        self.current_depth += 1
        if self.current_depth > self.max_depth:
            # Check if we already added a depth violation to prevent multiple entries for deeper nodes
            if not any(v.issue_type == "Max Depth Exceeded" for v in self.violations):
                self.violations.append(
                    SecurityViolation(
                        issue_type="Max Depth Exceeded",
                        message=f"Query depth exceeds maximum allowed depth of {self.max_depth}",
                        severity="High"
                    )
                )

        if node.alias:
            self.alias_count += 1
            if self.alias_count > self.max_aliases:
                self.violations.append(
                    SecurityViolation(
                        issue_type="Max Aliases Exceeded",
                        message=f"Query aliases exceed maximum allowed aliases of {self.max_aliases}",
                        severity="Medium"
                    )
                )

        if not self.allow_introspection:
            field_name = node.name.value
            if field_name in ["__schema", "__type", "__typename"]:
                self.violations.append(
                    SecurityViolation(
                        issue_type="Introspection Query",
                        message=f"Introspection field '{field_name}' is not allowed",
                        severity="High"
                    )
                )

    def leave_field(self, node: FieldNode, key: Any, parent: Any, path: List[Any], ancestors: List[Any]) -> None:
        self.current_depth -= 1

class GraphQLInspector:
    def __init__(self, max_depth: int = 5, max_aliases: int = 3, allow_introspection: bool = False):
        self.max_depth = max_depth
        self.max_aliases = max_aliases
        self.allow_introspection = allow_introspection

    def inspect(self, query: str) -> Dict[str, Any]:
        result = {
            "is_valid": True,
            "violations": [],
            "error": None
        }

        try:
            ast = parse(query)
        except GraphQLError as e:
            result["is_valid"] = False
            result["error"] = str(e)
            return result
        except Exception as e:
            result["is_valid"] = False
            result["error"] = f"Failed to parse query: {str(e)}"
            return result

        visitor = GraphQLSecurityVisitor(
            max_depth=self.max_depth,
            max_aliases=self.max_aliases,
            allow_introspection=self.allow_introspection
        )

        try:
            visit(ast, visitor)
        except Exception as e:
            result["is_valid"] = False
            result["error"] = f"Failed to traverse query: {str(e)}"
            return result

        if visitor.violations:
            result["is_valid"] = False
            result["violations"] = [v.to_dict() for v in visitor.violations]

        return result

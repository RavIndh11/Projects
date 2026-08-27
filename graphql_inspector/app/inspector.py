import re
from typing import List, Dict, Any, Tuple
from graphql import parse, validate, specified_rules
from graphql.language.ast import DocumentNode, OperationDefinitionNode, FieldNode, FragmentDefinitionNode, FragmentSpreadNode
import graphql

class GraphQLInspector:
    def __init__(self, max_depth: int = 5, max_aliases: int = 10):
        self.max_depth = max_depth
        self.max_aliases = max_aliases

    def inspect(self, query: str) -> Tuple[str, List[Dict[str, str]], Dict[str, Any]]:
        flags = []
        metrics = {"depth": 0, "aliases": 0, "introspection": False}

        try:
            document = parse(query)
        except Exception as e:
            flags.append({
                "rule_id": "GRAPHQL_PARSE_ERROR",
                "description": f"Failed to parse GraphQL query: {str(e)}",
                "severity": "High"
            })
            return "High", flags, metrics

        fragments = self._get_fragments(document)

        # Check introspection
        if self._has_introspection(document):
            flags.append({
                "rule_id": "GRAPHQL_INTROSPECTION",
                "description": "Introspection query detected",
                "severity": "Medium"
            })
            metrics["introspection"] = True

        # Check depth and aliases
        max_query_depth = 0
        total_aliases = 0

        for definition in document.definitions:
            if isinstance(definition, OperationDefinitionNode):
                depth = self._calculate_depth(definition, fragments)
                max_query_depth = max(max_query_depth, depth)

                aliases = self._count_aliases(definition, fragments)
                total_aliases += aliases

        metrics["depth"] = max_query_depth
        metrics["aliases"] = total_aliases

        if max_query_depth > self.max_depth:
            flags.append({
                "rule_id": "GRAPHQL_EXCESSIVE_DEPTH",
                "description": f"Query depth ({max_query_depth}) exceeds maximum allowed ({self.max_depth})",
                "severity": "Critical"
            })

        if total_aliases > self.max_aliases:
            flags.append({
                "rule_id": "GRAPHQL_EXCESSIVE_ALIASES",
                "description": f"Query aliases ({total_aliases}) exceed maximum allowed ({self.max_aliases})",
                "severity": "High"
            })

        risk_score = self._calculate_risk(flags)
        return risk_score, flags, metrics

    def _get_fragments(self, document: DocumentNode) -> Dict[str, FragmentDefinitionNode]:
        fragments = {}
        for definition in document.definitions:
            if isinstance(definition, FragmentDefinitionNode):
                fragments[definition.name.value] = definition
        return fragments

    def _has_introspection(self, document: DocumentNode) -> bool:
        # Simple string matching for common introspection fields as AST traversal can be complex for all cases
        query_str = ""
        try:
            # We can't directly stringify DocumentNode easily in graphql-core without print_ast
            query_str = graphql.print_ast(document)
        except:
            pass
        return "__schema" in query_str or "__type" in query_str

    def _calculate_depth(self, node: Any, fragments: Dict[str, FragmentDefinitionNode], current_depth: int = 0) -> int:
        if not hasattr(node, 'selection_set') or not node.selection_set:
            return current_depth

        max_depth = current_depth
        for selection in node.selection_set.selections:
            if isinstance(selection, FieldNode):
                depth = self._calculate_depth(selection, fragments, current_depth + 1)
                max_depth = max(max_depth, depth)
            elif isinstance(selection, FragmentSpreadNode):
                fragment_name = selection.name.value
                if fragment_name in fragments:
                    # To prevent infinite recursion in invalid self-referencing fragments (though invalid in spec, good to be safe)
                    # We just do a simple pass
                    depth = self._calculate_depth(fragments[fragment_name], fragments, current_depth + 1)
                    max_depth = max(max_depth, depth)

        return max_depth

    def _count_aliases(self, node: Any, fragments: Dict[str, FragmentDefinitionNode]) -> int:
        if not hasattr(node, 'selection_set') or not node.selection_set:
            return 0

        aliases = 0
        for selection in node.selection_set.selections:
            if isinstance(selection, FieldNode):
                if selection.alias:
                    aliases += 1
                aliases += self._count_aliases(selection, fragments)
            elif isinstance(selection, FragmentSpreadNode):
                fragment_name = selection.name.value
                if fragment_name in fragments:
                    aliases += self._count_aliases(fragments[fragment_name], fragments)
        return aliases

    def _calculate_risk(self, flags: List[Dict[str, str]]) -> str:
        if not flags:
            return "Low"

        severities = [f["severity"] for f in flags]
        if "Critical" in severities:
            return "Critical"
        if "High" in severities:
            return "High"
        if "Medium" in severities:
            return "Medium"
        return "Low"

import pytest
from app.inspector import GraphQLInspector

def test_clean_query():
    inspector = GraphQLInspector()
    query = """
    query {
        user(id: 1) {
            name
            email
        }
    }
    """
    risk_score, flags, metrics = inspector.inspect(query)
    assert risk_score == "Low"
    assert len(flags) == 0
    assert metrics["depth"] == 2
    assert metrics["aliases"] == 0

def test_introspection_query():
    inspector = GraphQLInspector()
    query = """
    query {
        __schema {
            types {
                name
            }
        }
    }
    """
    risk_score, flags, metrics = inspector.inspect(query)
    assert risk_score == "Medium"
    assert any(f["rule_id"] == "GRAPHQL_INTROSPECTION" for f in flags)
    assert metrics["introspection"] == True

def test_excessive_depth():
    inspector = GraphQLInspector(max_depth=3)
    query = """
    query {
        user {
            posts {
                comments {
                    author {
                        name
                    }
                }
            }
        }
    }
    """
    risk_score, flags, metrics = inspector.inspect(query)
    assert risk_score == "Critical"
    assert any(f["rule_id"] == "GRAPHQL_EXCESSIVE_DEPTH" for f in flags)
    assert metrics["depth"] == 5

def test_excessive_aliases():
    inspector = GraphQLInspector(max_aliases=2)
    query = """
    query {
        u1: user(id: 1) { name }
        u2: user(id: 2) { name }
        u3: user(id: 3) { name }
    }
    """
    risk_score, flags, metrics = inspector.inspect(query)
    assert risk_score == "High"
    assert any(f["rule_id"] == "GRAPHQL_EXCESSIVE_ALIASES" for f in flags)
    assert metrics["aliases"] == 3

def test_parse_error():
    inspector = GraphQLInspector()
    query = "query { user(id: 1) { name " # Missing closing brace
    risk_score, flags, metrics = inspector.inspect(query)
    assert risk_score == "High"
    assert any(f["rule_id"] == "GRAPHQL_PARSE_ERROR" for f in flags)

import pytest
from app.inspector import GraphQLInspector

def test_safe_query():
    inspector = GraphQLInspector()
    query = "{ user(id: 1) { name email } }"
    result = inspector.analyze_query(query)
    assert result["is_safe"] is True
    assert result["metrics"]["depth"] == 2
    assert result["metrics"]["aliases"] == 0
    assert result["metrics"]["has_introspection"] is False

def test_introspection_detection():
    inspector = GraphQLInspector()
    query = "{ __schema { types { name } } }"
    result = inspector.analyze_query(query)
    assert result["is_safe"] is False
    assert result["metrics"]["has_introspection"] is True
    assert "Introspection query detected" in result["findings"]

def test_excessive_depth():
    inspector = GraphQLInspector(max_depth=3)
    query = "{ user { posts { comments { author { name } } } } }"
    result = inspector.analyze_query(query)
    assert result["is_safe"] is False
    assert result["metrics"]["depth"] == 5
    assert any("Excessive nesting depth" in f for f in result["findings"])

def test_excessive_aliases():
    inspector = GraphQLInspector(max_aliases=2)
    query = "{ a: user(id: 1) { name } b: user(id: 2) { name } c: user(id: 3) { name } }"
    result = inspector.analyze_query(query)
    assert result["is_safe"] is False
    assert result["metrics"]["aliases"] == 3
    assert any("Excessive aliases" in f for f in result["findings"])

def test_invalid_query():
    inspector = GraphQLInspector()
    result = inspector.analyze_query(None)
    assert result["is_safe"] is False
    assert "Invalid query format" in result["findings"]

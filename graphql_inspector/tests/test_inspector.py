import pytest
from app.inspector import GraphQLInspector

def test_valid_query():
    inspector = GraphQLInspector()
    query = "{ users { id name } }"
    result = inspector.inspect(query)
    assert result["is_valid"] is True
    assert len(result["violations"]) == 0

def test_max_depth_exceeded():
    inspector = GraphQLInspector(max_depth=2)
    # Depth 1: users, Depth 2: friends, Depth 3: posts
    query = "{ users { friends { posts { id } } } }"
    result = inspector.inspect(query)
    assert result["is_valid"] is False
    assert len(result["violations"]) == 1
    assert result["violations"][0]["issue_type"] == "Max Depth Exceeded"

def test_max_aliases_exceeded():
    inspector = GraphQLInspector(max_aliases=2)
    query = "{ a: users(id: 1) { id } b: users(id: 2) { id } c: users(id: 3) { id } }"
    result = inspector.inspect(query)
    assert result["is_valid"] is False
    assert len(result["violations"]) == 1
    assert result["violations"][0]["issue_type"] == "Max Aliases Exceeded"

def test_introspection_blocked():
    inspector = GraphQLInspector(allow_introspection=False)
    query = "{ __schema { types { name } } }"
    result = inspector.inspect(query)
    assert result["is_valid"] is False
    assert len(result["violations"]) == 1
    assert result["violations"][0]["issue_type"] == "Introspection Query"

def test_introspection_allowed():
    inspector = GraphQLInspector(allow_introspection=True)
    query = "{ __schema { types { name } } }"
    result = inspector.inspect(query)
    assert result["is_valid"] is True

def test_malformed_query():
    inspector = GraphQLInspector()
    query = "{ users { id name " # Missing closing braces
    result = inspector.inspect(query)
    assert result["is_valid"] is False
    assert "error" in result
    assert result["error"] is not None

def test_multiple_violations():
    inspector = GraphQLInspector(max_depth=1, max_aliases=1, allow_introspection=False)
    query = "{ a: __schema { types { name } } b: __type { name } }"
    result = inspector.inspect(query)
    assert result["is_valid"] is False
    # 2 introspection, 1 alias exceeded (b is the 2nd alias), multiple depth exceeded
    violation_types = [v["issue_type"] for v in result["violations"]]
    assert "Introspection Query" in violation_types
    assert "Max Aliases Exceeded" in violation_types
    assert "Max Depth Exceeded" in violation_types

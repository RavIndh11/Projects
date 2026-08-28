from fastapi.testclient import TestClient
from app.main import app
import pytest

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_safe_query():
    query = """
    query {
      user(id: "1") {
        name
        email
      }
    }
    """
    response = client.post("/api/analyze", json={"query": query})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["severity"] == "Low"
    assert data["is_safe"] is True
    assert data["depth"] == 2

def test_deep_query_dos():
    query = """
    query {
      author {
        posts {
          author {
            posts {
              author {
                name
              }
            }
          }
        }
      }
    }
    """
    response = client.post("/api/analyze", json={
        "query": query,
        "max_depth_limit": 3
    })
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["is_safe"] is False
    assert "Query depth (6) exceeds limit (3)" in data["issues"][0]
    assert data["severity"] in ["Medium", "High", "Critical"]

def test_excessive_aliases():
    query = """
    query {
      a1: user(id: "1") { name }
      a2: user(id: "2") { name }
      a3: user(id: "3") { name }
      a4: user(id: "4") { name }
    }
    """
    response = client.post("/api/analyze", json={
        "query": query,
        "max_alias_limit": 2
    })
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["is_safe"] is False
    assert "Alias count (4) exceeds limit (2)" in data["issues"][0]

def test_introspection_query():
    query = """
    query {
      __schema {
        types {
          name
        }
      }
    }
    """
    response = client.post("/api/analyze", json={"query": query})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["is_safe"] is False
    assert data["introspection"] is True
    assert "Introspection query detected" in data["issues"][0]
    assert data["severity"] in ["High", "Critical"]

def test_syntax_error():
    query = "query { user(id: ) { name } }"
    response = client.post("/api/analyze", json={"query": query})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "error"
    assert "Syntax Error" in data["message"]

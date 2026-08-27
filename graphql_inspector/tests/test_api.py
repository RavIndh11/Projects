import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "GraphQL Security Inspector" in response.text

def test_inspect_clean_query():
    query = """
    query {
        user(id: 1) {
            name
        }
    }
    """
    response = client.post("/api/v1/inspect", json={"query": query})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["risk_score"] == "Low"
    assert len(data["flags"]) == 0

def test_inspect_malicious_query():
    query = """
    query {
        __schema {
            types {
                name
            }
        }
    }
    """
    response = client.post("/api/v1/inspect", json={"query": query})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["risk_score"] == "Medium"
    assert len(data["flags"]) > 0
    assert any(flag["rule_id"] == "GRAPHQL_INTROSPECTION" for flag in data["flags"])

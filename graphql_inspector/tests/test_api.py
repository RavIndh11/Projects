from fastapi.testclient import TestClient
from app.main import app
import pytest

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_inspect_safe_query():
    payload = {"query": "{ user { id name } }"}
    response = client.post("/api/inspect", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_safe"] is True

def test_inspect_malicious_query():
    payload = {"query": "{ __schema { types { name } } }"}
    response = client.post("/api/inspect", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_safe"] is False
    assert "Introspection query detected" in data["findings"]

def test_batch_inspect():
    payload = {
        "queries": [
            {"query": "{ user { id } }"},
            {"query": "{ __type(name: \"User\") { name } }"}
        ]
    }
    response = client.post("/api/inspect/batch", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    assert data[0]["is_safe"] is True
    assert data[1]["is_safe"] is False
    assert data[1]["metrics"]["has_introspection"] is True

def test_dashboard_renders():
    response = client.get("/")
    assert response.status_code == 200
    assert "GraphQL Security Inspector" in response.text

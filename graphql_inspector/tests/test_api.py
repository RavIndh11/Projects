import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_index_page():
    response = client.get("/")
    assert response.status_code == 200
    assert b"GraphQL Security Inspector" in response.content

def test_api_inspect_valid():
    payload = {
        "query": "{ users { id } }",
        "max_depth": 5,
        "max_aliases": 3,
        "allow_introspection": False
    }
    response = client.post("/api/inspect", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_valid"] is True
    assert len(data["violations"]) == 0

def test_api_inspect_violation():
    payload = {
        "query": "{ __schema { types { name } } }",
        "allow_introspection": False
    }
    response = client.post("/api/inspect", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_valid"] is False
    assert len(data["violations"]) > 0
    assert data["violations"][0]["issue_type"] == "Introspection Query"

def test_ui_inspect_valid():
    form_data = {
        "query": "{ users { id } }",
        "max_depth": 5,
        "max_aliases": 3
    }
    response = client.post("/ui/inspect", data=form_data)
    assert response.status_code == 200
    assert b"Passed" in response.content
    assert b"Failed" not in response.content

def test_ui_inspect_violation():
    form_data = {
        "query": "{ a: user(id: 1){id}, b: user(id:2){id}, c: user(id:3){id} }",
        "max_depth": 5,
        "max_aliases": 1
    }
    response = client.post("/ui/inspect", data=form_data)
    assert response.status_code == 200
    assert b"Failed" in response.content
    assert b"Max Aliases Exceeded" in response.content

def test_api_inspect_invalid_input():
    payload = {
        "query": "{ users { id } }",
        "max_depth": -1  # Validation error
    }
    response = client.post("/api/inspect", json=payload)
    assert response.status_code == 422

import pytest
from fastapi.testclient import TestClient
import jwt
from app.main import app

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_frontend_renders():
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "JWT Security Analyzer" in response.text

def test_api_analyze_valid_token():
    payload = {"sub": "123", "exp": 9999999999}
    secret = "this_is_a_very_strong_and_long_secret_key_12345!"
    token = jwt.encode(payload, secret, algorithm="HS256")

    response = client.post("/api/analyze", json={"token": token})
    assert response.status_code == 200

    data = response.json()
    assert data["is_valid_format"] is True
    assert "header" in data
    assert "payload" in data
    # At least the symmetric algorithm warning
    assert len(data["vulnerabilities"]) >= 1

def test_api_analyze_invalid_format():
    response = client.post("/api/analyze", json={"token": "not.a.token"})
    assert response.status_code == 200 # App handles validation and returns object
    data = response.json()
    assert data["is_valid_format"] is False
    assert "error" in data

def test_api_analyze_pydantic_validation_error():
    # Sending missing data or too short
    response = client.post("/api/analyze", json={"token": "short"})
    assert response.status_code == 422 # FastAPI validation failure

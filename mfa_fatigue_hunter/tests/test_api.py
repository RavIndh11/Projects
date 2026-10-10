import pytest
from fastapi.testclient import TestClient
from app.main import app
import os

client = TestClient(app)

def test_ingest_event_unauthorized():
    # If API_KEY is set in env, it should reject without key
    os.environ["API_KEY"] = "secret"
    response = client.post("/api/v1/ingest", json={
        "user_id": "test",
        "event_type": "mfa_push_sent"
    })
    assert response.status_code == 403
    os.environ.pop("API_KEY")

def test_ingest_event_authorized():
    os.environ["API_KEY"] = "secret"
    response = client.post("/api/v1/ingest", json={
        "user_id": "test",
        "event_type": "mfa_push_sent"
    }, headers={"X-API-Key": "secret"})
    assert response.status_code == 202
    assert response.json()["status"] == "accepted"
    os.environ.pop("API_KEY")

def test_ingest_invalid_event():
    response = client.post("/api/v1/ingest", json={
        "user_id": "test",
        "event_type": "invalid_event"
    })
    assert response.status_code == 422 # Validation error

def test_dashboard_loads():
    response = client.get("/")
    assert response.status_code == 200
    assert "MFA Fatigue Hunter" in response.text

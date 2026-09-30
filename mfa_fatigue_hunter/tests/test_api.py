from fastapi.testclient import TestClient
from app.main import app
import json

client = TestClient(app)

def test_health_check():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_dashboard():
    response = client.get("/")
    assert response.status_code == 200
    assert "MFA Fatigue Hunter Dashboard" in response.text

def test_ingest_event_valid_no_alert():
    event_data = {
        "user_id": "api_test@example.com",
        "status": "REJECTED",
        "source_ip": "10.0.0.1"
    }
    response = client.post("/api/events", json=event_data)
    assert response.status_code == 202
    assert response.json() == {"status": "Event logged successfully, no anomaly detected"}

def test_ingest_event_invalid():
    # Missing required field source_ip
    event_data = {
        "user_id": "api_test@example.com",
        "status": "REJECTED"
    }
    response = client.post("/api/events", json=event_data)
    assert response.status_code == 422

def test_ingest_event_alert():
    # Send 3 rejected events to trigger an alert
    event_data = {
        "user_id": "api_alert@example.com",
        "status": "REJECTED",
        "source_ip": "10.0.0.1"
    }
    client.post("/api/events", json=event_data)
    client.post("/api/events", json=event_data)
    response = client.post("/api/events", json=event_data)

    assert response.status_code == 200
    data = response.json()
    assert data["severity"] == "HIGH"
    assert data["user_id"] == "api_alert@example.com"
    assert not data["is_compromised"]

def test_ingest_event_compromised():
    # Send 3 rejected events, then 1 success
    user = "compromised@example.com"
    event_data = {
        "user_id": user,
        "status": "REJECTED",
        "source_ip": "10.0.0.1"
    }
    client.post("/api/events", json=event_data)
    client.post("/api/events", json=event_data)
    client.post("/api/events", json=event_data)

    success_data = {
        "user_id": user,
        "status": "SUCCESS",
        "source_ip": "10.0.0.1"
    }
    response = client.post("/api/events", json=success_data)

    assert response.status_code == 200
    data = response.json()
    assert data["severity"] == "CRITICAL"
    assert data["is_compromised"] is True

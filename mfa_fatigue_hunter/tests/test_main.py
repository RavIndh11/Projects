import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_ingest_event():
    payload = {
        "user_email": "test@example.com",
        "ip_address": "10.0.0.1",
        "status": "DENIED",
        "timestamp": "2023-10-01T12:00:00Z"
    }
    response = client.post("/api/v1/events", json=payload)
    assert response.status_code == 202
    assert response.json() == {"status": "event_processed", "alert_generated": False}

def test_dashboard_loads():
    response = client.get("/")
    assert response.status_code == 200
    assert "MFA Fatigue Hunter" in response.text

def test_get_alerts_empty():
    response = client.get("/api/v1/alerts")
    assert response.status_code == 200
    assert response.json() == []

def test_fatigue_alert_generation():
    # Send 3 denials
    payload = {
        "user_email": "spam@example.com",
        "ip_address": "10.0.0.1",
        "status": "DENIED"
    }

    for i in range(2):
        response = client.post("/api/v1/events", json=payload)
        assert response.status_code == 202
        assert response.json()["alert_generated"] is False

    # 3rd should trigger alert
    response = client.post("/api/v1/events", json=payload)
    assert response.status_code == 202
    assert response.json()["alert_generated"] is True
    assert response.json()["alert_severity"] == "HIGH"

    # Check alerts API
    response = client.get("/api/v1/alerts")
    assert response.status_code == 200
    alerts = response.json()
    assert len(alerts) >= 1
    assert alerts[0]["user_email"] == "spam@example.com"
    assert alerts[0]["severity"] == "HIGH"

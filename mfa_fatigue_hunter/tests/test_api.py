from fastapi.testclient import TestClient
from app.main import app
import pytest

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_receive_event_valid():
    payload = {
        "user_email": "user@example.com",
        "event_type": "push_sent",
        "ip_address": "192.168.1.1"
    }
    response = client.post("/api/v1/events", json=payload)
    assert response.status_code == 201
    assert response.json()["status"] == "processed"
    assert "alert_triggered" not in response.json()

def test_receive_event_invalid_email():
    payload = {
        "user_email": "not-an-email",
        "event_type": "push_sent"
    }
    response = client.post("/api/v1/events", json=payload)
    assert response.status_code == 422 # Unprocessable Entity

def test_receive_event_invalid_type():
    payload = {
        "user_email": "user@example.com",
        "event_type": "invalid_type"
    }
    response = client.post("/api/v1/events", json=payload)
    assert response.status_code == 422

def test_dashboard_load():
    response = client.get("/")
    assert response.status_code == 200
    assert "MFA Fatigue Hunter" in response.text

def test_fatigue_detection_flow():
    # Send multiple requests to trigger alert
    for _ in range(3):
        response = client.post("/api/v1/events", json={"user_email": "victim@example.com", "event_type": "push_sent"})

    assert response.status_code == 201
    assert response.json().get("alert_triggered") is True
    assert response.json().get("alert_severity") == "Medium"

    # Check if alert is accessible via API
    response = client.get("/api/v1/alerts")
    assert response.status_code == 200
    alerts = response.json()
    assert len(alerts) > 0
    assert alerts[0]["user_email"] == "victim@example.com"

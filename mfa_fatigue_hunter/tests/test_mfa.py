import pytest
from fastapi.testclient import TestClient
from app.main import app, detector
from app.models import AuthEvent, EventType, AlertSeverity
from datetime import datetime

client = TestClient(app)

@pytest.fixture(autouse=True)
def reset_detector():
    """Reset the detector state before each test."""
    detector.events = {}
    detector.alerts = []

def test_dashboard_loads():
    response = client.get("/")
    assert response.status_code == 200
    assert "MFA Fatigue Hunter Dashboard" in response.text

def test_ingest_single_event():
    event_data = {
        "user_email": "test@example.com",
        "event_type": "mfa_push_sent",
        "ip_address": "192.168.1.1"
    }
    response = client.post("/api/v1/events/ingest", json=event_data)
    assert response.status_code == 201
    assert response.json()["status"] == "success"
    assert "alert" not in response.json()

def test_mfa_fatigue_critical_alert():
    # Send 5 pushes and then an approval
    email = "victim@example.com"
    for _ in range(5):
        client.post("/api/v1/events/ingest", json={
            "user_email": email,
            "event_type": "mfa_push_sent",
            "ip_address": "1.1.1.1"
        })

    # Send approval
    response = client.post("/api/v1/events/ingest", json={
        "user_email": email,
        "event_type": "mfa_push_approved",
        "ip_address": "1.1.1.1"
    })

    assert response.status_code == 201
    data = response.json()
    assert "alert" in data
    assert data["alert"]["severity"] == "Critical"
    assert "MFA fatigue successful" in data["alert"]["reason"]

def test_mfa_fatigue_high_alert_no_approval():
    # Send 10 pushes without approval
    email = "spam@example.com"
    for _ in range(9):
        client.post("/api/v1/events/ingest", json={
            "user_email": email,
            "event_type": "mfa_push_sent",
            "ip_address": "2.2.2.2"
        })

    # The 10th push should trigger the High alert
    response = client.post("/api/v1/events/ingest", json={
        "user_email": email,
        "event_type": "mfa_push_sent",
        "ip_address": "2.2.2.2"
    })

    assert response.status_code == 201
    data = response.json()
    assert "alert" in data
    assert data["alert"]["severity"] == "High"
    assert "High volume of MFA pushes" in data["alert"]["reason"]

def test_invalid_event_payload():
    # Missing required fields
    response = client.post("/api/v1/events/ingest", json={
        "user_email": "bad@example.com"
    })
    assert response.status_code == 422 # Unprocessable Entity

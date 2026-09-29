import pytest
from fastapi.testclient import TestClient
from app.main import app, analyzer, recent_alerts
from datetime import datetime, timezone

client = TestClient(app)

@pytest.fixture(autouse=True)
def reset_state():
    """Reset the analyzer and alerts state before each test."""
    analyzer.events.clear()
    recent_alerts.clear()
    analyzer.threshold = 3
    analyzer.time_window = 60
    yield

def test_ingest_log_success():
    payload = {
        "user_id": "test_user",
        "event_type": "push_notification",
        "ip_address": "8.8.8.8",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "pending"
    }
    response = client.post("/api/v1/logs", json=payload)
    assert response.status_code == 202
    assert response.json() == {"status": "processed"}

def test_ingest_log_invalid_payload():
    payload = {
        "user_id": "test_user",
        "event_type": "invalid_type", # Invalid event type
        "ip_address": "8.8.8.8",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "pending"
    }
    response = client.post("/api/v1/logs", json=payload)
    assert response.status_code == 422

def test_trigger_fatigue_alert():
    payload = {
        "user_id": "victim_user",
        "event_type": "push_notification",
        "ip_address": "1.2.3.4",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "pending"
    }

    # Send events up to threshold - 1
    client.post("/api/v1/logs", json=payload)
    client.post("/api/v1/logs", json=payload)

    # Send the triggering event
    response = client.post("/api/v1/logs", json=payload)

    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "alert_triggered"
    assert data["alert"]["user_id"] == "victim_user"
    assert data["alert"]["severity"] == "CRITICAL"

def test_get_dashboard():
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "MFA Fatigue Hunter Dashboard" in response.text

def test_get_alerts_api():
    response = client.get("/api/v1/alerts")
    assert response.status_code == 200
    assert response.json() == {"alerts": []}

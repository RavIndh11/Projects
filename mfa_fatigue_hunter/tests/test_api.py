from fastapi.testclient import TestClient
from app.main import app, alerts_db, detector

client = TestClient(app)

def setup_function():
    alerts_db.clear()
    detector.user_prompts.clear()
    detector.active_fatigue_alerts.clear()

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_ingest_event_valid():
    payload = {
        "user_email": "admin@example.com",
        "event_type": "mfa_prompt",
        "source_ip": "10.0.0.1"
    }
    response = client.post("/api/events", json=payload)
    assert response.status_code == 202
    assert response.json() == {"status": "processed"}

def test_ingest_event_invalid_email():
    payload = {
        "user_email": "not-an-email",
        "event_type": "mfa_prompt",
        "source_ip": "10.0.0.1"
    }
    response = client.post("/api/events", json=payload)
    assert response.status_code == 422 # Pydantic validation error

def test_ingest_event_invalid_type():
    payload = {
        "user_email": "admin@example.com",
        "event_type": "invalid_type",
        "source_ip": "10.0.0.1"
    }
    response = client.post("/api/events", json=payload)
    assert response.status_code == 422

def test_dashboard_renders():
    # Insert a dummy event to create an alert for the dashboard
    # Threshold is 5 by default, so we send 5 prompts
    payload = {
        "user_email": "target@example.com",
        "event_type": "mfa_prompt",
        "source_ip": "192.168.1.1"
    }
    for _ in range(5):
        client.post("/api/events", json=payload)

    response = client.get("/")
    assert response.status_code == 200
    assert "MFA Fatigue Hunter" in response.text
    assert "target@example.com" in response.text
    assert "High" in response.text

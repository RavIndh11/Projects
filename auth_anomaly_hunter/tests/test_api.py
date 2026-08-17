from fastapi.testclient import TestClient
import pytest
from datetime import datetime, timedelta, timezone

from app.main import app
from app.db import db
from app.geo import _geo_cache, clear_cache

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_teardown():
    db.clear()
    clear_cache()
    yield

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_ingest_log_success_no_alert():
    payload = {
        "user_id": "test_user_1",
        "ip_address": "8.8.8.8",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "success"
    }

    response = client.post("/api/v1/logs", json=payload)
    assert response.status_code == 200
    assert response.json()["alert_generated"] is False

def test_ingest_log_impossible_travel():
    # Setup cache for deterministic testing
    _geo_cache["8.8.8.8"] = (37.386, -122.0838) # Mountain View, CA
    _geo_cache["1.1.1.1"] = (40.7128, -74.0060) # New York, NY

    now = datetime.now(timezone.utc)

    payload1 = {
        "user_id": "test_user_2",
        "ip_address": "8.8.8.8",
        "timestamp": (now - timedelta(minutes=30)).isoformat(),
        "status": "success"
    }

    payload2 = {
        "user_id": "test_user_2",
        "ip_address": "1.1.1.1",
        "timestamp": now.isoformat(),
        "status": "success"
    }

    # First login
    resp1 = client.post("/api/v1/logs", json=payload1)
    assert resp1.status_code == 200
    assert resp1.json()["alert_generated"] is False

    # Second login (too fast for CA -> NY)
    resp2 = client.post("/api/v1/logs", json=payload2)
    assert resp2.status_code == 200
    assert resp2.json()["alert_generated"] is True

def test_invalid_payload():
    payload = {
        "user_id": "test_user",
        "ip_address": "not_an_ip",
        "timestamp": "bad_date",
        "status": "success"
    }

    response = client.post("/api/v1/logs", json=payload)
    assert response.status_code == 422 # Unprocessable Entity (Pydantic validation failed)

def test_get_alerts():
    # Create an alert manually
    from app.models import AnomalyAlert
    import uuid

    alert = AnomalyAlert(
        alert_id=str(uuid.uuid4()),
        user_id="bob",
        severity="High",
        description="Test",
        timestamp=datetime.now(timezone.utc),
        details={}
    )
    db.add_alert(alert)

    response = client.get("/api/v1/alerts")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["user_id"] == "bob"

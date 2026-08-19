from fastapi.testclient import TestClient
from app.main import app
from datetime import datetime

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}

def test_ingest_valid_log():
    payload = {
        "user_email": "user@example.com",
        "ip_address": "8.8.8.8",
        "timestamp": datetime.utcnow().isoformat(),
        "status": "pending"
    }
    response = client.post("/api/v1/mfa_logs", json=payload)
    assert response.status_code == 201
    assert response.json()["status"] == "success"

def test_ingest_invalid_ip():
    payload = {
        "user_email": "user@example.com",
        "ip_address": "invalid_ip",
        "timestamp": datetime.utcnow().isoformat(),
        "status": "pending"
    }
    response = client.post("/api/v1/mfa_logs", json=payload)
    assert response.status_code == 422 # Pydantic validation error

def test_ingest_invalid_email():
    payload = {
        "user_email": "not_an_email",
        "ip_address": "8.8.8.8",
        "timestamp": datetime.utcnow().isoformat(),
        "status": "pending"
    }
    response = client.post("/api/v1/mfa_logs", json=payload)
    assert response.status_code == 422

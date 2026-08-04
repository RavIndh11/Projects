import pytest
from fastapi.testclient import TestClient
from app.main import app
import os

client = TestClient(app)
API_KEY = os.getenv("API_KEY", "default-dev-key")
HEADERS = {"X-API-Key": API_KEY}

def test_health_check():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}

def test_dashboard_access():
    response = client.get("/")
    assert response.status_code == 200
    assert "C2 Beacon Hunter" in response.text

def test_analyze_unauthorized():
    response = client.post("/api/v1/analyze", json={"logs": []})
    assert response.status_code == 403

def test_analyze_empty_batch():
    response = client.post("/api/v1/analyze", headers=HEADERS, json={"logs": []})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["processed_logs"] == 0
    assert data["alerts_found"] == 0

def test_analyze_invalid_ip():
    payload = {
        "logs": [
            {
                "timestamp": "2023-01-01T12:00:00Z",
                "src_ip": "invalid_ip",
                "dst_ip": "10.0.0.1",
                "dst_port": 80,
                "bytes_sent": 100,
                "bytes_received": 100
            }
        ]
    }
    response = client.post("/api/v1/analyze", headers=HEADERS, json=payload)
    assert response.status_code == 422 # Unprocessable Entity (Pydantic validation error)

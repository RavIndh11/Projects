import pytest
from fastapi.testclient import TestClient
import httpx
from app.main import app
from app.core.config import settings

# httpx==0.24.1 workaround for fastapi issue in tests
def test_health():
    with TestClient(app) as client:
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}

def test_ingest_logs_unauthorized():
    with TestClient(app) as client:
        response = client.post("/api/v1/logs", json={"logs": []})
        assert response.status_code == 403

def test_ingest_logs_authorized():
    with TestClient(app) as client:
        payload = {
            "logs": [
                {
                    "timestamp": "2023-10-27T10:00:00Z",
                    "user_id": "test_user",
                    "action": "mfa_prompt_denied"
                }
            ]
        }
        response = client.post(
            "/api/v1/logs",
            json=payload,
            headers={"X-API-Key": settings.API_KEY}
        )
        assert response.status_code == 200
        assert response.json()["status"] == "success"
        assert response.json()["processed_logs"] == 1

def test_dashboard_route():
    with TestClient(app) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert "MFA Fatigue Hunter Dashboard" in response.text

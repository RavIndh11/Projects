import pytest
from fastapi.testclient import TestClient
from src.main import app
from src.config import settings

def test_read_only_mode_api():
    with TestClient(app) as client:
        settings.read_only_mode = True
        response = client.post("/containers/create", json={})
        assert response.status_code == 403
        assert "forbidden in read-only mode" in response.json()["detail"]
        settings.read_only_mode = False

def test_invalid_json_payload():
    with TestClient(app) as client:
        # Invalid JSON payload should be caught by our logic
        response = client.post("/containers/create", content="invalid json")
        # However, the docker API or httpx proxy might complain about headers before body parse,
        # but since we parse it manually in main.py, let's just make sure we hit 400
        assert response.status_code == 400

def test_blocked_container_create_api():
    with TestClient(app) as client:
        payload = {
            "Image": "nginx:latest",
            "HostConfig": {
                "Privileged": True
            }
        }
        response = client.post("/containers/create", json=payload)
        assert response.status_code == 403
        assert "forbidden" in response.json()["detail"]

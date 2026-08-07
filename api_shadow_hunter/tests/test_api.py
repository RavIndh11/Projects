import pytest
from fastapi.testclient import TestClient
import io
from main import app

client = TestClient(app)

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "API Shadow Hunter" in response.text

def test_analyze_files():
    spec_content = """
    openapi: 3.0.0
    paths:
      /users:
        get:
          summary: List users
    """

    log_content = """
    {"method": "GET", "path": "/users"}
    {"method": "GET", "path": "/shadow"}
    """

    response = client.post(
        "/api/analyze",
        files={
            "spec_file": ("spec.yaml", io.BytesIO(spec_content.encode("utf-8")), "application/x-yaml"),
            "log_file": ("logs.json", io.BytesIO(log_content.encode("utf-8")), "application/json")
        }
    )

    assert response.status_code == 200
    data = response.json()

    assert data["total_documented"] == 1
    assert data["total_accessed"] == 2

    assert len(data["shadow_apis"]) == 1
    assert data["shadow_apis"][0]["path"] == "/shadow"

    assert len(data["zombie_apis"]) == 0

def test_analyze_files_empty():
    response = client.post(
        "/api/analyze",
        files={
            "spec_file": ("spec.yaml", io.BytesIO(b""), "application/x-yaml"),
            "log_file": ("logs.json", io.BytesIO(b""), "application/json")
        }
    )
    assert response.status_code == 400
    assert "empty" in response.json()["detail"]

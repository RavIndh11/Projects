import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_dashboard_loads():
    response = client.get("/")
    assert response.status_code == 200
    assert "SSRF Sentinel Dashboard" in response.text

def test_api_proxy_blocked_metadata(monkeypatch):
    # It shouldn't need a mock because 169.254.169.254 is directly parsed
    # but we'll mock resolve_hostname just in case the OS handles literal IPs weirdly
    monkeypatch.setattr("app.core.security.resolve_hostname", lambda host: ["169.254.169.254"])

    response = client.post("/api/proxy", json={"url": "http://169.254.169.254/latest/meta-data/"})
    assert response.status_code == 403

    data = response.json()
    assert data["status"] == "blocked"
    assert "blocked IP" in data["reason"]

def test_api_proxy_blocked_localhost(monkeypatch):
    monkeypatch.setattr("app.core.security.resolve_hostname", lambda host: ["127.0.0.1"])

    response = client.post("/api/proxy", json={"url": "http://localhost:8080/admin"})
    assert response.status_code == 403

    data = response.json()
    assert data["status"] == "blocked"
    assert "blocked IP" in data["reason"]

def test_form_proxy_blocked(monkeypatch):
    monkeypatch.setattr("app.core.security.resolve_hostname", lambda host: ["10.0.0.5"])

    response = client.post("/proxy-form", data={"url": "http://internal-api.local", "method": "GET"})
    assert response.status_code == 200 # Returns HTML with the error
    assert "blocked" in response.text.lower()
    assert "border-red-500" in response.text # Red alert box

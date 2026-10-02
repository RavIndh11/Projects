from fastapi.testclient import TestClient
from app.main import app

# Create TestClient without 'app' kwarg as per memory requirement for older starlette
client = TestClient(app)

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Web Shell Hunter" in response.text

def test_scan_clean_payload():
    payload = {"content": "echo 'Hello World';"}
    response = client.post("/api/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_malicious"] is False
    assert data["severity"] == "Low"
    assert len(data["matched_signatures"]) == 0

def test_scan_malicious_payload():
    payload = {"content": "<?php eval(base64_decode('...')); ?>"}
    response = client.post("/api/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_malicious"] is True
    assert "eval_execution" in data["matched_signatures"]
    assert "base64_decode" in data["matched_signatures"]

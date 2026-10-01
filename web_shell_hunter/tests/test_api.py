import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_dashboard_load():
    response = client.get("/")
    assert response.status_code == 200
    assert "Web Shell Hunter Dashboard" in response.text

def test_scan_clean_file():
    payload = {
        "file_path": "var/www/html/index.php",
        "file_content": "<?php echo 'Hello'; ?>"
    }
    response = client.post("/api/v1/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "Clean"
    assert len(data["findings"]) == 0
    assert data["file_path"] == payload["file_path"]

def test_scan_malicious_file():
    payload = {
        "file_path": "var/www/html/upload.php",
        "file_content": "<?php system($_GET['cmd']); ?>"
    }
    response = client.post("/api/v1/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "Malicious"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["severity"] == "Critical"

def test_path_traversal_validation():
    payload = {
        "file_path": "../../../etc/passwd",
        "file_content": "root:x:0:0"
    }
    response = client.post("/api/v1/scan", json=payload)
    assert response.status_code == 422 # Unprocessable Entity due to validation error

def test_absolute_path_validation():
    payload = {
        "file_path": "/etc/passwd",
        "file_content": "root:x:0:0"
    }
    response = client.post("/api/v1/scan", json=payload)
    assert response.status_code == 422

def test_missing_content():
    payload = {
        "file_path": "var/www/html/index.php"
    }
    response = client.post("/api/v1/scan", json=payload)
    assert response.status_code == 400
    assert "file_content must be provided" in response.text

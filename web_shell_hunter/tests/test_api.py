import pytest
from fastapi.testclient import TestClient
from app.main import app

# Create a test client
client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_index_page():
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Web Shell Hunter" in response.text

def test_scan_text_clean():
    payload = {
        "content": "This is just a normal text string.",
        "filename": "normal.txt"
    }
    response = client.post("/api/scan/text", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert not data["is_malicious"]
    assert data["threat_level"] == "Low"

def test_scan_text_malicious():
    payload = {
        "content": "<?php system('id'); ?>",
        "filename": "bad.php"
    }
    response = client.post("/api/scan/text", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_malicious"]
    assert "system_exec" in data["matched_signatures"]

def test_scan_file():
    # Simulate a file upload
    file_content = b"<?php eval(base64_decode($_POST['cmd'])); ?>"
    files = {"file": ("shell.php", file_content, "application/x-php")}

    response = client.post("/api/scan/file", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["is_malicious"]
    assert "eval_payload" in data["matched_signatures"]

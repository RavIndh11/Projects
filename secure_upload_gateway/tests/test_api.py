import pytest
from fastapi.testclient import TestClient
from app.main import app

# Create test client
client = TestClient(app)

def test_index_route():
    response = client.get("/")
    assert response.status_code == 200
    assert "Secure Upload Gateway" in response.text

def test_api_analyze_safe_file():
    files = {'file': ('test.txt', b'This is a test file content', 'text/plain')}
    response = client.post("/api/analyze", files=files)

    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "test.txt"
    assert data["severity"] == "Safe"
    assert len(data["findings"]) == 0

def test_api_analyze_dangerous_file():
    files = {'file': ('shell.php', b'<?php phpinfo(); ?>', 'application/x-httpd-php')}
    response = client.post("/api/analyze", files=files)

    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "shell.php"
    assert data["severity"] in ["High", "Critical"]
    assert len(data["findings"]) > 0

import pytest
import httpx
from fastapi.testclient import TestClient
from app.main import app
import os

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}

def test_index_page():
    response = client.get("/")
    assert response.status_code == 200
    assert "Secure Upload Gateway" in response.text

def test_analyze_clean_file():
    content = b"\x89PNG\r\n\x1a\n" + b"fake_png_data"
    files = {'file': ('test.png', content, 'image/png')}

    response = client.post("/api/analyze", files=files)
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "clean"
    assert data["filename"] == "test.png"

def test_analyze_malicious_polyglot():
    content = b"\x89PNG\r\n\x1a\n" + b"fake_data<script>alert(1)</script>"
    files = {'file': ('test.png', content, 'image/png')}

    response = client.post("/api/analyze", files=files)
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "malicious"
    assert data["severity"] == "critical"
    assert any(t["type"] == "polyglot_payload" for t in data["threats"])

def test_file_too_large(monkeypatch):
    # Temporarily set max upload size to 10 bytes
    monkeypatch.setenv("MAX_UPLOAD_SIZE", "10")

    content = b"This is a large file over 10 bytes."
    files = {'file': ('large.txt', content, 'text/plain')}

    response = client.post("/api/analyze", files=files)
    assert response.status_code == 413
    assert "File too large" in response.json()["detail"]

def test_no_file_provided():
    response = client.post("/api/analyze")
    assert response.status_code == 422 # FastAPI validation error for missing field

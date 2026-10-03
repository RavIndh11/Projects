import pytest
from fastapi.testclient import TestClient
from app.main import app
import io
import zipfile

client = TestClient(app)

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "Secure Upload Gateway" in response.text

def test_scan_clean_file():
    files = {'file': ('test.pdf', io.BytesIO(b"%PDF-1.4\ncontent"), 'application/pdf')}
    response = client.post("/api/v1/scan", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["result"]["is_safe"] == True
    assert data["result"]["severity"] == "Low"
    assert len(data["result"]["matched_rules"]) == 0

def test_scan_malicious_polyglot():
    files = {'file': ('test.pdf', io.BytesIO(b"%PDF-1.4\n<?php phpinfo(); ?>"), 'application/pdf')}
    response = client.post("/api/v1/scan", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["result"]["is_safe"] == False
    assert data["result"]["severity"] == "Critical"
    assert "embedded_script_detected" in data["result"]["matched_rules"]

import pytest
from fastapi.testclient import TestClient
import io
import zipfile

# Need to set this up safely for httpx compatibility as mentioned in memory
from app.main import app

client = TestClient(app)

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "Secure Upload Gateway" in response.text

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_analyze_upload_safe_txt():
    content = b"This is a safe text file."
    files = {'file': ('safe.txt', content, 'text/plain')}

    response = client.post("/api/analyze", files=files)
    assert response.status_code == 200

    data = response.json()
    assert data["filename"] == "safe.txt"
    assert data["is_safe"] is True
    assert data["overall_severity"] == "None"
    assert len(data["findings"]) == 0

def test_analyze_upload_missing_file():
    response = client.post("/api/analyze")
    assert response.status_code == 422 # FastAPI validation error for missing field

def test_analyze_upload_zip_slip():
    # Create a malicious zip in memory
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("../../../etc/passwd", b"root:x:0:0:root:/root:/bin/bash")

    files = {'file': ('evil.zip', zip_buffer.getvalue(), 'application/zip')}

    response = client.post("/api/analyze", files=files)
    assert response.status_code == 200

    data = response.json()
    assert data["is_safe"] is False
    assert data["overall_severity"] == "Critical"
    assert any("Zip Slip" in f["vulnerability"] for f in data["findings"])

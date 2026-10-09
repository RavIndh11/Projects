import pytest
from fastapi.testclient import TestClient
from app.main import app
import io
import zipfile

client = TestClient(app)

def create_in_memory_zip(files_dict):
    """Helper to create a zip file in memory for testing."""
    in_memory_zip = io.BytesIO()
    with zipfile.ZipFile(in_memory_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
        for filename, content in files_dict.items():
            zf.writestr(filename, content)
    return in_memory_zip.getvalue()

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_web_dashboard():
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Secure Upload Gateway" in response.text

def test_analyze_file_safe():
    # Test uploading a safe text file
    file_content = b"Safe text content"
    files = {'file': ('test.txt', file_content, 'text/plain')}
    response = client.post("/api/v1/analyze", files=files)

    assert response.status_code == 200
    data = response.json()
    assert data["is_safe"] is True
    assert data["risk_score"] == 0
    assert "threats_found" in data

def test_analyze_file_spoofing():
    # Test extension spoofing (txt content named as pdf)
    file_content = b"This is just text"
    files = {'file': ('fake.pdf', file_content, 'application/pdf')}
    response = client.post("/api/v1/analyze", files=files)

    assert response.status_code == 200
    data = response.json()
    assert data["is_safe"] is False
    assert data["risk_score"] >= 100
    assert any("Extension spoofing" in threat for threat in data["threats_found"])

def test_analyze_file_zip_slip():
    # Test Zip Slip via API
    zip_content = create_in_memory_zip({"../evil.sh": b"echo 'bad'"})
    files = {'file': ('evil.zip', zip_content, 'application/zip')}
    response = client.post("/api/v1/analyze", files=files)

    assert response.status_code == 200
    data = response.json()
    assert data["is_safe"] is False
    assert any("Zip Slip" in threat for threat in data["threats_found"])

def test_analyze_no_file():
    # Test without providing a file
    response = client.post("/api/v1/analyze")
    assert response.status_code == 422 # Unprocessable Entity (FastAPI validation)

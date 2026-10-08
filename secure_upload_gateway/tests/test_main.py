from fastapi.testclient import TestClient
from app.main import app
import io
import zipfile

client = TestClient(app)

def test_dashboard():
    response = client.get("/")
    assert response.status_code == 200
    assert "Secure Upload Gateway" in response.text

def test_upload_safe_file():
    pdf_content = b"%PDF-1.4\n1 0 obj\n<<\n/Title (Test)\n>>\nendobj\n"
    response = client.post(
        "/upload",
        files={"file": ("test.pdf", pdf_content, "application/pdf")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "safe"
    assert data["filename"] == "test.pdf"

def test_upload_spoofed_file():
    # Sending executable bytes with PDF extension
    exe_content = b"MZ\x90\x00\x03\x00\x00\x00"
    response = client.post(
        "/upload",
        files={"file": ("fake.pdf", exe_content, "application/pdf")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "danger"
    assert data["severity"] == "Critical"
    assert any("Extension mismatch" in f for f in data["findings"])

def test_upload_zip_slip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr('../../../etc/shadow', 'root:$6$...')

    response = client.post(
        "/upload",
        files={"file": ("evil.zip", buf.getvalue(), "application/zip")}
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "danger"
    assert data["severity"] == "Critical"
    assert any("Zip Slip" in f for f in data["findings"])

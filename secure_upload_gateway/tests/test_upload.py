import pytest
from httpx import AsyncClient
import io
import zipfile
from app.main import app

@pytest.fixture
def anyio_backend():
    return 'asyncio'

@pytest.mark.asyncio
async def test_dashboard_renders():
    # We can usehttpx version 0.24.1 for compatibility with starlette TestClient but httpx AsyncClient is cleaner for async endpoints
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.get("/")
        assert response.status_code == 200
        assert b"Secure Upload Gateway" in response.content

@pytest.mark.asyncio
async def test_safe_upload():
    # Create a simple text file
    file_content = b"This is a safe text file."
    files = {"file": ("test.txt", file_content, "text/plain")}

    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post("/upload", files=files)
        assert response.status_code == 200
        data = response.json()
        assert data["is_safe"] is True
        assert data["mime_type"] == "text/plain"
        assert len(data["threats"]) == 0

@pytest.mark.asyncio
async def test_extension_spoofing():
    # A text file pretending to be a PDF
    file_content = b"Not really a PDF"
    files = {"file": ("fake.pdf", file_content, "application/pdf")}

    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post("/upload", files=files)
        assert response.status_code == 200
        data = response.json()
        assert data["is_safe"] is False
        assert data["mime_type"] == "text/plain"
        assert any("Extension spoofing detected" in t for t in data["threats"])

@pytest.mark.asyncio
async def test_zip_slip_absolute_path():
    # Create malicious zip in memory
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("/etc/passwd", b"root:x:0:0:root:/root:/bin/bash")
    zip_content = zip_buffer.getvalue()

    files = {"file": ("malicious.zip", zip_content, "application/zip")}

    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post("/upload", files=files)
        assert response.status_code == 200
        data = response.json()
        assert data["is_safe"] is False
        assert any("Zip Slip (absolute path)" in t for t in data["threats"])

@pytest.mark.asyncio
async def test_zip_slip_directory_traversal():
    # Create malicious zip in memory
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("../../../etc/shadow", b"root:$6$xyz...")
    zip_content = zip_buffer.getvalue()

    files = {"file": ("traversal.zip", zip_content, "application/zip")}

    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post("/upload", files=files)
        assert response.status_code == 200
        data = response.json()
        assert data["is_safe"] is False
        assert any("Zip Slip (directory traversal)" in t for t in data["threats"])

@pytest.mark.asyncio
async def test_file_too_large():
    # Create a 6MB file (above 5MB limit)
    large_content = b"0" * (6 * 1024 * 1024)
    files = {"file": ("large.txt", large_content, "text/plain")}

    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post("/upload", files=files)
        assert response.status_code == 413
        assert "File too large" in response.json()["detail"]

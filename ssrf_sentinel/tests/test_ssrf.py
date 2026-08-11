import pytest
import asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app, is_safe_ip

def test_safe_ips():
    assert is_safe_ip("8.8.8.8") == True
    assert is_safe_ip("1.1.1.1") == True

def test_unsafe_ips():
    # Loopback
    assert is_safe_ip("127.0.0.1") == False
    assert is_safe_ip("::1") == False

    # Private
    assert is_safe_ip("10.0.0.1") == False
    assert is_safe_ip("172.16.0.1") == False
    assert is_safe_ip("192.168.1.1") == False

    # Cloud Metadata
    assert is_safe_ip("169.254.169.254") == False

    # Invalid
    assert is_safe_ip("invalid_ip") == False

@pytest.mark.asyncio
async def test_index_route():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/")
        assert response.status_code == 200
        assert "SSRF Sentinel" in response.text

@pytest.mark.asyncio
async def test_fetch_invalid_scheme():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/fetch", data={"url": "ftp://example.com"})
        assert response.status_code == 200
        assert "Invalid scheme" in response.text

@pytest.mark.asyncio
async def test_fetch_missing_hostname():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/fetch", data={"url": "http:///"})
        assert response.status_code == 200
        assert "Invalid URL. Hostname is missing" in response.text

@pytest.mark.asyncio
async def test_fetch_unsafe_ip():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/fetch", data={"url": "http://localhost/"})
        assert response.status_code == 200
        assert "not safe" in response.text

@pytest.mark.asyncio
async def test_fetch_success():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Note: this requires internet access and resolution of example.com
        response = await ac.post("/fetch", data={"url": "http://example.com"})
        assert response.status_code == 200
        # If example.com can be fetched, the status code of the response inside the template will show up
        assert "Status:" in response.text

import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app

@pytest.mark.asyncio
async def test_health_check():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}

@pytest.mark.asyncio
async def test_dashboard_loads():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/")
    assert response.status_code == 200
    assert "Auth Anomaly Hunter - SOC Dashboard" in response.text

@pytest.mark.asyncio
async def test_ingest_event_valid():
    payload = {
        "user_id": "test_user",
        "timestamp": "2023-10-27T10:00:00Z",
        "ip_address": "192.168.1.1",
        "status": "success",
        "location": {
            "lat": 40.7128,
            "lon": -74.0060
        }
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/api/v1/events", json=payload)

    assert response.status_code == 200
    assert response.json()["status"] == "processed"

@pytest.mark.asyncio
async def test_ingest_event_invalid_status():
    payload = {
        "user_id": "test_user",
        "timestamp": "2023-10-27T10:00:00Z",
        "ip_address": "192.168.1.1",
        "status": "unknown"
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/api/v1/events", json=payload)

    assert response.status_code == 422 # Unprocessable Entity

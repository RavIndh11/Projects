import pytest
from datetime import datetime, timedelta, timezone
from app.models import AuthLog
from app.analyzer import analyze_login, haversine_distance
from app.geo import _geo_cache, clear_cache

@pytest.fixture(autouse=True)
def setup_teardown():
    clear_cache()
    yield

def test_haversine_distance():
    # New York, NY
    coord1 = (40.7128, -74.0060)
    # London, UK
    coord2 = (51.5074, -0.1278)

    distance = haversine_distance(coord1, coord2)
    # Distance is ~5570 km. Check if it's within a reasonable range.
    assert 5500 < distance < 5600

@pytest.mark.asyncio
async def test_impossible_travel():
    # Pre-populate cache to avoid external API calls during testing
    _geo_cache["1.1.1.1"] = (40.7128, -74.0060) # NY
    _geo_cache["2.2.2.2"] = (51.5074, -0.1278) # London

    now = datetime.now(timezone.utc)

    log1 = AuthLog(
        user_id="alice",
        ip_address="1.1.1.1",
        timestamp=now - timedelta(hours=1), # 1 hour ago
        status="success"
    )

    log2 = AuthLog(
        user_id="alice",
        ip_address="2.2.2.2",
        timestamp=now,
        status="success"
    )

    alert = await analyze_login(log2, log1)

    assert alert is not None
    assert alert.severity == "Critical"
    assert alert.details["distance_km"] > 5000
    assert alert.details["speed_kmh"] > 5000

@pytest.mark.asyncio
async def test_normal_travel():
    # New York to Philadelphia (approx 130km)
    _geo_cache["1.1.1.1"] = (40.7128, -74.0060) # NY
    _geo_cache["3.3.3.3"] = (39.9526, -75.1652) # Philly

    now = datetime.now(timezone.utc)

    log1 = AuthLog(
        user_id="alice",
        ip_address="1.1.1.1",
        timestamp=now - timedelta(hours=2), # 2 hours ago
        status="success"
    )

    log2 = AuthLog(
        user_id="alice",
        ip_address="3.3.3.3",
        timestamp=now,
        status="success"
    )

    alert = await analyze_login(log2, log1)

    # Speed should be ~65 km/h, well below plausible threshold
    assert alert is None

@pytest.mark.asyncio
async def test_same_ip():
    now = datetime.now(timezone.utc)

    log1 = AuthLog(
        user_id="alice",
        ip_address="1.1.1.1",
        timestamp=now - timedelta(hours=1),
        status="success"
    )

    log2 = AuthLog(
        user_id="alice",
        ip_address="1.1.1.1",
        timestamp=now,
        status="success"
    )

    alert = await analyze_login(log2, log1)
    assert alert is None

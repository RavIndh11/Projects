import pytest
from datetime import datetime, timezone, timedelta
from app.engine import AnomalyEngine
from app.models import AuthEvent, Coordinates

@pytest.fixture
def engine():
    return AnomalyEngine(
        impossible_travel_speed_kmh=900.0,
        brute_force_time_window_sec=300.0,
        brute_force_max_failures=3
    )

def test_no_anomaly(engine):
    event1 = AuthEvent(
        user_id="user1",
        timestamp=datetime.now(timezone.utc),
        ip_address="192.168.1.1",
        status="success",
        location=Coordinates(lat=40.7128, lon=-74.0060) # NY
    )

    event2 = AuthEvent(
        user_id="user1",
        timestamp=datetime.now(timezone.utc) + timedelta(hours=2),
        ip_address="192.168.1.2",
        status="success",
        location=Coordinates(lat=42.3601, lon=-71.0589) # Boston (~300km)
    )

    anomalies1 = engine.process_event(event1)
    anomalies2 = engine.process_event(event2)

    assert len(anomalies1) == 0
    assert len(anomalies2) == 0

def test_impossible_travel(engine):
    event1 = AuthEvent(
        user_id="user2",
        timestamp=datetime.now(timezone.utc),
        ip_address="192.168.1.1",
        status="success",
        location=Coordinates(lat=40.7128, lon=-74.0060) # NY
    )

    event2 = AuthEvent(
        user_id="user2",
        timestamp=datetime.now(timezone.utc) + timedelta(minutes=30), # 30 min later
        ip_address="8.8.8.8",
        status="success",
        location=Coordinates(lat=51.5074, lon=-0.1278) # London (~5500km)
    )

    anomalies1 = engine.process_event(event1)
    anomalies2 = engine.process_event(event2)

    assert len(anomalies1) == 0
    assert len(anomalies2) == 1
    assert anomalies2[0].anomaly_type == "impossible_travel"

def test_brute_force(engine):
    now = datetime.now(timezone.utc)
    for i in range(3):
        event = AuthEvent(
            user_id="user3",
            timestamp=now + timedelta(seconds=i*10),
            ip_address="10.0.0.1",
            status="failure"
        )
        anomalies = engine.process_event(event)

        if i < 2:
            assert len(anomalies) == 0
        else:
            assert len(anomalies) == 1
            assert anomalies[0].anomaly_type == "brute_force"

def test_brute_force_cleared_on_success(engine):
    now = datetime.now(timezone.utc)

    # Two failures
    for i in range(2):
        engine.process_event(AuthEvent(
            user_id="user4",
            timestamp=now + timedelta(seconds=i*10),
            ip_address="10.0.0.1",
            status="failure"
        ))

    # One success clears it
    engine.process_event(AuthEvent(
        user_id="user4",
        timestamp=now + timedelta(seconds=30),
        ip_address="10.0.0.1",
        status="success"
    ))

    # Third failure doesn't trigger alert because it was cleared
    anomalies = engine.process_event(AuthEvent(
        user_id="user4",
        timestamp=now + timedelta(seconds=40),
        ip_address="10.0.0.1",
        status="failure"
    ))

    assert len(anomalies) == 0

import pytest
from app.analyzer import MFAAnalyzer
from app.models import MFALogEvent
from datetime import datetime, timezone, timedelta
import os

@pytest.fixture
def analyzer():
    # Set custom environment variables for testing
    os.environ["MFA_FATIGUE_THRESHOLD"] = "3"
    os.environ["MFA_TIME_WINDOW"] = "60"
    return MFAAnalyzer()

def create_event(user_id: str, minutes_ago: int = 0, status: str = "pending"):
    return MFALogEvent(
        user_id=user_id,
        event_type="push_notification",
        ip_address="10.0.0.1",
        timestamp=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
        status=status
    )

def test_no_alert_below_threshold(analyzer):
    alert1 = analyzer.process_event(create_event("user1"))
    alert2 = analyzer.process_event(create_event("user1"))

    assert alert1 is None
    assert alert2 is None
    assert len(analyzer.events["user1"]) == 2

def test_alert_triggered_at_threshold(analyzer):
    analyzer.process_event(create_event("user2"))
    analyzer.process_event(create_event("user2"))
    alert = analyzer.process_event(create_event("user2"))

    assert alert is not None
    assert alert.user_id == "user2"
    assert alert.severity == "CRITICAL"
    assert alert.event_count == 3
    # Should clear events after alerting
    assert len(analyzer.events["user2"]) == 0

def test_events_outside_time_window(analyzer):
    # Event 2 minutes ago (outside 60s window)
    analyzer.process_event(create_event("user3", minutes_ago=2))

    # Two recent events
    analyzer.process_event(create_event("user3"))
    alert = analyzer.process_event(create_event("user3"))

    # Should not alert because the first event was outside the window (only 2 recent events)
    assert alert is None
    assert len(analyzer.events["user3"]) == 2

def test_ignore_approved_status(analyzer):
    analyzer.process_event(create_event("user4", status="approved"))
    analyzer.process_event(create_event("user4", status="approved"))
    alert = analyzer.process_event(create_event("user4", status="approved"))

    assert alert is None
    assert len(analyzer.events["user4"]) == 0

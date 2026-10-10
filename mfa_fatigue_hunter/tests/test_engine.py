import pytest
from datetime import datetime, timedelta
from app.models import AuthEvent
from app.engine import DetectionEngine

@pytest.fixture
def engine():
    return DetectionEngine()

def test_engine_detects_fatigue(engine):
    user_id = "victim@example.com"

    # Send 5 mfa pushes
    for i in range(5):
        event = AuthEvent(
            user_id=user_id,
            event_type="mfa_push_sent",
            timestamp=datetime.utcnow()
        )
        alert = engine.process_event(event)

        if i < 4:
            assert alert is None
        else:
            assert alert is not None
            assert alert.severity == "High"
            assert alert.user_id == user_id

def test_engine_detects_critical_fatigue(engine):
    user_id = "victim2@example.com"

    # Send 4 pushes
    for i in range(4):
        event = AuthEvent(
            user_id=user_id,
            event_type="mfa_push_rejected",
            timestamp=datetime.utcnow()
        )
        engine.process_event(event)

    # Send an accept
    accept_event = AuthEvent(
        user_id=user_id,
        event_type="mfa_push_accepted",
        timestamp=datetime.utcnow()
    )
    # The acceptance itself doesn't trigger the count logic if we just do this,
    # wait, the logic checks if len(relevant) >= threshold.
    # We only sent 4 rejections, so the acceptance won't trigger it yet, because
    # accepted is NOT in relevant_events. We need 5 relevant events.
    engine.process_event(accept_event)

    # Send a 5th push to trigger the threshold, now with an accepted in history
    final_push = AuthEvent(
        user_id=user_id,
        event_type="mfa_push_sent",
        timestamp=datetime.utcnow()
    )
    alert = engine.process_event(final_push)

    assert alert is not None
    assert alert.severity == "Critical"

def test_sliding_window(engine):
    user_id = "victim3@example.com"
    old_time = datetime.utcnow() - timedelta(minutes=10)

    # Send 4 old events
    for _ in range(4):
        event = AuthEvent(
            user_id=user_id,
            event_type="mfa_push_sent",
            timestamp=old_time
        )
        engine.process_event(event)

    # Send 1 new event
    event = AuthEvent(
        user_id=user_id,
        event_type="mfa_push_sent",
        timestamp=datetime.utcnow()
    )
    alert = engine.process_event(event)

    # Should be None because the old ones were cleaned up
    assert alert is None

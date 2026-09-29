import pytest
from app.models import MFALogEvent, AlertEvent
from datetime import datetime, timezone
from pydantic import ValidationError

def test_valid_mfa_log_event():
    event = MFALogEvent(
        user_id="user123",
        event_type="push_notification",
        ip_address="192.168.1.1",
        timestamp=datetime.now(timezone.utc),
        status="pending"
    )
    assert event.user_id == "user123"
    assert str(event.ip_address) == "192.168.1.1"
    assert event.event_type == "push_notification"

def test_invalid_event_type():
    with pytest.raises(ValidationError):
        MFALogEvent(
            user_id="user123",
            event_type="invalid_type",
            ip_address="192.168.1.1",
            timestamp=datetime.now(timezone.utc),
            status="pending"
        )

def test_invalid_status():
    with pytest.raises(ValidationError):
        MFALogEvent(
            user_id="user123",
            event_type="push_notification",
            ip_address="192.168.1.1",
            timestamp=datetime.now(timezone.utc),
            status="hacked"
        )

def test_invalid_ip_address():
    with pytest.raises(ValidationError):
        MFALogEvent(
            user_id="user123",
            event_type="push_notification",
            ip_address="not-an-ip",
            timestamp=datetime.now(timezone.utc),
            status="pending"
        )

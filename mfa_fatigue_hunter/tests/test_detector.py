import pytest
from datetime import datetime, timedelta, timezone
from app.schemas import MFAEvent, MFAStatus, AlertSeverity
from app.detector import MFADetector

@pytest.fixture
def detector():
    return MFADetector(time_window_seconds=300, denial_threshold=3)

def test_no_alert_on_single_denial(detector):
    event = MFAEvent(
        user_email="test@example.com",
        ip_address="192.168.1.1",
        status=MFAStatus.DENIED,
        timestamp=datetime.utcnow()
    )
    alert = detector.process_event(event)
    assert alert is None
    assert len(detector.alerts) == 0

def test_fatigue_attack_detection(detector):
    now = datetime.utcnow()
    # 2 denials
    for _ in range(2):
        alert = detector.process_event(MFAEvent(
            user_email="victim@example.com",
            ip_address="1.1.1.1",
            status=MFAStatus.DENIED,
            timestamp=now
        ))
        assert alert is None

    # 3rd denial should trigger alert
    alert = detector.process_event(MFAEvent(
        user_email="victim@example.com",
        ip_address="1.1.1.1",
        status=MFAStatus.DENIED,
        timestamp=now
    ))

    assert alert is not None
    assert alert.severity == AlertSeverity.HIGH
    assert "Possible MFA Fatigue Attack" in alert.message
    assert len(detector.alerts) == 1

def test_compromise_detection(detector):
    now = datetime.utcnow()
    # 3 denials (triggers fatigue alert)
    for _ in range(3):
        detector.process_event(MFAEvent(
            user_email="target@example.com",
            ip_address="2.2.2.2",
            status=MFAStatus.DENIED,
            timestamp=now
        ))

    assert len(detector.alerts) == 1
    assert detector.alerts[0].severity == AlertSeverity.HIGH

    # 1 approval following denials should trigger compromise alert
    alert = detector.process_event(MFAEvent(
        user_email="target@example.com",
        ip_address="2.2.2.2",
        status=MFAStatus.APPROVED,
        timestamp=now + timedelta(seconds=10)
    ))

    assert alert is not None
    assert alert.severity == AlertSeverity.CRITICAL
    assert "Account Compromise Suspected" in alert.message
    assert len(detector.alerts) == 2

def test_events_outside_window_ignored(detector):
    old_time = datetime.utcnow() - timedelta(seconds=400)
    now = datetime.utcnow()

    # 2 old denials
    for _ in range(2):
        detector.process_event(MFAEvent(
            user_email="slow@example.com",
            ip_address="3.3.3.3",
            status=MFAStatus.DENIED,
            timestamp=old_time
        ))

    # 1 new denial (total 3, but 2 are outside window)
    alert = detector.process_event(MFAEvent(
        user_email="slow@example.com",
        ip_address="3.3.3.3",
        status=MFAStatus.DENIED,
        timestamp=now
    ))

    assert alert is None
    assert len(detector.alerts) == 0

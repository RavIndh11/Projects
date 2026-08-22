import pytest
from datetime import datetime, timedelta
from app.models import MFAEvent
from app.detector import MFAFatigueDetector

def test_detector_medium_threshold():
    detector = MFAFatigueDetector(time_window_seconds=60, threshold_medium=3, threshold_high=5, threshold_critical=10)
    email = "test@example.com"

    # Event 1
    alert = detector.process_event(MFAEvent(user_email=email, event_type="push_sent"))
    assert alert is None

    # Event 2
    alert = detector.process_event(MFAEvent(user_email=email, event_type="push_sent"))
    assert alert is None

    # Event 3 - Should trigger Medium alert
    alert = detector.process_event(MFAEvent(user_email=email, event_type="push_sent"))
    assert alert is not None
    assert alert.severity == "Medium"
    assert alert.push_count == 3

def test_detector_critical_threshold():
    detector = MFAFatigueDetector(time_window_seconds=60, threshold_medium=3, threshold_high=5, threshold_critical=10)
    email = "target@example.com"

    for _ in range(9):
        detector.process_event(MFAEvent(user_email=email, event_type="push_sent"))

    # 10th Event - Should trigger Critical alert
    alert = detector.process_event(MFAEvent(user_email=email, event_type="push_sent"))
    assert alert is not None
    assert alert.severity == "Critical"
    assert alert.push_count == 10

def test_detector_ignores_other_events():
    detector = MFAFatigueDetector()
    email = "safe@example.com"

    alert = detector.process_event(MFAEvent(user_email=email, event_type="push_approved"))
    assert alert is None
    assert len(detector.events) == 0

def test_detector_time_window():
    detector = MFAFatigueDetector(time_window_seconds=2)
    email = "slow@example.com"

    # Send 2 events
    detector.process_event(MFAEvent(user_email=email, event_type="push_sent", timestamp=datetime.utcnow() - timedelta(seconds=5)))
    detector.process_event(MFAEvent(user_email=email, event_type="push_sent", timestamp=datetime.utcnow() - timedelta(seconds=5)))

    # This 3rd event is now, the older ones should be purged
    alert = detector.process_event(MFAEvent(user_email=email, event_type="push_sent"))
    assert alert is None # Total count should be 1
    assert len(detector.events[email]) == 1

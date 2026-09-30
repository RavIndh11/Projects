from datetime import datetime, timedelta
from app.models import AuthEvent, EventStatus, Severity
from app.analyzer import MFAFatigueAnalyzer

def test_no_fatigue():
    analyzer = MFAFatigueAnalyzer(threshold=3)
    event1 = AuthEvent(user_id="test@example.com", status=EventStatus.REJECTED, source_ip="1.1.1.1")
    event2 = AuthEvent(user_id="test@example.com", status=EventStatus.REJECTED, source_ip="1.1.1.1")

    res1 = analyzer.analyze_event(event1)
    res2 = analyzer.analyze_event(event2)

    assert res1 is None
    assert res2 is None

def test_mfa_fatigue_alert():
    analyzer = MFAFatigueAnalyzer(threshold=3)
    user = "test@example.com"
    events = [
        AuthEvent(user_id=user, status=EventStatus.REJECTED, source_ip="1.1.1.1"),
        AuthEvent(user_id=user, status=EventStatus.REJECTED, source_ip="1.1.1.1"),
        AuthEvent(user_id=user, status=EventStatus.PENDING, source_ip="1.1.1.1"),
    ]

    for i, e in enumerate(events):
        res = analyzer.analyze_event(e)
        if i < 2:
            assert res is None
        else:
            assert res is not None
            assert res.severity == Severity.HIGH
            assert not res.is_compromised
            assert res.event_count == 3

def test_compromised_alert():
    analyzer = MFAFatigueAnalyzer(threshold=3)
    user = "victim@example.com"

    base_time = datetime.utcnow()
    events = [
        AuthEvent(user_id=user, status=EventStatus.REJECTED, source_ip="1.1.1.1", timestamp=base_time),
        AuthEvent(user_id=user, status=EventStatus.REJECTED, source_ip="1.1.1.1", timestamp=base_time + timedelta(seconds=10)),
        AuthEvent(user_id=user, status=EventStatus.REJECTED, source_ip="1.1.1.1", timestamp=base_time + timedelta(seconds=20)),
        AuthEvent(user_id=user, status=EventStatus.SUCCESS, source_ip="1.1.1.1", timestamp=base_time + timedelta(seconds=30)),
    ]

    for i, e in enumerate(events):
        res = analyzer.analyze_event(e)
        if i < 2:
            assert res is None
        elif i == 2:
            assert res is not None
            assert res.severity == Severity.HIGH
            assert not res.is_compromised
        elif i == 3:
            assert res is not None
            assert res.severity == Severity.CRITICAL
            assert res.is_compromised

def test_time_window():
    analyzer = MFAFatigueAnalyzer(time_window_minutes=5, threshold=3)
    user = "test@example.com"

    base_time = datetime.utcnow()
    # Event 1: 10 minutes ago
    e1 = AuthEvent(user_id=user, status=EventStatus.REJECTED, source_ip="1.1.1.1", timestamp=base_time - timedelta(minutes=10))
    # Event 2: 1 minute ago
    e2 = AuthEvent(user_id=user, status=EventStatus.REJECTED, source_ip="1.1.1.1", timestamp=base_time - timedelta(minutes=1))
    # Event 3: Now
    e3 = AuthEvent(user_id=user, status=EventStatus.REJECTED, source_ip="1.1.1.1", timestamp=base_time)

    assert analyzer.analyze_event(e1) is None
    assert analyzer.analyze_event(e2) is None
    # Because e1 is out of window, total events in window is 2, so threshold of 3 is not met
    assert analyzer.analyze_event(e3) is None

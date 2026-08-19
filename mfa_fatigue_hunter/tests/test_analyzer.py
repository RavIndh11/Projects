from datetime import datetime, timedelta
from app.analyzer import MFAAnalyzer
from app.models import MFALog

def test_no_alert_under_threshold():
    analyzer = MFAAnalyzer(spam_threshold=3)
    base_time = datetime.utcnow()

    # 2 pending requests, should not alert
    log1 = MFALog(user_email="test@example.com", ip_address="1.1.1.1", timestamp=base_time, status="pending")
    log2 = MFALog(user_email="test@example.com", ip_address="1.1.1.1", timestamp=base_time + timedelta(seconds=1), status="pending")

    assert analyzer.analyze(log1) is None
    assert analyzer.analyze(log2) is None

def test_medium_alert_on_spam():
    analyzer = MFAAnalyzer(spam_threshold=3)
    base_time = datetime.utcnow()

    log1 = MFALog(user_email="spam@example.com", ip_address="1.1.1.1", timestamp=base_time, status="pending")
    log2 = MFALog(user_email="spam@example.com", ip_address="1.1.1.1", timestamp=base_time + timedelta(seconds=1), status="pending")
    log3 = MFALog(user_email="spam@example.com", ip_address="1.1.1.1", timestamp=base_time + timedelta(seconds=2), status="pending")

    analyzer.analyze(log1)
    analyzer.analyze(log2)
    alert = analyzer.analyze(log3)

    assert alert is not None
    assert alert.severity == "Medium"
    assert "Active MFA Spamming" in alert.message

def test_critical_alert_on_fatigue_success():
    analyzer = MFAAnalyzer(spam_threshold=3)
    base_time = datetime.utcnow()

    # 3 spam requests followed by an approval
    analyzer.analyze(MFALog(user_email="victim@example.com", ip_address="1.1.1.1", timestamp=base_time, status="pending"))
    analyzer.analyze(MFALog(user_email="victim@example.com", ip_address="1.1.1.1", timestamp=base_time, status="pending"))
    analyzer.analyze(MFALog(user_email="victim@example.com", ip_address="1.1.1.1", timestamp=base_time, status="pending"))

    approve_log = MFALog(user_email="victim@example.com", ip_address="2.2.2.2", timestamp=base_time + timedelta(seconds=10), status="approved")
    alert = analyzer.analyze(approve_log)

    assert alert is not None
    assert alert.severity == "Critical"
    assert "MFA Fatigue Success" in alert.message

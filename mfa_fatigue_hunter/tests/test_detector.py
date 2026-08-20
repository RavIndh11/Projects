import pytest
import time
from app.detector import MFAFatigueDetector
from app.models import AuthEvent

def test_single_prompt_no_alert():
    detector = MFAFatigueDetector()
    event = AuthEvent(
        user_email="test@example.com",
        event_type="mfa_prompt",
        source_ip="1.1.1.1"
    )
    alert = detector.process_event(event)
    assert alert is None
    assert len(detector.user_prompts["test@example.com"]) == 1

def test_mfa_fatigue_alert():
    detector = MFAFatigueDetector(time_window_seconds=300, fatigue_threshold=3)

    # Prompt 1
    detector.process_event(AuthEvent(user_email="test@example.com", event_type="mfa_prompt", source_ip="1.1.1.1"))

    # Prompt 2
    alert2 = detector.process_event(AuthEvent(user_email="test@example.com", event_type="mfa_prompt", source_ip="1.1.1.1"))
    assert alert2 is None

    # Prompt 3 - Should trigger alert
    alert3 = detector.process_event(AuthEvent(user_email="test@example.com", event_type="mfa_prompt", source_ip="1.1.1.1"))
    assert alert3 is not None
    assert alert3.severity == "High"
    assert "MFA Fatigue Attack" in alert3.description

def test_successful_prompt_bombing():
    detector = MFAFatigueDetector(time_window_seconds=300, fatigue_threshold=3)

    # Simulate fatigue attack
    for _ in range(3):
        alert = detector.process_event(AuthEvent(user_email="test@example.com", event_type="mfa_prompt", source_ip="1.1.1.1"))

    # Now verify the state shows an active fatigue timestamp
    assert "test@example.com" in detector.active_fatigue_alerts

    # Simulate successful login after fatigue
    success_alert = detector.process_event(AuthEvent(user_email="test@example.com", event_type="mfa_success", source_ip="1.1.1.1"))

    assert success_alert is not None
    assert success_alert.severity == "Critical"
    assert "SUCCESSFUL MFA PROMPT BOMBING" in success_alert.description

    # Verify active fatigue is cleared
    assert "test@example.com" not in detector.active_fatigue_alerts

def test_normal_success_clears_prompts():
    detector = MFAFatigueDetector()

    # Normal prompt
    detector.process_event(AuthEvent(user_email="user@example.com", event_type="mfa_prompt", source_ip="2.2.2.2"))
    assert len(detector.user_prompts["user@example.com"]) == 1

    # Normal success
    alert = detector.process_event(AuthEvent(user_email="user@example.com", event_type="mfa_success", source_ip="2.2.2.2"))

    assert alert is None
    assert len(detector.user_prompts["user@example.com"]) == 0

def test_late_success_no_alert():
    detector = MFAFatigueDetector(time_window_seconds=10, fatigue_threshold=3)

    # Simulate fatigue attack at t=0
    for _ in range(3):
        detector.process_event(AuthEvent(user_email="test@example.com", event_type="mfa_prompt", source_ip="1.1.1.1", timestamp=100))

    assert "test@example.com" in detector.active_fatigue_alerts

    # Simulate a late success login at t=200 (well past the 10-second window)
    success_event = AuthEvent(user_email="test@example.com", event_type="mfa_success", source_ip="1.1.1.1", timestamp=200)
    alert = detector.process_event(success_event)

    # Should not alert for successful prompt bombing because it's outside the window
    assert alert is None

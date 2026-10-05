import pytest
from datetime import datetime, timedelta
from app.models.schemas import LogEntry
from app.services.analyzer import analyze_logs, state_store, recent_alerts
from app.core.config import settings

@pytest.fixture(autouse=True)
def reset_state():
    state_store.clear()
    recent_alerts.clear()
    yield

def test_no_fatigue():
    now = datetime.utcnow()
    logs = [
        LogEntry(timestamp=now, user_id="u1", action="mfa_prompt_denied"),
        LogEntry(timestamp=now + timedelta(seconds=10), user_id="u1", action="mfa_prompt_denied")
    ]

    alerts = analyze_logs(logs)
    assert len(alerts) == 0

def test_high_severity_fatigue():
    now = datetime.utcnow()
    logs = [
        LogEntry(timestamp=now, user_id="u1", action="mfa_prompt_denied"),
        LogEntry(timestamp=now + timedelta(seconds=10), user_id="u1", action="mfa_prompt_denied"),
        LogEntry(timestamp=now + timedelta(seconds=20), user_id="u1", action="mfa_prompt_ignored"),
    ]

    alerts = analyze_logs(logs)
    assert len(alerts) == 1
    assert alerts[0].severity == "High"
    assert alerts[0].user_id == "u1"
    assert alerts[0].prompt_count == 3

def test_critical_severity_fatigue():
    now = datetime.utcnow()
    logs = [
        LogEntry(timestamp=now, user_id="u1", action="mfa_prompt_denied"),
        LogEntry(timestamp=now + timedelta(seconds=10), user_id="u1", action="mfa_prompt_denied"),
        LogEntry(timestamp=now + timedelta(seconds=20), user_id="u1", action="mfa_prompt_ignored"),
        LogEntry(timestamp=now + timedelta(seconds=30), user_id="u1", action="mfa_prompt_accepted"),
    ]

    alerts = analyze_logs(logs)
    assert len(alerts) == 1
    assert alerts[0].severity == "Critical"
    assert alerts[0].user_id == "u1"

    # State should be cleared after a critical alert
    assert len(state_store.get("u1", [])) == 0

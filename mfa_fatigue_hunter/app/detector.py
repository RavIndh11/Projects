import time
from collections import defaultdict
from typing import List
from datetime import datetime, timezone
import json
import logging

from app.schemas import MFAEvent, MFAStatus, Alert, AlertSeverity

from pythonjsonlogger import jsonlogger

# Configure JSON structured logging
logger = logging.getLogger("mfa_fatigue_hunter")
logger.setLevel(logging.INFO)
# Prevent duplicate logs if handlers exist
if not logger.handlers:
    logHandler = logging.StreamHandler()
    formatter = jsonlogger.JsonFormatter(
        '%(asctime)s %(levelname)s %(name)s %(message)s'
    )
    logHandler.setFormatter(formatter)
    logger.addHandler(logHandler)


class MFADetector:
    def __init__(self, time_window_seconds: int = 300, denial_threshold: int = 3):
        # In-memory store: user_email -> list of MFAEvent
        self.events_store = defaultdict(list)
        self.alerts: List[Alert] = []

        self.time_window_seconds = time_window_seconds
        self.denial_threshold = denial_threshold

    def _cleanup_old_events(self, email: str, current_time: datetime):
        """Remove events outside the current time window."""
        valid_events = []
        for event in self.events_store[email]:
            delta = (current_time - event.timestamp).total_seconds()
            if delta <= self.time_window_seconds:
                valid_events.append(event)
        self.events_store[email] = valid_events

    def process_event(self, event: MFAEvent) -> Alert | None:
        """Process a new MFA event and return an Alert if fatigue/compromise is detected."""

        if event.timestamp.tzinfo is None:
            event.timestamp = event.timestamp.replace(tzinfo=timezone.utc)

        current_time = event.timestamp
        email = event.user_email

        # Add new event
        self.events_store[email].append(event)

        # Cleanup old events before analysis
        self._cleanup_old_events(email, current_time)

        recent_events = self.events_store[email]

        # Count denied/pending in window
        denied_or_pending = [e for e in recent_events if e.status in (MFAStatus.DENIED, MFAStatus.PENDING)]

        # Check for Fatigue Attack (High Severity)
        if event.status in (MFAStatus.DENIED, MFAStatus.PENDING) and len(denied_or_pending) >= self.denial_threshold:
            alert = Alert(
                user_email=email,
                severity=AlertSeverity.HIGH,
                message=f"Possible MFA Fatigue Attack: {len(denied_or_pending)} requests in {self.time_window_seconds}s",
                timestamp=datetime.utcnow(),
                details={"event_count": len(denied_or_pending), "window_seconds": self.time_window_seconds}
            )
            self._log_alert(alert)
            self.alerts.append(alert)
            return alert

        # Check for Compromise (Critical Severity)
        # If an approval happens immediately after a string of denials/pendings
        if event.status == MFAStatus.APPROVED:
            # Look at events strictly before this approval
            prior_events = [e for e in recent_events if e != event]
            prior_denied_or_pending = [e for e in prior_events if e.status in (MFAStatus.DENIED, MFAStatus.PENDING)]

            if len(prior_denied_or_pending) >= self.denial_threshold:
                alert = Alert(
                    user_email=email,
                    severity=AlertSeverity.CRITICAL,
                    message=f"Account Compromise Suspected: MFA Approved after {len(prior_denied_or_pending)} failed/pending attempts.",
                    timestamp=datetime.utcnow(),
                    details={"failed_attempts_before_approval": len(prior_denied_or_pending)}
                )
                self._log_alert(alert)
                self.alerts.append(alert)
                # Clear events to avoid duplicate alerts for same incident
                self.events_store[email] = []
                return alert

        return None

    def _log_alert(self, alert: Alert):
        log_data = alert.model_dump()
        log_data["timestamp"] = log_data["timestamp"].isoformat()
        logger.warning(json.dumps(log_data))

    def get_recent_alerts(self, limit: int = 50) -> List[Alert]:
        return sorted(self.alerts, key=lambda x: x.timestamp, reverse=True)[:limit]

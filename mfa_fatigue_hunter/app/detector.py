from typing import Optional
import uuid
from typing import Dict, List
from datetime import datetime, timedelta
from .models import AuthEvent, EventType, ThreatAlert, AlertSeverity

# Configuration for fatigue detection
TIME_WINDOW_MINUTES = 5
PUSH_THRESHOLD_HIGH = 5
PUSH_THRESHOLD_CRITICAL = 10

class MFAFatigueDetector:
    def __init__(self):
        # In-memory storage for events: {user_email: [AuthEvent, ...]}
        self.events: Dict[str, List[AuthEvent]] = {}
        self.alerts: List[ThreatAlert] = []

    def ingest_event(self, event: AuthEvent) -> Optional[ThreatAlert]:
        user_email = event.user_email
        if user_email not in self.events:
            self.events[user_email] = []

        self.events[user_email].append(event)

        # Cleanup old events
        self._cleanup_old_events(user_email, event.timestamp)

        return self._evaluate_fatigue(user_email, event)

    def _cleanup_old_events(self, user_email: str, current_time: datetime):
        window_start = current_time - timedelta(minutes=TIME_WINDOW_MINUTES)
        self.events[user_email] = [
            e for e in self.events[user_email]
            if e.timestamp >= window_start
        ]

    def _evaluate_fatigue(self, user_email: str, current_event: AuthEvent) -> Optional[ThreatAlert]:
        recent_events = self.events[user_email]

        pushes = [e for e in recent_events if e.event_type == EventType.MFA_PUSH_SENT]
        rejects = [e for e in recent_events if e.event_type == EventType.MFA_PUSH_REJECTED]

        push_count = len(pushes)

        if push_count == 0:
            return None

        first_push = min(pushes, key=lambda x: x.timestamp)

        # If an approval happens after multiple pushes/rejects
        if current_event.event_type == EventType.MFA_PUSH_APPROVED:
            if push_count >= PUSH_THRESHOLD_HIGH:
                return self._create_alert(
                    user_email=user_email,
                    severity=AlertSeverity.CRITICAL,
                    reason=f"MFA fatigue successful. {push_count} pushes followed by approval.",
                    event_count=push_count + 1,
                    first_event_time=first_push.timestamp,
                    last_event_time=current_event.timestamp
                )

        # Ongoing fatigue without approval yet
        if push_count >= PUSH_THRESHOLD_CRITICAL:
             return self._create_alert(
                user_email=user_email,
                severity=AlertSeverity.HIGH,
                reason=f"High volume of MFA pushes ({push_count}) detected without approval.",
                event_count=push_count,
                first_event_time=first_push.timestamp,
                last_event_time=current_event.timestamp
            )

        return None

    def _create_alert(self, user_email: str, severity: AlertSeverity, reason: str,
                      event_count: int, first_event_time: datetime, last_event_time: datetime) -> ThreatAlert:

        alert = ThreatAlert(
            alert_id=str(uuid.uuid4()),
            user_email=user_email,
            severity=severity,
            reason=reason,
            event_count=event_count,
            first_event_time=first_event_time,
            last_event_time=last_event_time
        )

        # Don't add duplicate alerts for the same ongoing issue within a short timeframe
        # In a real system, you might update an existing alert instead
        self.alerts.append(alert)
        return alert

    def get_all_alerts(self) -> List[ThreatAlert]:
        return sorted(self.alerts, key=lambda x: x.last_event_time, reverse=True)

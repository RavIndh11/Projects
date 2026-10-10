from collections import defaultdict
from datetime import datetime, timedelta
import uuid
from typing import List, Dict, Optional
from pydantic_settings import BaseSettings

from app.models import AuthEvent, Alert
from app.logger import logger

class Settings(BaseSettings):
    time_window_seconds: int = 300
    threshold_count: int = 5

    class Config:
        env_file = ".env"

settings = Settings()

class DetectionEngine:
    def __init__(self):
        # Store events per user_id
        # structure: { "user_id": [AuthEvent, AuthEvent, ...] }
        self.events: Dict[str, List[AuthEvent]] = defaultdict(list)
        self.alerts: List[Alert] = []

    def _cleanup_old_events(self, user_id: str, current_time: datetime):
        """Remove events older than the sliding window."""
        cutoff_time = current_time - timedelta(seconds=settings.time_window_seconds)
        self.events[user_id] = [
            e for e in self.events[user_id]
            if e.timestamp > cutoff_time
        ]

    def process_event(self, event: AuthEvent) -> Optional[Alert]:
        """
        Process a new AuthEvent and return an Alert if a fatigue attack is detected.
        """
        self.events[event.user_id].append(event)

        # We process alerts at the time the event arrives
        current_time = event.timestamp
        self._cleanup_old_events(event.user_id, current_time)

        # We are specifically looking for multiple mfa_push_sent or mfa_push_rejected
        # Followed by a potential mfa_push_accepted? Or just sheer volume of pushes.
        # Let's count MFA pushes sent and rejected.
        relevant_events = [
            e for e in self.events[event.user_id]
            if e.event_type in ('mfa_push_sent', 'mfa_push_rejected')
        ]

        # Let's see if a successful accept happened after many pushes
        accepted_events = [
            e for e in self.events[event.user_id]
            if e.event_type == 'mfa_push_accepted'
        ]

        if len(relevant_events) >= settings.threshold_count:
            # We have a potential attack.
            # Determine severity based on if it was ultimately accepted.
            severity = "High"
            description = f"Detected {len(relevant_events)} MFA requests/rejections in {settings.time_window_seconds}s for user {event.user_id}."

            if len(accepted_events) > 0:
                severity = "Critical"
                description += " CRITICAL: A push was ultimately accepted, indicating a possible successful fatigue attack!"

            related_ips = list(set([e.ip_address for e in relevant_events if e.ip_address]))

            alert = Alert(
                alert_id=str(uuid.uuid4()),
                user_id=event.user_id,
                severity=severity,
                timestamp=current_time,
                description=description,
                event_count=len(relevant_events),
                time_window_seconds=settings.time_window_seconds,
                related_ips=related_ips
            )

            # Record alert
            self.alerts.append(alert)
            logger.warning(
                "MFA Fatigue Alert Generated",
                extra={"alert_data": alert.model_dump()}
            )

            # Clear events to avoid spamming alerts for the same window
            self.events[event.user_id] = []

            return alert

        return None

    def get_recent_alerts(self, limit: int = 50) -> List[Alert]:
        """Return the most recent alerts, sorted by timestamp descending."""
        return sorted(self.alerts, key=lambda x: x.timestamp, reverse=True)[:limit]

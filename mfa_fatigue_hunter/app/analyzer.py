from typing import List, Dict, Optional
from datetime import datetime, timedelta
from app.models import AuthEvent, EventStatus, DetectionResult, Severity

class MFAFatigueAnalyzer:
    def __init__(self, time_window_minutes: int = 5, threshold: int = 3):
        self.time_window_minutes = time_window_minutes
        self.threshold = threshold
        # In-memory store: user_id -> List[AuthEvent]
        self.user_events: Dict[str, List[AuthEvent]] = {}

    def analyze_event(self, event: AuthEvent) -> Optional[DetectionResult]:
        """
        Ingests an event and evaluates if it triggers an MFA fatigue alert.
        """
        if event.user_id not in self.user_events:
            self.user_events[event.user_id] = []

        # Add the new event
        self.user_events[event.user_id].append(event)

        # Clean up old events outside the time window
        cutoff_time = event.timestamp - timedelta(minutes=self.time_window_minutes)
        self.user_events[event.user_id] = [
            e for e in self.user_events[event.user_id]
            if e.timestamp >= cutoff_time
        ]

        recent_events = self.user_events[event.user_id]

        return self._evaluate_events(recent_events, event.user_id)

    def _evaluate_events(self, events: List[AuthEvent], user_id: str) -> Optional[DetectionResult]:
        # Count non-success events (PENDING or REJECTED)
        spam_events = [e for e in events if e.status in (EventStatus.PENDING, EventStatus.REJECTED)]
        success_events = [e for e in events if e.status == EventStatus.SUCCESS]

        if len(spam_events) >= self.threshold:
            # Check if there's a subsequent success event
            # Ensure the success event happened after multiple spam events
            is_compromised = False
            severity = Severity.HIGH
            message = f"Potential MFA Fatigue attack detected for user {user_id}. {len(spam_events)} spam events recorded."

            if success_events:
                # Find the earliest success event that occurred after the spam threshold was reached
                # Or simply, if there's a success after multiple rejections in the same window
                # Let's verify the success came after the spam
                latest_spam_time = max(e.timestamp for e in spam_events)
                latest_success_time = max(e.timestamp for e in success_events)

                if latest_success_time >= spam_events[0].timestamp:
                    is_compromised = True
                    severity = Severity.CRITICAL
                    message = f"CRITICAL: Successful login after potential MFA Fatigue attack for user {user_id}!"

            # Extract unique IPs
            source_ips = list({e.source_ip for e in events})

            return DetectionResult(
                user_id=user_id,
                severity=severity,
                message=message,
                event_count=len(events),
                time_window_seconds=self.time_window_minutes * 60,
                first_event_time=min(e.timestamp for e in events),
                last_event_time=max(e.timestamp for e in events),
                source_ips=source_ips,
                is_compromised=is_compromised
            )

        return None

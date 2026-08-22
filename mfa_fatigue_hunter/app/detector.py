from typing import Dict, List, Optional
from datetime import datetime, timedelta
import threading
from .models import MFAEvent, ThreatAlert
import logging
from pythonjsonlogger import jsonlogger

logger = logging.getLogger(__name__)
logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(name)s %(message)s')
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)
logger.setLevel(logging.INFO)

class MFAFatigueDetector:
    def __init__(self, time_window_seconds: int = 300, threshold_medium: int = 3, threshold_high: int = 5, threshold_critical: int = 10):
        self.time_window_seconds = time_window_seconds
        self.threshold_medium = threshold_medium
        self.threshold_high = threshold_high
        self.threshold_critical = threshold_critical
        self.events: Dict[str, List[MFAEvent]] = {}
        self.alerts: List[ThreatAlert] = []
        self.lock = threading.Lock()

    def process_event(self, event: MFAEvent) -> Optional[ThreatAlert]:
        if event.event_type != "push_sent":
            return None # Only track push_sent for fatigue

        with self.lock:
            if event.user_email not in self.events:
                self.events[event.user_email] = []

            self.events[event.user_email].append(event)

            # Clean up old events
            cutoff_time = event.timestamp - timedelta(seconds=self.time_window_seconds)
            self.events[event.user_email] = [e for e in self.events[event.user_email] if e.timestamp >= cutoff_time]

            recent_events = self.events[event.user_email]
            push_count = len(recent_events)

            if push_count >= self.threshold_medium:
                severity = "Medium"
                if push_count >= self.threshold_critical:
                    severity = "Critical"
                elif push_count >= self.threshold_high:
                    severity = "High"

                alert = ThreatAlert(
                    user_email=event.user_email,
                    severity=severity,
                    push_count=push_count,
                    time_window_seconds=self.time_window_seconds,
                    first_event_time=recent_events[0].timestamp,
                    last_event_time=recent_events[-1].timestamp,
                    description=f"Detected {push_count} MFA pushes for {event.user_email} within {self.time_window_seconds} seconds."
                )

                # Check if we already alerted for this specific count to avoid spamming the UI too much,
                # but we'll append it to keep a history of escalations.
                self.alerts.append(alert)
                logger.warning("MFA Fatigue Detected", extra={"alert_details": alert.model_dump()})
                return alert

        return None

    def get_alerts(self) -> List[ThreatAlert]:
        with self.lock:
            # Return a copy sorted by most recent
            return sorted(self.alerts, key=lambda x: x.last_event_time, reverse=True)

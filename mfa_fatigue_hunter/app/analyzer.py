import os
import threading
from collections import defaultdict
from datetime import datetime, timezone
import logging
from pythonjsonlogger import jsonlogger
from .models import MFALogEvent, AlertEvent

# Configure JSON Logging
logger = logging.getLogger("mfa_analyzer")
logger.setLevel(logging.INFO)
logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(message)s')
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)

class MFAAnalyzer:
    def __init__(self):
        self.events = defaultdict(list)
        self.lock = threading.Lock()

        # Load config from env or default
        try:
            self.threshold = int(os.environ.get("MFA_FATIGUE_THRESHOLD", 5))
            self.time_window = int(os.environ.get("MFA_TIME_WINDOW", 60))
        except ValueError:
            self.threshold = 5
            self.time_window = 60

        logger.info(f"Analyzer initialized with threshold {self.threshold} in {self.time_window}s window.")

    def process_event(self, event: MFALogEvent) -> AlertEvent | None:
        """
        Process an incoming MFA event and detect if a fatigue attack is occurring.
        Only considers 'pending' or 'denied' push_notification events as indicators of fatigue.
        """
        # We primarily care about push notifications for fatigue bombing
        if event.event_type != 'push_notification' or event.status not in ['pending', 'denied']:
            return None

        current_time = datetime.now(timezone.utc)
        user_id = event.user_id

        with self.lock:
            # Add the new event timestamp
            self.events[user_id].append(event.timestamp)

            # Filter events within the time window
            recent_events = [
                ts for ts in self.events[user_id]
                if (current_time - ts).total_seconds() <= self.time_window
            ]
            self.events[user_id] = recent_events

            event_count = len(recent_events)

            if event_count >= self.threshold:
                alert = AlertEvent(
                    user_id=user_id,
                    severity="CRITICAL",
                    message=f"MFA Fatigue Attack Detected: {event_count} pushes in {self.time_window} seconds.",
                    event_count=event_count,
                    time_window=self.time_window,
                    timestamp=current_time
                )

                logger.warning("MFA Fatigue Alert Generated", extra={
                    "user_id": user_id,
                    "event_count": event_count,
                    "time_window": self.time_window,
                    "ip_address": str(event.ip_address)
                })

                # To prevent spamming alerts for the same user repeatedly, we can optionally clear
                # or throttle. For this implementation, we will clear the recent events after alerting.
                self.events[user_id] = []

                return alert

        return None

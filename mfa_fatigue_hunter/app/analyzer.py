import threading
import uuid
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from .models import MFALog, Alert

class MFAAnalyzer:
    def __init__(self, time_window_seconds: int = 300, spam_threshold: int = 5):
        self.time_window_seconds = time_window_seconds
        self.spam_threshold = spam_threshold
        # Stores logs per user email. In a real app, use Redis.
        self.user_logs: Dict[str, List[MFALog]] = {}
        self.lock = threading.Lock()

    def analyze(self, log: MFALog) -> Optional[Alert]:
        with self.lock:
            if log.user_email not in self.user_logs:
                self.user_logs[log.user_email] = []

            # Append new log
            self.user_logs[log.user_email].append(log)

            # Prune old logs outside the time window
            cutoff_time = log.timestamp - timedelta(seconds=self.time_window_seconds)
            self.user_logs[log.user_email] = [
                l for l in self.user_logs[log.user_email]
                if l.timestamp >= cutoff_time
            ]

            recent_logs = self.user_logs[log.user_email]

            # Count the number of 'pending' or 'denied' requests that are considered part of the spam
            spam_requests = [l for l in recent_logs if l.status in ["pending", "denied", "timeout"]]
            spam_count = len(spam_requests)

            alert = None

            # Check for critical alert: Spam followed by an approval
            if log.status == "approved" and spam_count >= self.spam_threshold:
                alert = Alert(
                    alert_id=str(uuid.uuid4()),
                    severity="Critical",
                    user_email=log.user_email,
                    message=f"Possible MFA Fatigue Success: {spam_count} spam requests followed by an approval.",
                    timestamp=datetime.utcnow(),
                    trigger_count=spam_count + 1
                )
                # Clear logs after critical alert to avoid duplicate alerts for the same event chain
                self.user_logs[log.user_email] = []

            # Check for medium alert: High volume of pending/denied requests (active spamming)
            elif spam_count >= self.spam_threshold and log.status in ["pending", "denied"]:
                alert = Alert(
                    alert_id=str(uuid.uuid4()),
                    severity="Medium",
                    user_email=log.user_email,
                    message=f"Active MFA Spamming detected: {spam_count} requests in {self.time_window_seconds}s.",
                    timestamp=datetime.utcnow(),
                    trigger_count=spam_count
                )

            return alert

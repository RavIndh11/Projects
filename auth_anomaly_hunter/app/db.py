import threading
from typing import Optional, List, Dict
from app.models import AuthLog, AnomalyAlert

# Thread-safe in-memory storage for state and alerts
class DB:
    def __init__(self):
        self._lock = threading.Lock()
        self._last_logins: Dict[str, AuthLog] = {}
        self._alerts: List[AnomalyAlert] = []

    def get_last_login(self, user_id: str) -> Optional[AuthLog]:
        with self._lock:
            return self._last_logins.get(user_id)

    def set_last_login(self, user_id: str, log: AuthLog):
        with self._lock:
            # Only update if the new log is more recent (or if there's no existing log)
            existing = self._last_logins.get(user_id)
            if not existing or log.timestamp > existing.timestamp:
                self._last_logins[user_id] = log

    def add_alert(self, alert: AnomalyAlert):
        with self._lock:
            self._alerts.append(alert)

    def get_alerts(self, limit: int = 50) -> List[AnomalyAlert]:
        with self._lock:
            # Return a copy of the most recent alerts
            return sorted(self._alerts, key=lambda x: x.timestamp, reverse=True)[:limit]

    def clear(self):
        with self._lock:
            self._last_logins.clear()
            self._alerts.clear()

# Global singleton instance
db = DB()

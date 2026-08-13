import math
from typing import Dict, List, Optional
from datetime import datetime, timezone
from app.models import AuthEvent, AnomalyResult

def haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculate the great circle distance between two points
    on the earth (specified in decimal degrees)
    Returns distance in kilometers.
    """
    # Convert decimal degrees to radians
    lon1, lat1, lon2, lat2 = map(math.radians, [lon1, lat1, lon2, lat2])

    # Haversine formula
    dlon = lon2 - lon1
    dlat = lat2 - lat1
    a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
    c = 2 * math.asin(math.sqrt(a))
    r = 6371 # Radius of earth in kilometers. Use 3956 for miles.
    return c * r

class AnomalyEngine:
    def __init__(self, impossible_travel_speed_kmh: float = 900.0, brute_force_time_window_sec: float = 300.0, brute_force_max_failures: int = 5):
        self.impossible_travel_speed_kmh = impossible_travel_speed_kmh
        self.brute_force_time_window_sec = brute_force_time_window_sec
        self.brute_force_max_failures = brute_force_max_failures

        # State storage (in a real app, this would be Redis or a database)
        self.last_success_events: Dict[str, AuthEvent] = {}
        self.failed_attempts: Dict[str, List[datetime]] = {}
        self.detected_anomalies: List[AnomalyResult] = []

    def process_event(self, event: AuthEvent) -> List[AnomalyResult]:
        anomalies = []

        if event.status == "success":
            # Check for impossible travel
            last_event = self.last_success_events.get(event.user_id)
            if last_event and event.location and last_event.location:
                # Calculate time difference in hours
                time_diff = (event.timestamp - last_event.timestamp).total_seconds() / 3600.0

                # Only check if time difference is positive and > 0
                if time_diff > 0:
                    distance = haversine(
                        last_event.location.lat, last_event.location.lon,
                        event.location.lat, event.location.lon
                    )
                    speed = distance / time_diff

                    if speed > self.impossible_travel_speed_kmh:
                        anomaly = AnomalyResult(
                            user_id=event.user_id,
                            anomaly_type="impossible_travel",
                            severity="High",
                            description=f"Impossible travel detected: {distance:.2f} km in {time_diff:.2f} hours ({speed:.2f} km/h)",
                            timestamp=datetime.now(timezone.utc)
                        )
                        anomalies.append(anomaly)
                        self.detected_anomalies.append(anomaly)

            # Update last success event
            self.last_success_events[event.user_id] = event
            # Clear failures on success
            if event.user_id in self.failed_attempts:
                del self.failed_attempts[event.user_id]

        elif event.status == "failure":
            # Brute force detection
            now = event.timestamp

            if event.user_id not in self.failed_attempts:
                self.failed_attempts[event.user_id] = []

            self.failed_attempts[event.user_id].append(now)

            # Clean up old failures
            self.failed_attempts[event.user_id] = [
                t for t in self.failed_attempts[event.user_id]
                if (now - t).total_seconds() <= self.brute_force_time_window_sec
            ]

            # Check threshold
            if len(self.failed_attempts[event.user_id]) >= self.brute_force_max_failures:
                # Only alert once per window basically, or repeatedly if they keep trying
                anomaly = AnomalyResult(
                    user_id=event.user_id,
                    anomaly_type="brute_force",
                    severity="Medium",
                    description=f"Brute force detected: {len(self.failed_attempts[event.user_id])} failures within {self.brute_force_time_window_sec} seconds",
                    timestamp=datetime.now(timezone.utc)
                )
                anomalies.append(anomaly)
                self.detected_anomalies.append(anomaly)

                # Prevent spamming: clear the history after alerting
                self.failed_attempts[event.user_id] = []

        return anomalies

    def get_recent_anomalies(self, limit: int = 50) -> List[AnomalyResult]:
        return list(reversed(self.detected_anomalies))[:limit]

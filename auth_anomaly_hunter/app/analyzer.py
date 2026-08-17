import math
import uuid
from typing import Optional, Tuple
from datetime import datetime, timezone
import logging

from app.models import AuthLog, AnomalyAlert
from app.geo import get_coordinates

logger = logging.getLogger("auth_anomaly_hunter.analyzer")

# Max plausible travel speed in km/h (e.g., commercial airliner speed)
MAX_PLAUSIBLE_SPEED_KMH = 1000.0

def haversine_distance(coord1: Tuple[float, float], coord2: Tuple[float, float]) -> float:
    """
    Calculate the great circle distance in kilometers between two points
    on the earth (specified in decimal degrees)
    """
    lat1, lon1 = coord1
    lat2, lon2 = coord2

    # Convert decimal degrees to radians
    lon1, lat1, lon2, lat2 = map(math.radians, [lon1, lat1, lon2, lat2])

    # Haversine formula
    dlon = lon2 - lon1
    dlat = lat2 - lat1
    a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
    c = 2 * math.asin(math.sqrt(a))
    r = 6371 # Radius of earth in kilometers
    return c * r

async def analyze_login(current_log: AuthLog, previous_log: Optional[AuthLog]) -> Optional[AnomalyAlert]:
    """
    Analyzes a login event against the previous login event for the same user.
    Returns an AnomalyAlert if 'impossible travel' is detected.
    """
    if not previous_log:
        return None

    # We need timestamps to be aware of timezone, convert if naive, but pydantic datetime is usually tz-aware
    curr_time = current_log.timestamp
    prev_time = previous_log.timestamp

    # Ensure timezone awareness for subtraction
    if curr_time.tzinfo is None:
        curr_time = curr_time.replace(tzinfo=timezone.utc)
    if prev_time.tzinfo is None:
        prev_time = prev_time.replace(tzinfo=timezone.utc)

    time_diff_hours = (curr_time - prev_time).total_seconds() / 3600.0

    # If the logins are too close in time or out of order, or we're missing time, handle gracefully
    if time_diff_hours <= 0:
        return None

    # Only process if IPs are different
    if str(current_log.ip_address) == str(previous_log.ip_address):
        return None

    coord_curr = await get_coordinates(str(current_log.ip_address))
    coord_prev = await get_coordinates(str(previous_log.ip_address))

    if not coord_curr or not coord_prev:
        return None

    distance_km = haversine_distance(coord_prev, coord_curr)

    # If distance is negligible, don't flag
    if distance_km < 50.0:
        return None

    speed_kmh = distance_km / time_diff_hours

    if speed_kmh > MAX_PLAUSIBLE_SPEED_KMH:
        logger.warning(f"Impossible travel detected for user {current_log.user_id}: {speed_kmh:.2f} km/h")

        # Determine severity based on speed and distance
        if speed_kmh > 5000:
            severity = "Critical"
        elif speed_kmh > 2000:
            severity = "High"
        else:
            severity = "Medium"

        return AnomalyAlert(
            alert_id=str(uuid.uuid4()),
            user_id=current_log.user_id,
            severity=severity,
            description=f"Impossible travel detected. Calculated speed: {speed_kmh:.2f} km/h",
            timestamp=datetime.now(timezone.utc),
            details={
                "previous_ip": str(previous_log.ip_address),
                "current_ip": str(current_log.ip_address),
                "distance_km": round(distance_km, 2),
                "time_diff_hours": round(time_diff_hours, 2),
                "speed_kmh": round(speed_kmh, 2)
            }
        )

    return None

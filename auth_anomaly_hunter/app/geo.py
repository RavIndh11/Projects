import httpx
import logging
from typing import Optional, Tuple

logger = logging.getLogger("auth_anomaly_hunter.geo")

# Simple in-memory cache for IP coordinates
_geo_cache = {}

async def get_coordinates(ip_address: str) -> Optional[Tuple[float, float]]:
    """
    Simulates a geo-location lookup, mapping an IP address to (latitude, longitude).
    Uses ip-api.com for a basic free lookup, with caching.
    """
    if ip_address in _geo_cache:
        return _geo_cache[ip_address]

    # Handle loopback/private IPs for testing
    if ip_address in ("127.0.0.1", "::1") or ip_address.startswith("10.") or ip_address.startswith("192.168."):
         # Default to some arbitrary location for local testing (e.g., Null Island or a specific test coord)
         _geo_cache[ip_address] = (0.0, 0.0)
         return (0.0, 0.0)

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"http://ip-api.com/json/{ip_address}")
            response.raise_for_status()
            data = response.json()

            if data.get("status") == "success":
                lat = data.get("lat")
                lon = data.get("lon")
                if lat is not None and lon is not None:
                    _geo_cache[ip_address] = (float(lat), float(lon))
                    return (float(lat), float(lon))
            else:
                 logger.warning(f"Geo lookup failed for {ip_address}: {data.get('message')}")
    except httpx.RequestError as e:
        logger.error(f"Error fetching geo data for {ip_address}: {e}")
    except Exception as e:
         logger.error(f"Unexpected error in geo lookup for {ip_address}: {e}")

    return None

# For testing purposes, allow clearing the cache
def clear_cache():
    _geo_cache.clear()

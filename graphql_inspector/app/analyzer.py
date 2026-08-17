import httpx

import socket
from urllib.parse import urlparse
import ipaddress
from app.schemas import AnalysisReport, SensitiveField
from app.logger import logger

# Sensitve keywords to look for in schema
SENSITIVE_KEYWORDS = [
    "password", "token", "secret", "ssn", "creditcard", "apikey",
    "socialsecurity", "private", "credential"
]

def is_safe_url(url: str) -> bool:
    """
    Validates URL to prevent basic SSRF.
    Rejects localhost, local network IPs, and invalid schemes.
    (Note: DNS rebinding is still a potential threat not fully solved by this synchronous check).
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ["http", "https"]:
            return False

        hostname = parsed.hostname
        if not hostname:
            return False

        # Block literal loopback/private IPs
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
                return False
        except ValueError:
            pass # Not an IP address, proceed to DNS resolution

        # Resolve DNS and block private IPs
        # This is basic and still susceptible to TOCTOU/DNS Rebinding
        try:
            ip_addr = socket.gethostbyname(hostname)
            ip = ipaddress.ip_address(ip_addr)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
                return False
        except socket.gaierror:
            # Cannot resolve
            return False

        return True
    except Exception as e:
        logger.error(f"Error validating URL {url}: {e}")
        return False


def get_introspection_query() -> str:
    return """
    query IntrospectionQuery {
      __schema {
        types {
          name
          kind
          fields {
            name
            type {
              name
              kind
              ofType {
                name
                kind
              }
            }
          }
        }
      }
    }
    """

async def analyze_graphql_endpoint(url: str) -> AnalysisReport:
    """
    Analyzes a GraphQL endpoint by attempting introspection.
    """
    if not is_safe_url(url):
        logger.warning(f"Rejected unsafe URL: {url}")
        return AnalysisReport(url=url, introspection_enabled=False, error_message="Invalid or unsafe URL (SSRF protection).")

    logger.info(f"Analyzing GraphQL endpoint: {url}")

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "GraphQL-Inspector-Security-Tool"
    }
    payload = {
        "query": get_introspection_query()
    }

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            response = await client.post(url, json=payload, headers=headers)

            if response.status_code == 200:
                data = response.json()
                if "data" in data and "__schema" in data["data"]:
                    # Introspection successful
                    logger.info(f"Introspection ENABLED at {url}")
                    return parse_schema(url, data["data"]["__schema"])
                else:
                    logger.info(f"Introspection disabled or invalid response at {url}")
                    return AnalysisReport(url=url, introspection_enabled=False, error_message="Introspection not enabled or returned unexpected structure.")
            else:
                 logger.info(f"Endpoint {url} returned HTTP {response.status_code}")
                 return AnalysisReport(url=url, introspection_enabled=False, error_message=f"HTTP Error: {response.status_code}")

    except httpx.RequestError as e:
        logger.error(f"Request error analyzing {url}: {e}")
        return AnalysisReport(url=url, introspection_enabled=False, error_message=f"Request failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error analyzing {url}: {e}")
        return AnalysisReport(url=url, introspection_enabled=False, error_message=f"Unexpected error: {str(e)}")

def parse_schema(url: str, schema: dict) -> AnalysisReport:
    report = AnalysisReport(url=url, introspection_enabled=True)

    types = schema.get("types", [])
    report.total_types = len(types)

    for t in types:
        type_name = t.get("name")
        if not type_name or type_name.startswith("__"):
            continue # Skip internal types

        fields = t.get("fields")
        if not fields:
            continue

        for field in fields:
            field_name = field.get("name", "")

            # Check for sensitive keywords in field names
            for keyword in SENSITIVE_KEYWORDS:
                if keyword in field_name.lower():
                    report.sensitive_fields.append(
                        SensitiveField(
                            type_name=type_name,
                            field_name=field_name,
                            reason=f"Matches sensitive keyword: '{keyword}'"
                        )
                    )
                    break # Don't add same field multiple times for different keywords

    return report

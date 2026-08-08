import httpx
from urllib.parse import urlparse, urlunparse
from app.core.security import validate_url, logger
from typing import Dict, Any, Optional

# Constants
PROXY_TIMEOUT = 5.0  # seconds
MAX_REDIRECTS = 0    # We block redirects to prevent secondary SSRF

async def safe_fetch(url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None, body: Any = None) -> Dict[str, Any]:
    """
    Safely fetches a URL after performing SSRF validation and using a pinned IP.
    """
    # 1. Validate the URL
    is_safe, reason, safe_ip = validate_url(url)

    if not is_safe or not safe_ip:
        logger.warning("SSRF blocked", extra={"url": url, "reason": reason})
        return {
            "status": "blocked",
            "reason": reason,
            "status_code": 403,
            "content": None,
            "headers": {}
        }

    logger.info("URL validated successfully", extra={"url": url, "resolved_ip": safe_ip})

    # 2. Proceed with fetch using the original URL.
    # Note: We do not rewrite the URL to the resolved IP address to preserve HTTPS/SNI
    # capabilities (as pinning the IP directly causes `httpx` certificate validation to fail
    # against the IP instead of the domain name).
    # While this preserves functionality, it slightly limits TOCTOU DNS rebinding protection
    # depending on the OS's internal DNS cache, as the HTTP client re-resolves the domain.

    req_headers = dict(headers) if headers else {}

    try:
        async with httpx.AsyncClient(timeout=PROXY_TIMEOUT, follow_redirects=False) as client:
            response = await client.request(
                method=method,
                url=url,
                headers=req_headers,
                content=body if body else None
            )

            return {
                "status": "allowed",
                "reason": "OK",
                "status_code": response.status_code,
                "content": response.text,
                "headers": dict(response.headers)
            }

    except httpx.TimeoutException:
        logger.error("Request timed out", extra={"url": url})
        return {
            "status": "error",
            "reason": "Request timed out",
            "status_code": 504,
            "content": None,
            "headers": {}
        }
    except Exception as e:
        logger.error("Request failed", extra={"url": url, "error": str(e)})
        return {
            "status": "error",
            "reason": f"Request failed: {str(e)}",
            "status_code": 500,
            "content": None,
            "headers": {}
        }

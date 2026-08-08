import ipaddress
import socket
from urllib.parse import urlparse
from app.core.logger import logger

# List of blocked CIDRs based on RFC 1918, RFC 4193, RFC 4291, and Cloud Metadata IPs
BLOCKED_CIDRS = [
    ipaddress.ip_network('127.0.0.0/8'),        # IPv4 loopback
    ipaddress.ip_network('10.0.0.0/8'),         # RFC1918
    ipaddress.ip_network('172.16.0.0/12'),      # RFC1918
    ipaddress.ip_network('192.168.0.0/16'),     # RFC1918
    ipaddress.ip_network('169.254.0.0/16'),     # RFC3927 (Cloud Metadata)
    ipaddress.ip_network('0.0.0.0/8'),          # Current network
    ipaddress.ip_network('::1/128'),            # IPv6 loopback
    ipaddress.ip_network('::/128'),             # IPv6 unspecified (often maps to localhost)
    ipaddress.ip_network('fc00::/7'),           # IPv6 Unique Local Addresses
    ipaddress.ip_network('fe80::/10'),          # IPv6 Link-local addresses
]

def is_ip_blocked(ip_str: str) -> bool:
    """Checks if an IP address is in a blocked CIDR."""
    try:
        ip = ipaddress.ip_address(ip_str)

        # Prevent IPv4-mapped IPv6 bypass (e.g., ::ffff:127.0.0.1)
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped

        for cidr in BLOCKED_CIDRS:
            if ip in cidr:
                logger.warning(f"Blocked IP matched CIDR", extra={"ip": ip_str, "cidr": str(cidr)})
                return True
        return False
    except ValueError:
        logger.error(f"Invalid IP address format", extra={"ip": ip_str})
        return True # Block invalid IPs

def resolve_hostname(hostname: str) -> list[str]:
    """Resolves a hostname to a list of IP addresses."""
    try:
        # getaddrinfo returns a list of tuples: (family, type, proto, canonname, sockaddr)
        # sockaddr is a tuple (address, port) for IPv4 or (address, port, flow info, scope id) for IPv6
        addrs = socket.getaddrinfo(hostname, None)
        ips = [addr[4][0] for addr in addrs]
        return list(set(ips)) # Return unique IPs
    except socket.gaierror as e:
        logger.error(f"DNS resolution failed", extra={"hostname": hostname, "error": str(e)})
        return []

def validate_url(url: str) -> tuple[bool, str, str | None]:
    """
    Validates a URL against SSRF attacks.
    Returns (is_valid, reason, resolved_ip)
    """
    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"URL parsing error: {e}", None

    if parsed.scheme not in ('http', 'https'):
        return False, "Unsupported scheme (only http/https allowed)", None

    hostname = parsed.hostname
    if not hostname:
        return False, "No hostname found in URL", None

    # Resolve hostname to IPs
    ips = resolve_hostname(hostname)

    if not ips:
        return False, "Could not resolve hostname", None

    # Check all resolved IPs to prevent DNS rebinding attacks where an attacker
    # might return both a safe and an unsafe IP.
    for ip in ips:
        if is_ip_blocked(ip):
            return False, f"Hostname resolved to a blocked IP: {ip}", ip

    # If all IPs are safe, return the first one as the safe IP to use for the proxy request
    # This mitigates Time-of-Check to Time-of-Use (TOCTOU) DNS Rebinding
    return True, "URL is safe", ips[0]

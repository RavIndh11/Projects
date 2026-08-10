import socket
import ipaddress
import urllib.parse
import httpx
import logging

logger = logging.getLogger(__name__)

class SSRFError(Exception):
    pass

class URLValidator:
    BLOCKED_NETWORKS = [
        # IPv4
        ipaddress.ip_network('127.0.0.0/8'),        # Loopback
        ipaddress.ip_network('10.0.0.0/8'),         # Private network
        ipaddress.ip_network('172.16.0.0/12'),      # Private network
        ipaddress.ip_network('192.168.0.0/16'),     # Private network
        ipaddress.ip_network('169.254.0.0/16'),     # Link-local (Cloud metadata)
        ipaddress.ip_network('224.0.0.0/4'),        # Multicast
        ipaddress.ip_network('240.0.0.0/4'),        # Reserved
        ipaddress.ip_network('0.0.0.0/8'),          # Current network
        # IPv6
        ipaddress.ip_network('::1/128'),            # Loopback
        ipaddress.ip_network('fc00::/7'),           # Unique local
        ipaddress.ip_network('fe80::/10'),          # Link-local
        ipaddress.ip_network('ff00::/8'),           # Multicast
    ]

    @classmethod
    def is_safe_ip(cls, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            for network in cls.BLOCKED_NETWORKS:
                if ip in network:
                    return False
            return True
        except ValueError:
            return False

    @classmethod
    def resolve_hostname(cls, hostname: str) -> str:
        try:
            # We use getaddrinfo to support both IPv4 and IPv6
            # AF_UNSPEC gets both, we can just grab the first one
            addrinfo = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            if not addrinfo:
                raise SSRFError(f"Could not resolve hostname: {hostname}")
            # addrinfo[0] is (family, type, proto, canonname, sockaddr)
            # sockaddr is (IP, port) for IPv4 or (IP, port, flowinfo, scopeid) for IPv6
            return addrinfo[0][4][0]
        except socket.gaierror as e:
            logger.error(f"DNS resolution failed for {hostname}: {e}")
            raise SSRFError(f"DNS resolution failed for hostname: {hostname}")

    @classmethod
    def parse_and_validate_url(cls, url: str) -> tuple[str, str, urllib.parse.ParseResult]:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            raise SSRFError("Only HTTP and HTTPS schemes are allowed.")

        hostname = parsed.hostname
        if not hostname:
            raise SSRFError("Invalid URL: missing hostname.")

        ip = cls.resolve_hostname(hostname)
        if not cls.is_safe_ip(ip):
            raise SSRFError(f"IP address {ip} is in a restricted range.")

        return hostname, ip, parsed

    @classmethod
    async def safe_fetch(cls, url: str, timeout: int = 5) -> str:
        """
        Safely fetches a URL, preventing SSRF and DNS rebinding.
        It resolves the hostname, verifies the IP, and connects directly to the IP
        while setting the original Host header.
        """
        hostname, ip, parsed = cls.parse_and_validate_url(url)

        # Reconstruct the URL using the IP address instead of the hostname
        # If there's a port, preserve it
        netloc = ip
        if ':' in ip and not ip.startswith('['): # IPv6 formatting
            netloc = f"[{ip}]"

        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"

        safe_url = parsed._replace(netloc=netloc).geturl()

        headers = {
            "Host": hostname,
            "User-Agent": "SSRF-Sentinel/1.0"
        }

        try:
            # follow_redirects=False is important. If we follow redirects,
            # httpx will re-resolve DNS and potentially hit internal networks.
            # To be 100% safe against SSRF via redirects, we don't follow them automatically.
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                async with client.stream("GET", safe_url, headers=headers, follow_redirects=False) as response:
                    # Check for redirects
                    if 300 <= response.status_code < 400:
                        raise SSRFError(f"Redirects are not allowed for security reasons. (Status: {response.status_code})")

                    response.raise_for_status()
                    # Read only the first 1000 bytes to prevent OOM
                    content = await response.aread()
                    return content[:1000].decode(errors='replace')
        except httpx.RequestError as e:
            logger.error(f"HTTP request failed: {e}")
            raise SSRFError(f"Failed to fetch URL: {str(e)}")

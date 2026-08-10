import pytest
from app.ssrf import URLValidator, SSRFError
import httpx
from unittest.mock import patch, MagicMock, AsyncMock

class TestSSRF:
    def test_safe_ip(self):
        assert URLValidator.is_safe_ip("8.8.8.8") is True
        assert URLValidator.is_safe_ip("1.1.1.1") is True

        # Private IPs
        assert URLValidator.is_safe_ip("10.0.0.1") is False
        assert URLValidator.is_safe_ip("192.168.1.1") is False
        assert URLValidator.is_safe_ip("172.16.0.1") is False

        # Localhost
        assert URLValidator.is_safe_ip("127.0.0.1") is False
        assert URLValidator.is_safe_ip("::1") is False

        # Cloud metadata
        assert URLValidator.is_safe_ip("169.254.169.254") is False

    @patch('socket.getaddrinfo')
    def test_resolve_hostname_success(self, mock_getaddrinfo):
        # Mocking a successful resolution for example.com to an IP
        mock_getaddrinfo.return_value = [(2, 1, 6, '', ('93.184.216.34', 0))]
        ip = URLValidator.resolve_hostname("example.com")
        assert ip == "93.184.216.34"

    @patch('socket.getaddrinfo')
    def test_resolve_hostname_failure(self, mock_getaddrinfo):
        import socket
        mock_getaddrinfo.side_effect = socket.gaierror("DNS resolution failed")
        with pytest.raises(SSRFError, match="DNS resolution failed for hostname"):
            URLValidator.resolve_hostname("invalid.domain.that.does.not.exist")

    @patch('app.ssrf.URLValidator.resolve_hostname')
    def test_parse_and_validate_url_success(self, mock_resolve):
        mock_resolve.return_value = "8.8.8.8"
        hostname, ip, parsed = URLValidator.parse_and_validate_url("https://example.com/path?query=1")
        assert hostname == "example.com"
        assert ip == "8.8.8.8"

    @patch('app.ssrf.URLValidator.resolve_hostname')
    def test_parse_and_validate_url_blocked_ip(self, mock_resolve):
        mock_resolve.return_value = "127.0.0.1"
        with pytest.raises(SSRFError, match="restricted range"):
            URLValidator.parse_and_validate_url("http://localhost:8080")

    def test_parse_and_validate_url_invalid_scheme(self):
        with pytest.raises(SSRFError, match="Only HTTP and HTTPS"):
            URLValidator.parse_and_validate_url("ftp://example.com")

    @pytest.mark.asyncio
    @patch('app.ssrf.URLValidator.parse_and_validate_url')
    @patch('httpx.AsyncClient.stream')
    async def test_safe_fetch_success(self, mock_stream, mock_parse):
        # Mock URL parsing and validation
        import urllib.parse
        mock_parse.return_value = ("example.com", "93.184.216.34", urllib.parse.urlparse("https://example.com"))

        # Mock httpx response
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.aread.return_value = b"Hello World"
        mock_response.raise_for_status = MagicMock()

        # Make the stream context manager return the mock response
        mock_context_manager = AsyncMock()
        mock_context_manager.__aenter__.return_value = mock_response
        mock_stream.return_value = mock_context_manager

        result = await URLValidator.safe_fetch("https://example.com")
        assert result == "Hello World"
        mock_stream.assert_called_once()

    @pytest.mark.asyncio
    @patch('app.ssrf.URLValidator.parse_and_validate_url')
    @patch('httpx.AsyncClient.stream')
    async def test_safe_fetch_redirect_blocked(self, mock_stream, mock_parse):
        # Mock URL parsing and validation
        import urllib.parse
        mock_parse.return_value = ("example.com", "93.184.216.34", urllib.parse.urlparse("https://example.com"))

        # Mock httpx response returning a redirect
        mock_response = AsyncMock()
        mock_response.status_code = 302

        mock_context_manager = AsyncMock()
        mock_context_manager.__aenter__.return_value = mock_response
        mock_stream.return_value = mock_context_manager

        with pytest.raises(SSRFError, match="Redirects are not allowed"):
            await URLValidator.safe_fetch("https://example.com")

    @pytest.mark.asyncio
    @patch('app.ssrf.URLValidator.parse_and_validate_url')
    @patch('httpx.AsyncClient.stream')
    async def test_safe_fetch_request_error(self, mock_stream, mock_parse):
        import urllib.parse
        mock_parse.return_value = ("example.com", "93.184.216.34", urllib.parse.urlparse("https://example.com"))
        mock_stream.side_effect = httpx.RequestError("Connection timeout")

        with pytest.raises(SSRFError, match="Failed to fetch URL"):
            await URLValidator.safe_fetch("https://example.com")

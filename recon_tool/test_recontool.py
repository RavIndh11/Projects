import pytest
import sys
import os
import socket
from unittest.mock import patch, MagicMock, mock_open

# Ensure the recon_tool folder is in the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from recontool import (
    is_ip,
    whois_lookup,
    dns_enum,
    ip_geolocation,
    reverse_dns_lookup,
    passive_subdomains,
    analyze_security_headers,
    check_ssl_cert,
    parse_ssl_cert,
    socket_port_scan,
    nmap_scan,
    format_results_as_text
)

def test_is_ip():
    assert is_ip("192.168.1.1") is True
    assert is_ip("8.8.8.8") is True
    assert is_ip("256.100.0.1") is False  # Invalid octet
    assert is_ip("example.com") is False
    assert is_ip("2001:db8::1") is True  # Contains colon, so falls back to basic IPv6 check

@patch("recontool.whois.whois")
def test_whois_lookup(mock_whois):
    # Mock WHOIS dictionary-like response
    mock_whois.return_value = {"domain_name": "example.com", "registrar": "GoDaddy"}
    res = whois_lookup("example.com")
    assert isinstance(res, dict)
    assert res["registrar"] == "GoDaddy"

    # Mock WHOIS failure
    mock_whois.side_effect = Exception("WHOIS Error")
    res_err = whois_lookup("example.com")
    assert "WHOIS lookup failed" in res_err

@patch("recontool.shutil.which")
@patch("recontool.subprocess.check_output")
@patch("recontool.socket.gethostbyname_ex")
def test_dns_enum_with_dig(mock_gethostbyname, mock_check_output, mock_which):
    # Case 1: dig is available
    mock_which.return_value = "/usr/bin/dig"
    mock_check_output.return_value = b"1.2.3.4\n"

    res = dns_enum("example.com")
    assert res["A"] == "1.2.3.4"
    assert res["NS"] == "1.2.3.4"
    assert res["MX"] == "1.2.3.4"

@patch("recontool.shutil.which")
@patch("recontool.socket.gethostbyname_ex")
def test_dns_enum_fallback(mock_gethostbyname, mock_which):
    # Case 2: dig is NOT available (socket fallback)
    mock_which.return_value = None
    mock_gethostbyname.return_value = ("example.com", [], ["9.9.9.9", "8.8.8.8"])

    res = dns_enum("example.com")
    assert "9.9.9.9" in res["A"]
    assert "8.8.8.8" in res["A"]
    assert "Skipped" in res["NS"]

@patch("recontool.requests.get")
def test_ip_geolocation(mock_get):
    # Success scenario
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"city": "New York", "country": "US"}
    mock_get.return_value = mock_response

    res = ip_geolocation("8.8.8.8")
    assert isinstance(res, dict)
    assert res["city"] == "New York"

    # HTTP Error scenario
    mock_response_err = MagicMock()
    mock_response_err.status_code = 404
    mock_get.return_value = mock_response_err
    res_err = ip_geolocation("8.8.8.8")
    assert "status 404" in res_err

@patch("recontool.socket.gethostbyaddr")
def test_reverse_dns_lookup(mock_gethostbyaddr):
    # Success
    mock_gethostbyaddr.return_value = ("dns.google", [], ["8.8.8.8"])
    res = reverse_dns_lookup("8.8.8.8")
    assert res == "dns.google"

    # Failure
    mock_gethostbyaddr.side_effect = socket.herror("host not found")
    res_err = reverse_dns_lookup("8.8.8.8")
    assert "Reverse DNS lookup failed" in res_err

@patch("recontool.requests.get")
def test_passive_subdomains(mock_get):
    # Success scenario
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {"name_value": "www.example.com"},
        {"name_value": "api.example.com\n*.example.com"},
        {"name_value": "test.notmatching.com"}
    ]
    mock_get.return_value = mock_response

    res = passive_subdomains("example.com")
    assert "www.example.com" in res
    assert "api.example.com" in res
    assert "test.notmatching.com" not in res
    assert "*.example.com" not in res  # Wilcard filtering

@patch("recontool.requests.get")
def test_analyze_security_headers(mock_get):
    mock_response = MagicMock()
    mock_response.url = "https://example.com"
    mock_response.headers = {
        "Strict-Transport-Security": "max-age=63072000",
        "X-Frame-Options": "DENY"
    }
    mock_get.return_value = mock_response

    res = analyze_security_headers("example.com")
    assert isinstance(res, dict)
    assert "Strict-Transport-Security" in res["present"]
    assert "Content-Security-Policy" in res["missing"]

def test_parse_ssl_cert():
    cert = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "DigiCert Inc"),),),
        "version": 3,
        "notBefore": "Jan  1 00:00:00 2023 GMT",
        "notAfter": "Dec 31 23:59:59 2023 GMT"
    }
    parsed = parse_ssl_cert(cert)
    assert "commonName=example.com" in parsed["subject"]
    assert "organizationName=DigiCert Inc" in parsed["issuer"]
    assert parsed["notBefore"] == "Jan  1 00:00:00 2023 GMT"

@patch("recontool.socket.socket")
def test_socket_port_scan(mock_socket):
    mock_sock_inst = MagicMock()
    # Connect success for port 80, connect failure for port 443
    mock_sock_inst.connect_ex.side_effect = lambda addr: 0 if addr[1] == 80 else 111
    mock_socket.return_value = mock_sock_inst

    res = socket_port_scan("example.com", ports=[80, 443])
    assert "Port 80: OPEN" in res
    assert "Port 443" not in res

@patch("recontool.shutil.which")
@patch("recontool.subprocess.check_output")
@patch("recontool.socket_port_scan")
def test_nmap_scan_routing(mock_socket_scan, mock_check_output, mock_which):
    # Case 1: nmap available
    mock_which.return_value = "/usr/bin/nmap"
    mock_check_output.return_value = b"Nmap report for example.com\n"

    res = nmap_scan("example.com")
    assert "Nmap report" in res

    # Case 2: nmap NOT available (routes to socket_port_scan)
    mock_which.return_value = None
    mock_socket_scan.return_value = "Socket scan results"

    res_fallback = nmap_scan("example.com")
    assert res_fallback == "Socket scan results"

def test_format_results_as_text():
    results = {
        "target_info": {"type": "Domain", "domain": "example.com"},
        "dns": {"A": "1.2.3.4"},
        "rdns": "example.com"
    }
    txt = format_results_as_text(results)
    assert "example.com" in txt
    assert "=== DNS Enumeration ===" in txt
    assert "=== Reverse DNS Lookup ===" in txt

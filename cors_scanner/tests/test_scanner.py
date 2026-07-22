import pytest
import requests_mock
from cors_scanner.scanner import CORSScanner

@pytest.fixture
def scanner():
    return CORSScanner(timeout=2)

def test_generate_payloads(scanner):
    payloads = scanner._generate_payloads("https://example.com/api")
    assert "https://evil.com" in payloads
    assert "null" in payloads
    assert "https://example.com.evil.com" in payloads
    assert "https://evilexample.com" in payloads

def test_scan_url_vulnerable_high(scanner):
    url = "https://example.com/api"
    with requests_mock.Mocker() as m:
        # Mock a vulnerable response where it reflects any origin and allows credentials
        # Provide a default mock for any request to this URL, but specific mock for our evil.com payload
        m.get(url, text="mock", headers={"Access-Control-Allow-Origin": "https://evil.com", "Access-Control-Allow-Credentials": "true"})

        findings = scanner.scan_url(url)

        # We expect at least one finding for https://evil.com
        evil_finding = next((f for f in findings if f["payload"] == "https://evil.com"), None)
        assert evil_finding is not None
        assert evil_finding["severity"] == "High"
        assert evil_finding["acao_header"] == "https://evil.com"
        assert evil_finding["acac_header"] == "true"

def test_scan_url_vulnerable_medium(scanner):
    url = "https://example.com/api"
    with requests_mock.Mocker() as m:
        # Mock a vulnerable response where it reflects any origin but NO credentials allowed
        m.get(url, text="mock", headers={"Access-Control-Allow-Origin": "null"})

        findings = scanner.scan_url(url)

        null_finding = next((f for f in findings if f["payload"] == "null"), None)
        assert null_finding is not None
        assert null_finding["severity"] == "Medium"
        assert null_finding["acao_header"] == "null"
        assert null_finding["acac_header"] == "false"

def test_scan_url_secure(scanner):
    url = "https://example.com/api"
    with requests_mock.Mocker() as m:
        # Mock a secure response (only allows specific origin, e.g., itself)
        m.get(url, headers={"Access-Control-Allow-Origin": "https://example.com"})

        findings = scanner.scan_url(url)

        # Scanner should not flag this because the reflected origin doesn't match the malicious payload
        assert len(findings) == 0

def test_scan_url_connection_error(scanner):
    url = "http://localhost:99999/api" # Invalid port/URL
    # Should handle connection errors gracefully and return empty list
    findings = scanner.scan_url(url)
    assert len(findings) == 0

import pytest
from app.core.security import is_ip_blocked, validate_url

def test_is_ip_blocked_loopback():
    assert is_ip_blocked("127.0.0.1") is True
    assert is_ip_blocked("127.1.2.3") is True

def test_is_ip_blocked_rfc1918():
    assert is_ip_blocked("10.0.0.1") is True
    assert is_ip_blocked("172.16.0.1") is True
    assert is_ip_blocked("192.168.1.1") is True

def test_is_ip_blocked_cloud_metadata():
    assert is_ip_blocked("169.254.169.254") is True

def test_is_ip_blocked_public():
    assert is_ip_blocked("8.8.8.8") is False
    assert is_ip_blocked("1.1.1.1") is False

def test_is_ip_blocked_invalid():
    assert is_ip_blocked("not.an.ip") is True
    assert is_ip_blocked("999.999.999.999") is True

def test_validate_url_invalid_scheme():
    is_safe, reason, ip = validate_url("ftp://example.com")
    assert is_safe is False
    assert "scheme" in reason.lower()

def test_validate_url_no_hostname():
    is_safe, reason, ip = validate_url("http://")
    assert is_safe is False
    assert "hostname" in reason.lower()

def test_validate_url_blocked_ip(monkeypatch):
    # Mock DNS resolution to return a local IP
    monkeypatch.setattr("app.core.security.resolve_hostname", lambda host: ["127.0.0.1"])

    is_safe, reason, ip = validate_url("http://example.com")
    assert is_safe is False
    assert "blocked IP" in reason

def test_validate_url_safe(monkeypatch):
    # Mock DNS resolution to return a public IP
    monkeypatch.setattr("app.core.security.resolve_hostname", lambda host: ["93.184.216.34"]) # example.com

    is_safe, reason, ip = validate_url("http://example.com")
    assert is_safe is True
    assert ip == "93.184.216.34"

def test_validate_url_dns_rebinding(monkeypatch):
    # Mock DNS resolution to return one safe and one blocked IP
    monkeypatch.setattr("app.core.security.resolve_hostname", lambda host: ["8.8.8.8", "169.254.169.254"])

    is_safe, reason, ip = validate_url("http://example.com")
    assert is_safe is False
    assert "blocked IP" in reason

def test_is_ip_blocked_ipv4_mapped():
    assert is_ip_blocked("::ffff:127.0.0.1") is True
    assert is_ip_blocked("::ffff:169.254.169.254") is True

def test_is_ip_blocked_ipv6_unspecified():
    assert is_ip_blocked("::") is True

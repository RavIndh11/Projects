import pytest
import os
import tempfile
import time
import base64
import json
import hmac
import hashlib
from jwt_inspector.core import (
    parse_jwt,
    analyze_token,
    brute_force_hmac_sha256,
    InvalidTokenError,
    base64url_decode
)

def create_mock_jwt(header, payload, secret=None):
    """Helper to create a JWT for testing."""
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode('utf-8')).decode('utf-8').rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8').rstrip('=')

    signing_input = f"{header_b64}.{payload_b64}"

    if secret:
        signature = hmac.new(
            secret.encode('utf-8'),
            signing_input.encode('utf-8'),
            hashlib.sha256
        ).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')
    else:
        signature_b64 = ""

    return f"{signing_input}.{signature_b64}"


def test_base64url_decode_valid():
    # 'test' -> 'dGVzdA==' -> 'dGVzdA'
    decoded = base64url_decode("dGVzdA")
    assert decoded == b"test"

def test_base64url_decode_invalid():
    with pytest.raises(InvalidTokenError):
        base64url_decode("a_@#$!!")

def test_parse_jwt_valid():
    token = create_mock_jwt({"alg": "HS256"}, {"user": "admin"}, secret="testsecret")
    parsed = parse_jwt(token)
    assert parsed["header"] == {"alg": "HS256"}
    assert parsed["payload"] == {"user": "admin"}
    assert "signature_raw" in parsed
    assert "signing_input" in parsed

def test_parse_jwt_invalid_format():
    with pytest.raises(InvalidTokenError):
        parse_jwt("header.payload") # Missing signature part

def test_analyze_token_none_alg():
    token = create_mock_jwt({"alg": "none"}, {"user": "admin"})
    parsed = parse_jwt(token)
    analysis = analyze_token(parsed)
    assert analysis["is_none_algorithm"] is True
    assert any("CRITICAL" in issue for issue in analysis["issues"])

def test_analyze_token_expired():
    expired_time = int(time.time()) - 3600 # 1 hour ago
    token = create_mock_jwt({"alg": "HS256"}, {"exp": expired_time})
    parsed = parse_jwt(token)
    analysis = analyze_token(parsed)
    assert analysis["is_expired"] is True
    assert any("WARNING: Token is expired" in issue for issue in analysis["issues"])

def test_analyze_token_not_expired():
    future_time = int(time.time()) + 3600 # 1 hour from now
    token = create_mock_jwt({"alg": "HS256"}, {"exp": future_time})
    parsed = parse_jwt(token)
    analysis = analyze_token(parsed)
    assert analysis["is_expired"] is False

def test_brute_force_success():
    secret = "secret123"
    token = create_mock_jwt({"alg": "HS256"}, {"user": "admin"}, secret=secret)
    parsed = parse_jwt(token)

    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("wrongpass\n")
        f.write("password\n")
        f.write(f"{secret}\n")
        f.write("admin123\n")
        wordlist_path = f.name

    try:
        found_secret = brute_force_hmac_sha256(parsed["signing_input"], parsed["signature_raw"], wordlist_path)
        assert found_secret == secret
    finally:
        os.unlink(wordlist_path)

def test_brute_force_failure():
    secret = "supersecret"
    token = create_mock_jwt({"alg": "HS256"}, {"user": "admin"}, secret=secret)
    parsed = parse_jwt(token)

    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("wrongpass\n")
        f.write("password\n")
        wordlist_path = f.name

    try:
        found_secret = brute_force_hmac_sha256(parsed["signing_input"], parsed["signature_raw"], wordlist_path)
        assert found_secret is None
    finally:
        os.unlink(wordlist_path)

import pytest
import jwt
from app.analyzer import JWTAnalyzer

@pytest.fixture
def analyzer():
    return JWTAnalyzer()

def test_valid_token_no_vulns(analyzer):
    # A properly configured token
    payload = {"sub": "123", "exp": 9999999999}
    secret = "this_is_a_very_strong_and_long_secret_key_12345!"
    token = jwt.encode(payload, secret, algorithm="HS256")

    result = analyzer.analyze(token)
    assert result.is_valid_format is True
    assert result.error is None
    # HS256 generates a 'Low' vulnerability for being symmetric, we should find exactly 1 vuln
    assert len(result.vulnerabilities) == 1
    assert result.vulnerabilities[0].id == "JWT-002"

def test_alg_none_vulnerability(analyzer):
    # Constructing an alg:none token manually since PyJWT protects against creating it easily
    # Header: {"alg": "none", "typ": "JWT"} -> eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
    # Payload: {"sub": "123", "exp": 9999999999} -> eyJzdWIiOiIxMjMiLCJleHAiOjk5OTk5OTk5OTl9
    # Signature: empty
    token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjMiLCJleHAiOjk5OTk5OTk5OTl9."

    result = analyzer.analyze(token)
    assert result.is_valid_format is True

    vuln_ids = [v.id for v in result.vulnerabilities]
    assert "JWT-001" in vuln_ids  # alg: none

def test_weak_secret_bruteforce(analyzer):
    payload = {"sub": "123", "exp": 9999999999}
    secret = "secret"  # One of the weak secrets in the list
    token = jwt.encode(payload, secret, algorithm="HS256")

    result = analyzer.analyze(token)
    assert result.is_valid_format is True

    vuln_ids = [v.id for v in result.vulnerabilities]
    assert "JWT-005" in vuln_ids  # Brute forced weak secret
    assert "JWT-002" in vuln_ids  # Symmetric alg

def test_missing_expiration(analyzer):
    payload = {"sub": "123"}
    secret = "super_strong_secret_key_wow_so_long!"
    token = jwt.encode(payload, secret, algorithm="HS256")

    result = analyzer.analyze(token)
    assert result.is_valid_format is True

    vuln_ids = [v.id for v in result.vulnerabilities]
    assert "JWT-003" in vuln_ids  # Missing exp

def test_sensitive_data_in_payload(analyzer):
    payload = {"sub": "123", "exp": 9999999999, "password": "my_super_secret_password"}
    secret = "super_strong_secret_key_wow_so_long!"
    token = jwt.encode(payload, secret, algorithm="HS256")

    result = analyzer.analyze(token)
    assert result.is_valid_format is True

    vuln_ids = [v.id for v in result.vulnerabilities]
    assert "JWT-004" in vuln_ids  # Sensitive data

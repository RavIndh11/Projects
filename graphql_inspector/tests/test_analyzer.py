import pytest
from app.analyzer import is_safe_url, parse_schema

def test_is_safe_url():
    # Valid public URLs
    assert is_safe_url("https://example.com/graphql") == True
    assert is_safe_url("http://google.com") == True

    # Invalid schemes
    assert is_safe_url("ftp://example.com") == False
    assert is_safe_url("file:///etc/passwd") == False

    # SSRF / Private IPs
    assert is_safe_url("http://127.0.0.1/graphql") == False
    assert is_safe_url("http://localhost:8080/graphql") == False
    assert is_safe_url("http://10.0.0.1") == False
    assert is_safe_url("http://192.168.1.5") == False
    assert is_safe_url("http://169.254.169.254/latest/meta-data") == False # AWS Metadata

def test_parse_schema_no_sensitive_fields():
    schema = {
        "types": [
            {
                "name": "User",
                "fields": [
                    {"name": "id"},
                    {"name": "username"}
                ]
            }
        ]
    }
    report = parse_schema("http://test.com", schema)
    assert report.total_types == 1
    assert len(report.sensitive_fields) == 0

def test_parse_schema_with_sensitive_fields():
    schema = {
        "types": [
            {
                "name": "User",
                "fields": [
                    {"name": "id"},
                    {"name": "passwordHash"},
                    {"name": "api_token_value"}
                ]
            },
            {
                "name": "__InternalState", # Should be skipped
                "fields": [
                    {"name": "secretKey"}
                ]
            }
        ]
    }
    report = parse_schema("http://test.com", schema)
    assert report.total_types == 2 # includes the internal one but we skip field checks
    assert len(report.sensitive_fields) == 2

    field_names = [f.field_name for f in report.sensitive_fields]
    assert "passwordHash" in field_names
    assert "api_token_value" in field_names

import pytest
from unittest.mock import patch, MagicMock
import os
import json
import sys

# Add parent directory to path so we can import scanner
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from scanner import resolve_cname, check_vulnerability, load_signatures

@pytest.fixture
def sample_signatures():
    return [
        {
            "provider": "GitHub Pages",
            "cname": ["github.io"],
            "fingerprint": "There isn't a GitHub Pages site here."
        }
    ]

@patch('dns.resolver.resolve')
def test_resolve_cname_success(mock_resolve):
    mock_answer = MagicMock()
    mock_answer.target = MagicMock()
    mock_answer.target.__str__.return_value = "target.github.io."
    mock_resolve.return_value = [mock_answer]

    result = resolve_cname("test.example.com")
    assert result == ["target.github.io"]

@patch('dns.resolver.resolve')
def test_resolve_cname_nxdomain(mock_resolve):
    import dns.resolver
    mock_resolve.side_effect = dns.resolver.NXDOMAIN

    result = resolve_cname("nonexistent.example.com")
    assert result == []

@patch('scanner.resolve_cname')
@patch('requests.get')
def test_check_vulnerability_vulnerable(mock_get, mock_resolve_cname, sample_signatures):
    mock_resolve_cname.return_value = ["test.github.io"]

    mock_response = MagicMock()
    mock_response.text = "Some HTML here... There isn't a GitHub Pages site here. ...and more HTML"
    mock_get.return_value = mock_response

    result = check_vulnerability("vulnerable.example.com", sample_signatures)

    assert result is not None
    assert result["domain"] == "vulnerable.example.com"
    assert result["cname"] == "test.github.io"
    assert result["provider"] == "GitHub Pages"
    assert result["vulnerable"] is True

@patch('scanner.resolve_cname')
@patch('requests.get')
def test_check_vulnerability_not_vulnerable(mock_get, mock_resolve_cname, sample_signatures):
    mock_resolve_cname.return_value = ["test.github.io"]

    mock_response = MagicMock()
    mock_response.text = "This is a valid GitHub Pages site, no takeover here."
    mock_get.return_value = mock_response

    result = check_vulnerability("secure.example.com", sample_signatures)

    assert result is None

@patch('scanner.resolve_cname')
def test_check_vulnerability_no_cname(mock_resolve_cname, sample_signatures):
    mock_resolve_cname.return_value = []

    result = check_vulnerability("nodns.example.com", sample_signatures)

    assert result is None

def test_load_signatures(tmp_path):
    sig_file = tmp_path / "test_sigs.json"
    test_data = [{"provider": "Test", "cname": ["test.com"], "fingerprint": "test error"}]
    sig_file.write_text(json.dumps(test_data))

    loaded = load_signatures(str(sig_file))
    assert loaded == test_data

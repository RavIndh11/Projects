import pytest
from unittest.mock import patch, MagicMock
from typosquat_hunter.scanner import Scanner

class MockAnswer:
    def __init__(self, data):
        self._data = data

    def __str__(self):
        return self._data

class MockMXAnswer:
    def __init__(self, data):
        self.exchange = data

@patch('dns.resolver.Resolver.resolve')
def test_check_domain_resolvable(mock_resolve):
    scanner = Scanner()

    def side_effect(domain, record_type):
        if record_type == 'A':
            return [MockAnswer('1.2.3.4')]
        elif record_type == 'MX':
            return [MockMXAnswer('mail.example.com')]

    mock_resolve.side_effect = side_effect

    result = scanner.check_domain('example.com')
    assert result['resolvable'] is True
    assert '1.2.3.4' in result['a_records']
    assert 'mail.example.com' in result['mx_records']

@patch('dns.resolver.Resolver.resolve')
def test_check_domain_not_resolvable(mock_resolve):
    scanner = Scanner()
    import dns.resolver

    mock_resolve.side_effect = dns.resolver.NXDOMAIN

    result = scanner.check_domain('example.com')
    assert result['resolvable'] is False
    assert not result['a_records']
    assert not result['mx_records']

@patch.object(Scanner, 'check_domain')
def test_scan_domains(mock_check_domain):
    scanner = Scanner()
    mock_check_domain.side_effect = [
        {"domain": "resolvable.com", "resolvable": True, "a_records": ["1.2.3.4"], "mx_records": []},
        {"domain": "unresolvable.com", "resolvable": False, "a_records": [], "mx_records": []}
    ]

    results = scanner.scan_domains(["resolvable.com", "unresolvable.com"])

    assert len(results) == 1
    assert results[0]["domain"] == "resolvable.com"

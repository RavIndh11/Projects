import os
import pytest
from log_analyzer.analyzer import LogAnalyzer

@pytest.fixture
def sample_log_path():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(current_dir, 'sample_access.log')

def test_parse_line_benign():
    analyzer = LogAnalyzer()
    line = '192.168.1.10 - - [12/Oct/2023:14:05:01 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
    is_malicious, attack_type, fields = analyzer.parse_line(line)

    assert is_malicious is False
    assert attack_type == ""
    assert fields['ip'] == '192.168.1.10'
    assert fields['path'] == '/index.html'

def test_parse_line_sqli():
    analyzer = LogAnalyzer()
    line = '10.0.0.5 - - [12/Oct/2023:14:06:12 +0000] "GET /login.php?user=admin\' OR \'1\'=\'1 HTTP/1.1" 200 450 "-" "Mozilla/5.0"'
    is_malicious, attack_type, fields = analyzer.parse_line(line)

    assert is_malicious is True
    assert attack_type == "SQL_INJECTION"
    assert fields['ip'] == '10.0.0.5'

def test_parse_line_xss():
    analyzer = LogAnalyzer()
    line = '172.16.0.2 - - [12/Oct/2023:14:08:45 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 403 230 "-" "curl/7.68.0"'
    is_malicious, attack_type, fields = analyzer.parse_line(line)

    assert is_malicious is True
    assert attack_type == "CROSS_SITE_SCRIPTING"
    assert fields['ip'] == '172.16.0.2'

def test_parse_line_lfi():
    analyzer = LogAnalyzer()
    line = '10.0.0.5 - - [12/Oct/2023:14:09:10 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 404 150 "-" "python-requests/2.25.1"'
    is_malicious, attack_type, fields = analyzer.parse_line(line)

    assert is_malicious is True
    assert attack_type == "PATH_TRAVERSAL"
    assert fields['ip'] == '10.0.0.5'

def test_analyze_file(sample_log_path):
    analyzer = LogAnalyzer()
    analyzer.analyze_file(sample_log_path)

    summary = analyzer.get_summary()

    assert summary['total_lines_parsed'] == 6
    assert summary['total_attacks_detected'] == 3
    assert summary['unique_malicious_ips_count'] == 2

    assert '10.0.0.5' in summary['malicious_activity_by_ip']
    assert len(summary['malicious_activity_by_ip']['10.0.0.5']) == 2

    assert '172.16.0.2' in summary['malicious_activity_by_ip']
    assert len(summary['malicious_activity_by_ip']['172.16.0.2']) == 1

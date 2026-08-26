import re
from typing import Dict, List, Tuple
from collections import defaultdict

from .patterns import ATTACK_PATTERNS

# Typical Common/Combined Log Format regex.
# Example: 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
# Optimized regex uses negated character classes to reduce backtracking
LOG_REGEX = re.compile(
    r'^(?P<ip>[^ ]+) [^ ]+ [^ ]+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>[^"]+?) (?P<protocol>HTTP/\S+)" (?P<status>\d{3}) (?P<size>[^ ]+)(?: "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)

ATTACK_PATTERNS_ITEMS = tuple(ATTACK_PATTERNS.items())

class LogAnalyzer:
    def __init__(self):
        # We will track malicious requests by IP Address
        self.malicious_ips = defaultdict(list)
        self.total_lines_parsed = 0
        self.total_attacks_detected = 0

    def parse_line(self, line: str) -> Tuple[bool, str, Dict[str, str]]:
        """
        Parses a single log line, checks for attack patterns.
        Returns a tuple (is_malicious, attack_type, parsed_fields)
        """
        match = LOG_REGEX.match(line)
        if not match:
            return False, "", {}

        fields = match.groupdict()
        self.total_lines_parsed += 1

        # Check path, referrer, and user-agent for malicious patterns
        # Standard web attacks commonly manifest here
        path = fields.get('path')
        referrer = fields.get('referrer')
        user_agent = fields.get('user_agent')

        # We process targets linearly for correctness against the previous ordering.
        if path:
            for attack_type, pattern in ATTACK_PATTERNS_ITEMS:
                if pattern.search(path):
                    self.total_attacks_detected += 1
                    return True, attack_type, fields

        if referrer:
            for attack_type, pattern in ATTACK_PATTERNS_ITEMS:
                if pattern.search(referrer):
                    self.total_attacks_detected += 1
                    return True, attack_type, fields

        if user_agent:
            for attack_type, pattern in ATTACK_PATTERNS_ITEMS:
                if pattern.search(user_agent):
                    self.total_attacks_detected += 1
                    return True, attack_type, fields

        return False, "", fields

    def analyze_file(self, file_path: str):
        """
        Reads a log file line by line and populates the internal state.
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    is_malicious, attack_type, fields = self.parse_line(line.strip())
                    if is_malicious and 'ip' in fields:
                        ip = fields['ip']
                        self.malicious_ips[ip].append({
                            'timestamp': fields.get('timestamp', ''),
                            'method': fields.get('method', ''),
                            'path': fields.get('path', ''),
                            'status': fields.get('status', ''),
                            'attack_type': attack_type
                        })
        except FileNotFoundError:
            raise FileNotFoundError(f"Log file not found: {file_path}")
        except Exception as e:
            raise Exception(f"Error processing file {file_path}: {str(e)}")

    def get_summary(self) -> Dict:
        """
        Returns a structured summary of the analysis.
        """
        summary = {
            "total_lines_parsed": self.total_lines_parsed,
            "total_attacks_detected": self.total_attacks_detected,
            "unique_malicious_ips_count": len(self.malicious_ips),
            "malicious_activity_by_ip": dict(self.malicious_ips)
        }
        return summary

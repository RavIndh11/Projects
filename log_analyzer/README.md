# ThreatLens

**ThreatLens** is a lightweight, Python-based Web Log Anomaly Detector.

## Overview
ThreatLens analyzes standard Nginx or Apache access logs to identify common web application attacks such as SQL Injection (SQLi), Cross-Site Scripting (XSS), and Path Traversal. It quickly parses logs, identifies offending IP addresses, and aggregates the malicious activity into a concise, actionable report.

## Problem Statement
System administrators, SOC analysts, and security engineers often need a quick, dependency-light way to parse web server access logs during incident response or routine checks. While full SIEM solutions (like Splunk or ELK) are powerful, they can be heavy and take time to query. ThreatLens provides an immediate, local, regex-based analysis tool that runs directly from the command line.

## Features
- **Fast Parsing**: Reads Common/Combined Log Formats efficiently.
- **Pattern Matching**: Detects SQLi, XSS, and Path Traversal via configurable regular expressions.
- **Contextual Awareness**: Checks the Request Path, Referrer, and User-Agent headers for malicious payloads.
- **Aggregation**: Groups detected attacks by the source IP address.
- **Flexible Output**: Supports both human-readable text reports and JSON output for pipeline integration.

## Architecture / Workflow
1. The user runs the `cli.py` script, pointing it to a target access log file.
2. The `LogAnalyzer` reads the file line by line.
3. Each line is matched against the `LOG_REGEX` to extract fields (IP, Path, Status, User-Agent, etc.).
4. The extracted fields are checked against compiled regular expressions in `patterns.py`.
5. If an attack signature matches, the event is recorded and attributed to the source IP.
6. A summary report is generated and printed to `stdout`.

## Installation

Ensure you have Python 3.7+ installed.

```bash
# Clone the repository
git clone <your-repo-url>
cd <repo-name>/log_analyzer

# (Optional) Set up a virtual environment and install test dependencies
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

Run the tool against a log file:

```bash
# Standard text output
python -m log_analyzer.cli /path/to/access.log

# JSON output
python -m log_analyzer.cli /path/to/access.log --format json
```

### Example

```bash
$ python -m log_analyzer.cli tests/sample_access.log
==================================================
 ThreatLens - Analysis Report
==================================================
Total Log Lines Parsed:     6
Total Attacks Detected:     3
Unique Malicious IPs:       2
==================================================

Malicious Activity Summary:

[-] IP Address: 10.0.0.5 (Events: 2)
    -> [12/Oct/2023:14:06:12 +0000] SQL_INJECTION - GET /login.php?user=admin' OR '1'='1 (Status: 200)
    -> [12/Oct/2023:14:09:10 +0000] PATH_TRAVERSAL - GET /download?file=../../../../etc/passwd (Status: 404)

[-] IP Address: 172.16.0.2 (Events: 1)
    -> [12/Oct/2023:14:08:45 +0000] CROSS_SITE_SCRIPTING - GET /search?q=<script>alert(1)</script> (Status: 403)
```

## Security Considerations
- **Log Forging**: Attackers can sometimes manipulate log entries (e.g., injecting newline characters in the User-Agent) to trick parsers. The regex used here assumes standard log structure but may not catch advanced evasion techniques.
- **False Positives/Negatives**: The regex patterns in `patterns.py` are simplified. They may flag benign activity that resembles attacks, or miss heavily obfuscated payloads.

## Limitations
- **Regex Dependency**: This tool relies solely on pattern matching, not behavioral analysis or machine learning.
- **Format Rigidity**: It expects standard Nginx/Apache Combined Log Formats. Custom log formats will fail to parse unless `LOG_REGEX` in `analyzer.py` is updated.

## Future Improvements
- **Custom Log Formats**: Allow users to pass a custom regex string via the CLI to parse non-standard logs.
- **Geolocate IPs**: Integrate with an offline GeoIP database (like MaxMind) to report the origin country of attacking IPs.
- **Machine Learning Integration**: Introduce an anomaly detection model to find novel payloads that bypass regex signatures.
- **Daemon Mode**: Allow the tool to tail a live log file (`tail -f`) and alert in real-time.

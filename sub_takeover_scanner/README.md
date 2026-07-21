# Subdomain Takeover Scanner

## Project Overview
This project is a lightweight, Python-based security tool designed to detect potential Subdomain Takeover vulnerabilities. It scans a list of given subdomains to identify if they point to third-party services that are no longer actively provisioned, which could allow an attacker to claim the subdomain.

## Problem Statement
When a subdomain has a DNS `CNAME` record pointing to a third-party service (like GitHub Pages, Heroku, AWS S3, etc.) but the service is deleted or unprovisioned by the owner, an attacker can register the same service and essentially take control of the original subdomain. This is known as a Subdomain Takeover. It poses significant risks, such as phishing, cookie stealing, or damaging brand reputation.

## Proposed Solution
This tool automates the process of checking for subdomain takeovers. It resolves the CNAME records for given subdomains, cross-references them with a known list of vulnerable third-party providers, and fetches the HTTP response to check for specific error "fingerprints" indicating the service is unclaimed.

## Features
- **CNAME Resolution**: Automatically resolves DNS CNAME chains.
- **Fingerprint Matching**: Uses a customizable JSON signature file to match CNAMEs and HTTP response fingerprints.
- **Multi-Target Scanning**: Supports scanning a single domain or bulk scanning via a text file.
- **JSON Output**: Ability to export vulnerable results to a JSON file for further analysis or integration.
- **Extensible**: Easy to add new providers to `signatures.json` without changing code.

## Architecture & Workflow
1. The user inputs a single domain (`-d`) or a list of domains (`-l`).
2. For each domain, the scanner queries the DNS records to resolve any `CNAME`s.
3. If a CNAME matches a known third-party provider in `signatures.json`, an HTTP GET request is made to the domain.
4. The HTTP response body is compared against the specific error fingerprint (e.g., "There isn't a GitHub Pages site here.").
5. If the fingerprint matches, the domain is flagged as vulnerable.

## Installation Instructions

1. Ensure you have Python 3 installed.
2. Clone this repository and navigate to the project directory:
   ```bash
   cd sub_takeover_scanner
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage Examples

**Scan a single domain:**
```bash
python scanner.py -d test.github.io
```

**Scan a list of subdomains from a file:**
```bash
python scanner.py -l subdomains.txt
```

**Export results to a JSON file:**
```bash
python scanner.py -l subdomains.txt -o results.json
```

## Security Considerations
- **Active Scanning:** This tool makes actual HTTP GET requests to the targets. Ensure you have authorization to scan the domains you are testing.
- **DNS Enumeration:** This tool does *not* brute-force subdomains. It only tests subdomains you provide. Use tools like `Amass` or `Sublist3r` first to generate a list.

## Limitations
- It only detects vulnerabilities for services defined in `signatures.json`. If a provider is not listed or the fingerprint changes, it may yield false negatives.
- Network timeouts, WAFs, or DNS blocking can interfere with the scan.

## Future Improvements
- Add concurrency/multithreading using `concurrent.futures` to drastically speed up scanning for large lists.
- Add support for checking `A` records (e.g., dangling Elastic IPs) in addition to `CNAME`s.
- Implement retries for transient network or DNS failures.

# CORS Scanner

## Project Overview
CORS Scanner is a lightweight, concurrent Python CLI tool designed to detect Cross-Origin Resource Sharing (CORS) misconfigurations. It tests target URLs by sending HTTP requests with crafted `Origin` headers (e.g., `https://evil.com`, `null`, prefix/suffix bypasses) and analyzes the server's responses to identify insecure `Access-Control-Allow-Origin` (ACAO) and `Access-Control-Allow-Credentials` (ACAC) configurations.

## Problem Statement
Many web applications mistakenly configure CORS to dynamically reflect any provided `Origin` header or use wildcard `*` with credentials enabled. This can lead to severe security vulnerabilities, allowing malicious websites to perform cross-origin actions on behalf of an authenticated user (e.g., stealing sensitive data via AJAX requests).

## Proposed Solution
This tool automates the process of identifying such misconfigurations. It programmatically generates common bypass payloads, sends the requests concurrently for speed, and flags vulnerable endpoints. It categorizes findings by severity:
*   **High:** Reflected origin matches the payload AND credentials are allowed (`ACAC: true`). This is highly exploitable.
*   **Medium:** Reflected origin matches the payload but credentials are not allowed. Still a misconfiguration, but exploitation potential depends on the specific context (e.g., accessing unauthenticated sensitive public data).
*   **Low:** Wildcard `*` used with `ACAC: true`. This is technically against the CORS specification and modern browsers block it, but it indicates a poor security configuration attempt by the developer.

## Features
*   **Targeted Payloads:** Tests `evil.com`, `null`, and domain prefix/suffix variations.
*   **Concurrency:** Utilizes threading for fast bulk scanning of multiple URLs.
*   **Clear Output:** Color-coded console output indicating severity.
*   **JSON Export:** Ability to save findings to a JSON file for integration into other pipelines.

## Installation

1.  Clone the repository and navigate to the directory:
    ```bash
    cd cors_scanner
    ```
2.  Install the dependencies (it is recommended to use a virtual environment):
    ```bash
    pip install -r requirements.txt
    ```
3.  Install the tool locally:
    ```bash
    pip install -e .
    ```

## Usage Examples

**Scan a single URL:**
```bash
cors-scanner -u https://example.com/api/v1/user
```

**Scan a list of URLs from a file with 20 threads and save to JSON:**
```bash
cors-scanner -l urls.txt -t 20 -o findings.json
```

**View Help:**
```bash
cors-scanner -h
```

## Security Considerations
*   **Active Scanning:** This tool sends actual HTTP requests to targets. Ensure you have explicit permission to scan the domains you are targeting.
*   **Insecure Requests Warning:** The tool intentionally suppresses `urllib3` insecure request warnings to allow scanning of targets with invalid or self-signed SSL/TLS certificates, which is common in internal or testing environments.

## Limitations
*   **GET Requests Only:** Currently, the scanner primarily relies on `GET` requests to check for reflected headers. Some endpoints might only exhibit CORS misconfigurations on `OPTIONS` (preflight) or other HTTP methods like `POST` or `PUT`.
*   **False Positives/Negatives:** The tool relies on standard HTTP header behavior. Specialized WAFs or load balancers might alter responses, potentially leading to false results. It does not perform actual exploitation to confirm vulnerability.

## Future Improvements
*   Add support for `OPTIONS` preflight request testing.
*   Allow custom headers (e.g., Authorization tokens) to test authenticated endpoints.
*   Integrate proxy support for routing traffic through tools like Burp Suite.
*   Expand the payload list to include more advanced bypass techniques (e.g., URL encoding tricks).

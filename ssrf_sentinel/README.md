# SSRF Sentinel

SSRF Sentinel is a defensive security tool designed to act as a Server-Side Request Forgery (SSRF) safe proxy. It safely fetches external URLs while blocking access to internal networks, cloud metadata services, and preventing DNS Rebinding attacks.

## Problem Statement

Many applications need to fetch content from user-provided URLs (e.g., webhooks, unfurling previews, integrations). Without proper validation, an attacker can supply URLs that point to internal infrastructure (like `http://localhost:8080`, `http://169.254.169.254/latest/meta-data/`), leading to SSRF. This tool provides a robust reference implementation for safely fetching URLs.

## Features & Capabilities

- **IP Allowlisting/Denylisting**: Blocks requests to loopback, private IP ranges (RFC 1918), and cloud metadata IPs.
- **DNS Rebinding Prevention**: Resolves the hostname to an IP address, validates the IP, and connects directly to the validated IP instead of the hostname, effectively mitigating DNS rebinding attacks.
- **Redirect Handling**: Drops requests that result in redirects to prevent attackers from bypassing initial checks via internal redirects.
- **Structured JSON Logging**: Suitable for log collectors (SIEM/Logstash).
- **Web UI**: A lightweight, Tailwind CSS-based interface for SOC analysts and developers to safely test payloads.

## Architecture

1. User submits a URL to the API or Web UI.
2. The `URLValidator` parses the URL and ensures it uses `http` or `https`.
3. The hostname is resolved to an IP address.
4. The IP address is checked against restricted ranges.
5. If safe, a direct connection is made to the IP address with the original `Host` header (preventing DNS Rebinding).
6. Result is returned or an error is logged and displayed.

## Installation & Setup

### Docker Execution (Recommended)

1. Build and run the container:
   ```bash
   docker compose up --build
   ```
2. Access the Web UI at `http://localhost:8000`.

### Native Execution

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Run the FastAPI server:
   ```bash
   uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```

## Usage Examples

**API Request:**
```bash
curl -X POST http://localhost:8000/api/fetch \
     -F "url=https://example.com"
```

## Security Considerations

- While SSRF Sentinel checks standard restricted ranges, custom internal network topologies may require adding additional IP ranges to the blocklist.
- It strictly drops redirects to prevent attackers from providing a safe external URL that redirects to an internal one.

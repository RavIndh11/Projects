# SSRF Sentinel

## Overview
SSRF Sentinel is a defensive security tool designed to act as a Server-Side Request Forgery (SSRF) safe proxy. It allows fetching URLs securely by implementing DNS Rebinding prevention. It resolves the hostname to an IP address, verifies that the IP is not an internal, loopback, or cloud metadata address, and then fetches the content using the resolved IP with the original Host header.

## Architecture
The application is built using **FastAPI** and uses **httpx** for making asynchronous HTTP requests. The UI is built with **Jinja2** templates and **Tailwind CSS**. It incorporates structured JSON logging suitable for SIEM integration.

## Features
- **DNS Resolution Pinning**: Resolves the hostname once and connects directly to the IP to prevent DNS rebinding attacks.
- **Strict IP Validation**: Blocks access to loopback (`127.0.0.1`), private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and AWS/GCP Metadata services (`169.254.169.254`).
- **Web UI**: A clean dashboard for SOC analysts to manually test and preview URL fetches safely.

## Setup & Execution

### Option 1: Native Python
1. Create a virtual environment and install dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
2. Run the application:
   ```bash
   uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```

### Option 2: Docker Compose
1. Build and start the container:
   ```bash
   docker-compose up --build
   ```
2. The application will be available at `http://localhost:8000`.

## Testing
Run the test suite using pytest:
```bash
PYTHONPATH=. pytest tests/
```

## Security Considerations
- The proxy strictly follows DNS pinning but is still subject to the routing capabilities of its host. Ensure it runs in an isolated network environment if possible.
- The `httpx` client enforces a short timeout and does not follow redirects automatically, ensuring redirection-based SSRF attempts fail.

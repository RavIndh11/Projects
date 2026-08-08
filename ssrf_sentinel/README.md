# SSRF Sentinel 🛡️

A defensive security tool designed to act as a **Server-Side Request Forgery (SSRF)** safe proxy.

SSRF Sentinel allows services to safely fetch remote URLs on behalf of users by implementing strict URL validation, DNS resolution checks, and IP pinning to prevent DNS Rebinding attacks.

## 🎯 Problem Statement
Many applications need to fetch data from URLs provided by users (e.g., fetching a profile picture, rendering webhooks, generating PDFs). If not secured, attackers can exploit this to access internal network services (like databases, Redis, or cloud metadata endpoints at `169.254.169.254`).

SSRF Sentinel solves this by acting as a hardened, centralized proxy that securely parses, resolves, and validates all outbound requests against blocked internal CIDR ranges (RFC 1918) before actually making the HTTP request.

## 🏗️ Architecture & Features

- **Strict IP Validation**: Blocks loopback (`127.0.0.1`), local networks (`10.0.0.0/8`, `192.168.0.0/16`), and Cloud Metadata IPs (`169.254.169.254`).
- **DNS Rebinding Consideration**: Performs upfront DNS resolution validation against blocked CIDRs. *Note on limitations:* To fully preserve HTTPS/SNI capabilities, the proxy forwards the original domain name to the HTTP client (rather than rewriting it to a raw IP address). While DNS caching mitigates some risk, a small Time-of-Check to Time-of-Use (TOCTOU) window exists if an attacker employs highly aggressive DNS rebinding techniques.
- **Structured JSON Logging**: Out-of-the-box support for SIEM/Logstash ingestion.
- **Redirects Disabled**: Prevents secondary SSRF attacks via 301/302 redirects.
- **Interactive UI Dashboard**: Built with FastAPI and Tailwind CSS for SOC analysts to review requests.

## 🚀 Installation & Setup

### Native Execution (Python 3.11+)

1. **Clone & Setup Environment**
   ```bash
   cd ssrf_sentinel
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Run the Application**
   ```bash
   uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```

### Docker Compose (Recommended)

1. **Setup Environment**
   ```bash
   cp .env.example .env
   ```

2. **Build and Run**
   ```bash
   docker-compose up --build -d
   ```

The application will be available at `http://localhost:8000`.

## 💻 Usage

### 1. Web Dashboard
Visit `http://localhost:8000/` to use the interactive proxy form and view real-time request logs.

### 2. API Endpoint
```bash
curl -X POST "http://localhost:8000/api/proxy" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://example.com", "method": "GET"}'
```

**Blocked Request Example (Cloud Metadata):**
```bash
curl -X POST "http://localhost:8000/api/proxy" \
     -H "Content-Type: application/json" \
     -d '{"url": "http://169.254.169.254/latest/meta-data/", "method": "GET"}'
```

Response:
```json
{
  "status": "blocked",
  "reason": "Hostname resolved to a blocked IP: 169.254.169.254",
  "status_code": 403,
  "content": null,
  "headers": {}
}
```

## 🔒 Security Considerations
- **Environment**: The Docker container runs as a non-root user (`appuser`) and employs read-only filesystems and `no-new-privileges` to prevent container escapes.
- **Dependencies**: Outbound requests are handled via `httpx` with `follow_redirects=False` to strictly limit the scope of the proxy request.
- **Future Improvements**: Support for allowing specific safe internal domains via an allowlist, or advanced protocol handling (e.g., blocking `file://`, `gopher://`, etc. which are implicitly blocked by requiring `http/https`).
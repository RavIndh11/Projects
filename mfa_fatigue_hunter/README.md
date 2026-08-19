# MFA Fatigue Hunter

**MFA Fatigue Hunter** is a lightweight, real-time Defensive Security and SOC Automation tool. It analyzes incoming Multi-Factor Authentication (MFA) logs to detect MFA Fatigue (or "MFA Spamming") attacks, where a threat actor repeatedly triggers MFA push notifications to overwhelm a user into accidentally approving a fraudulent login request.

## Problem Statement
Attackers with compromised credentials often bypass MFA by bombarding the victim with push notifications. If a user is annoyed or confused and clicks "Approve", the attacker gains access. Existing IAM logs often show these events, but correlating a high volume of "pending/denied" requests followed by an "approved" request in real-time requires specific detection logic. This tool provides exactly that.

## Architecture
1. **API Ingestion**: A FastAPI endpoint (`/api/v1/mfa_logs`) receives structured JSON logs.
2. **Analyzer Engine**: Maintains a sliding time window (e.g., 5 minutes) of MFA requests per user.
3. **Detection Rules**:
   - **Medium Alert**: If X number of pending/denied requests occur within the window, flag as "Active MFA Spamming".
   - **Critical Alert**: If the spam threshold is met AND is immediately followed by an "approved" request, flag as "Possible MFA Fatigue Success".
4. **Dashboard**: A Tailwind CSS-powered UI for SOC analysts to view alerts in real-time.

## Features
- **Strict Input Validation**: Utilizes Pydantic to ensure email formats, IPv4 addresses, and status strings are valid, mitigating injection risks.
- **Structured JSON Logging**: Outputs logs in JSON format for easy ingestion by SIEMs (Splunk, Elastic).
- **Secure Deployment**: Containerized with Docker, running as a non-root user (`appuser`, UID 10001) on a slim Python base image.

## Installation & Setup

### Native Execution (Local)
1. Navigate to the directory:
   ```bash
   cd mfa_fatigue_hunter
   ```
2. Set up the virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
3. Set environment variables:
   ```bash
   cp .env.example .env
   ```
4. Run the server:
   ```bash
   uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```

### Docker (Production Ready)
1. Build and run using Docker Compose:
   ```bash
   docker compose up --build -d
   ```
2. The service is available at `http://localhost:8000`.

## Usage Examples

### Simulating an Attack (Testing via cURL)

**1. Send 5 spam requests (triggers Medium alert):**
```bash
for i in {1..5}; do
  curl -X POST "http://localhost:8000/api/v1/mfa_logs" \
       -H "Content-Type: application/json" \
       -d "{
             \"user_email\": \"victim@example.com\",
             \"ip_address\": \"192.168.1.100\",
             \"timestamp\": \"$(date -u +'%Y-%m-%dT%H:%M:%SZ')\",
             \"status\": \"pending\"
           }"
  sleep 1
done
```

**2. Send a final approval request (triggers Critical alert):**
```bash
curl -X POST "http://localhost:8000/api/v1/mfa_logs" \
     -H "Content-Type: application/json" \
     -d "{
           \"user_email\": \"victim@example.com\",
           \"ip_address\": \"10.0.0.50\",
           \"timestamp\": \"$(date -u +'%Y-%m-%dT%H:%M:%SZ')\",
           \"status\": \"approved\"
         }"
```

### Viewing the Dashboard
Navigate to `http://localhost:8000/` in your browser. The dashboard automatically refreshes every 5 seconds.

## Security Considerations & Limitations
- **In-Memory State**: Currently, the time window logic relies on in-memory storage (Python dictionaries with threading locks). For a highly-available, multi-node production deployment, this should be backed by a distributed cache like Redis.
- **Rate Limiting**: The `/api/v1/mfa_logs` endpoint should be protected by an API Gateway or WAF to prevent denial-of-service (DoS) via log flooding.
- **Log Forgery**: Ensure that only trusted IAM providers (e.g., Okta, Entra ID) or internal SIEM forwarders can route traffic to this API.

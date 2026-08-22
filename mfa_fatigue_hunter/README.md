# MFA Fatigue Hunter

**MFA Fatigue Hunter** is a defensive cybersecurity tool designed to detect Multi-Factor Authentication (MFA) Spam (or MFA Fatigue) attacks in real-time. It acts as a webhook receiver for identity providers (e.g., Okta, Duo) and alerts SOC analysts when an attacker attempts to overwhelm a user with push notifications.

## Overview & Problem Statement
MFA Fatigue is an attack vector where a threat actor, having compromised valid credentials, repeatedly sends MFA push notifications to the victim's device in hopes that the user will eventually approve the request out of frustration or confusion. This tool solves the detection gap by monitoring event frequencies and automatically classifying threats based on customizable thresholds.

## Architecture
1. **Event Source:** Identity Provider (IdP) sends webhook events (e.g., `push_sent`) to the API.
2. **API Layer (FastAPI):** Validates incoming JSON payloads using strict Pydantic schemas.
3. **Detection Engine:** Aggregates events per user over a sliding time window (default 300s).
4. **Alerting & UI:** If thresholds are breached, generates `ThreatAlert` objects and displays them on the built-in HTML/Tailwind SOC Dashboard.

## Features
- Real-time event aggregation and fatigue detection.
- Tiered severity levels (Medium, High, Critical) based on push counts.
- Strict input validation to prevent injection attacks.
- Lightweight web dashboard for SOC analysts.
- Fully containerized with a hardened Docker configuration (non-root user).

## Setup & Installation

### Using Docker Compose (Recommended)
1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
2. Build and run the container:
   ```bash
   docker-compose up --build -d
   ```
3. Access the SOC Dashboard at `http://localhost:8000/`.

### Native Python Execution
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Run the server:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

## Usage Example
Simulate an identity provider sending events via webhook:
```bash
curl -X 'POST' \
  'http://localhost:8000/api/v1/events' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "user_email": "target@company.com",
  "event_type": "push_sent",
  "ip_address": "203.0.113.50",
  "user_agent": "IdP-Webhook-Agent"
}'
```

## Security Considerations
- **Authentication:** In a production deployment, the `/api/v1/events` endpoint MUST be protected using an API key, Mutual TLS (mTLS), or webhook signature validation to ensure only authorized IdPs can submit events.
- **Data Persistence:** Currently, state is maintained in-memory. For high-availability, this should be backed by a datastore like Redis.
- **Container Hardening:** The Docker container runs as a non-root user (`appuser`, UID 10001) to minimize privilege escalation risks.

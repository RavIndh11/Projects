# MFA Fatigue Hunter

**MFA Fatigue Hunter** is a defensive security tool designed for real-time detection of Multi-Factor Authentication (MFA) push spam (fatigue) attacks and potential account compromises. It ingests authentication event logs, analyzes them across a sliding time window, and generates alerts when malicious patterns are detected.

## Problem Statement

Attackers frequently use "MFA Fatigue" or "MFA Spamming" to bypass two-factor authentication. By repeatedly sending push notifications to a user's device, they hope the victim will eventually approve the request out of annoyance, confusion, or habit. This tool acts as an automated SOC analyst, detecting:
1. **MFA Fatigue Attacks**: Rapid succession of denied or pending MFA requests.
2. **Account Compromise**: An MFA approval immediately following a fatigue attack.

## Architecture

- **FastAPI**: Provides a high-performance REST API for event ingestion and a lightweight Web UI dashboard.
- **Pydantic**: Enforces strict input validation to prevent injection attacks and ensure data integrity.
- **In-Memory Store**: Uses a sliding time window algorithm to analyze events rapidly without external dependencies.
- **Structured Logging**: Outputs alerts in JSON format, making it trivial to ingest into SIEMs (e.g., Splunk, ELK).

## Features & Capabilities

- **Real-Time Analysis**: Detects attacks within seconds of log ingestion.
- **Threat Severities**: Automatically categorizes threats (e.g., `HIGH` for fatigue, `CRITICAL` for compromise).
- **SOC Dashboard**: A lightweight, auto-refreshing Web UI built with Tailwind CSS for monitoring active threats.
- **Secure Deployment**: Containerized with Docker, running as a non-root user with enforced security options.

## Installation & Setup

### Docker (Recommended)

1. Clone the repository and navigate to the project directory:
   ```bash
   git clone <repo-url>
   cd mfa_fatigue_hunter
   ```
2. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
3. Build and run the container:
   ```bash
   docker compose up --build -d
   ```
4. Access the SOC Dashboard at `http://localhost:8000`.

### Native Setup

1. Create a virtual environment and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
2. Run the application:
   ```bash
   uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```

## Usage Examples

### 1. Ingesting an Event

Send an HTTP POST request to the ingestion API:

```bash
curl -X POST "http://localhost:8000/api/v1/events" \
     -H "Content-Type: application/json" \
     -d '{
           "user_email": "victim@example.com",
           "ip_address": "192.168.1.1",
           "status": "DENIED"
         }'
```

### 2. Simulating a Fatigue Attack

Run the above curl command 3 times in rapid succession. The response will indicate an alert generation:

```json
{
  "status": "event_processed",
  "alert_generated": true,
  "alert_severity": "HIGH"
}
```

### 3. Fetching Alerts

```bash
curl -X GET "http://localhost:8000/api/v1/alerts"
```

## Security Considerations & Limitations

- **Statelessness vs. Scalability**: Currently, the event store is in-memory for speed and simplicity. In a highly distributed environment with multiple container replicas, a centralized store (like Redis) would be necessary for accurate cross-node correlation.
- **Input Sanitization**: Pydantic strictly validates all incoming JSON fields, mitigating standard web vulnerabilities.
- **Container Hardening**: The Docker image drops privileges and runs as a non-root user (`appuser`).

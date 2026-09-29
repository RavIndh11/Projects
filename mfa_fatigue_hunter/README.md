# MFA Fatigue Hunter

**MFA Fatigue Hunter** is a lightweight, real-time detection engine designed for Security Operations Centers (SOC). It ingests Multi-Factor Authentication (MFA) logs and analyzes them for "MFA Fatigue" (or MFA Bombing) attacks—identifying when a threat actor repeatedly spams a user with push notifications in an attempt to annoy or trick them into approving the request.

## Problem Statement

When an attacker compromises a user's primary credentials (username and password) but is blocked by MFA, they may employ an MFA fatigue attack. By sending dozens of push notifications in rapid succession, they hope the user will accidentally press "Approve" or accept it just to stop the continuous notifications. Detecting this behavior quickly is critical for identifying compromised primary credentials and preventing full account takeover (ATO).

## Architecture

1. **Log Ingestion (API)**: FastAPI endpoint `/api/v1/logs` receives JSON logs of MFA events.
2. **Analyzer**: An in-memory engine tracks recent `push_notification` events per user. It checks if the number of pending or denied requests exceeds a configured threshold within a specific time window.
3. **Structured Logging**: Outputs JSON formatted alerts for seamless integration with SIEMs (Splunk, ELK).
4. **Dashboard**: A TailwindCSS-styled HTML dashboard displays real-time critical alerts for SOC analysts.

## Features

- **Real-Time Analysis**: Processes and correlates logs instantly upon ingestion.
- **Strict Validation**: Uses Pydantic to ensure all incoming data (IPs, timestamps, event types) is strictly validated, preventing injection attacks.
- **Configurable Thresholds**: Easily adjust the fatigue threshold and time window via environment variables.
- **SOC Dashboard**: A clean, single-page view of recent high-severity MFA fatigue alerts.
- **Hardened Deployment**: Dockerized to run as a non-root user (`appuser`) on a slim base image.

## Installation & Setup

### Native (Local Development)

1. Navigate to the project directory:
   ```bash
   cd mfa_fatigue_hunter
   ```
2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
3. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
4. Run the server:
   ```bash
   uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
   ```

### Docker (Production Ready)

1. Build and start the container using Docker Compose:
   ```bash
   docker compose up --build -d
   ```
2. The service will be available at `http://localhost:8000`.

## Usage Examples

### Ingesting a Log

```bash
curl -X POST "http://localhost:8000/api/v1/logs" \
     -H "Content-Type: application/json" \
     -d '{
           "user_id": "alice123",
           "event_type": "push_notification",
           "ip_address": "203.0.113.5",
           "timestamp": "2023-10-27T10:00:00Z",
           "status": "pending"
         }'
```

To trigger an alert, send this request multiple times (e.g., 5 times within 60 seconds, based on the default configuration).

### Viewing the Dashboard
Navigate your browser to `http://localhost:8000/` to view the SOC dashboard and monitor recent alerts.

## Security Considerations & Limitations

- **State Persistence**: Currently, event state is held in-memory. For a multi-node, high-availability production deployment, the in-memory store should be replaced with a distributed cache like Redis.
- **Input Sanitization**: Pydantic strictly validates schemas. However, rate-limiting should be applied at the API Gateway level to prevent denial-of-service (DoS) attacks via log flooding.
- **Legitimate Fatigue**: Users occasionally trigger multiple requests legitimately if they have connection issues. Thresholds must be tuned to the specific environment to balance false positives with detection speed.

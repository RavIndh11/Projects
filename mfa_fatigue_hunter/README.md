# MFA Fatigue Hunter

A lightweight, real-time defensive security microservice and SOC dashboard designed to detect **MFA Fatigue (Prompt Bombing)** attacks.

## Overview & Problem Statement
Adversaries frequently use stolen credentials in combination with "MFA Fatigue" attacks—spamming a user with MFA push notifications until the victim inadvertently or intentionally approves the request just to make the notifications stop.

**MFA Fatigue Hunter** acts as a detection engine, analyzing authentication logs in real-time. It applies a sliding window algorithm to identify high volumes of MFA pushes, assigning severities and instantly providing SOC analysts with a clear view of potential compromise. If a high volume of pushes is followed by an `mfa_push_accepted` event, a **Critical** alert is generated indicating a likely successful breach.

## Features & Capabilities
- **Real-time API Ingestion**: Receives authentication events from IAM/SSO providers (Okta, Entra ID, Auth0).
- **Sliding Window Detection Engine**: Automatically groups events by user over customizable timeframes.
- **Severity Contextualization**: Distinguishes between failed fatigue attempts (High) and successful bypasses (Critical).
- **Live SOC Dashboard**: A TailwindCSS-based UI that auto-updates every 30 seconds to show recent alerts.
- **SIEM-Ready Logging**: Outputs JSON structured logs using `python-json-logger` for easy ingestion into Logstash/Splunk/Datadog.

## Architecture

```text
[IAM / SSO Provider]
        |
        | (JSON Webhook: mfa_push_sent, mfa_push_rejected, mfa_push_accepted)
        v
+------------------------+
|   MFA Fatigue Hunter   |
|   - FastAPI Server     | <---> [ SOC Analyst Browser ]
|   - Detection Engine   |         (Live Dashboard)
|   - JSON Logger        |
+------------------------+
        |
        v
[ SIEM / Log Collector ]
```

## Installation & Setup

### Option 1: Native Execution
Requirements: Python 3.11+
```bash
# Clone and navigate
cd mfa_fatigue_hunter

# Create environment and install deps
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure env
cp .env.example .env

# Run server
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Option 2: Docker Compose (Production Ready)
```bash
cd mfa_fatigue_hunter
cp .env.example .env
docker compose up --build -d
```

Access the dashboard at `http://localhost:8000`.

## Usage Examples

### 1. Simulating an Attack (Ingesting Logs)
You can send webhook events to the API to simulate log ingestion from your SSO provider.

```bash
# Send an MFA Push event
curl -X POST "http://localhost:8000/api/v1/ingest" \
     -H "Content-Type: application/json" \
     -H "X-API-Key: your_secure_api_key_here" \
     -d '{
           "user_id": "jdoe@example.com",
           "event_type": "mfa_push_sent",
           "ip_address": "198.51.100.22"
         }'
```

Spamming the endpoint 5+ times within the sliding window will trigger an alert. If you follow up with an `mfa_push_accepted` event, the alert escalates to Critical.

### 2. View Alerts via API
```bash
curl -s http://localhost:8000/api/v1/alerts | jq
```

## Security Considerations & Limitations
- **Statefulness**: Currently, the engine stores state in memory. In a multi-instance production deployment (e.g., Kubernetes with multiple replicas), a distributed cache like Redis should be implemented to track the sliding windows globally.
- **Authentication**: Ensure the `API_KEY` is securely injected via a secrets manager. Do not expose the ingest endpoint to the public internet without proper mutual TLS or API Gateway protection.
- **Data Retention**: The in-memory state automatically drops events older than the sliding window, keeping memory footprint low. Alerts are kept up to a limit for the dashboard, but permanent retention should rely on the JSON logs shipped to a SIEM.

# MFA Fatigue Hunter

A defensive security tool designed for real-time detection of MFA push spam and fatigue attacks (MFA Bombing).

## Overview & Problem Statement
MFA Fatigue attacks exploit human exhaustion by bombarding a user with push notifications until they approve the request either accidentally or simply to stop the annoyance. This tool acts as an active log analysis engine, ingesting authentication events and evaluating them against specific behavioral thresholds to identify and alert on potential MFA Bombing campaigns before or as they succeed.

## Architecture
```
[ IdP Logs / Auth Webhooks ] --> (POST /api/v1/events/ingest)
                                        |
                                        v
                               [ MFAFatigueDetector ]
                               - Tracks events per user in time windows
                               - Evaluates push thresholds
                                        |
                                        v
                               [ JSON Log Output (SIEM Ready) ]
                               [ Lightweight SOC Dashboard UI ]
```

## Features & Capabilities
*   **Real-time Analysis:** Processes events on ingestion.
*   **Threshold-based Detection:** Detects high volumes of pushes (e.g., >10 pushes) and successful fatigue (e.g., >5 pushes followed by an approval).
*   **SIEM Ready:** Outputs structured JSON logs for easy integration with log collectors.
*   **SOC Dashboard:** A lightweight Tailwind CSS + Jinja2 dashboard for quick visibility into active alerts.

## Installation & Setup

### Native Execution
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Run the application:
   ```bash
   uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```

### Docker Deployment
1. Ensure `.env` is present (copy from `.env.example`).
2. Build and start the container:
   ```bash
   docker compose up --build
   ```

## Usage Examples

Send a simulated event:
```bash
curl -X POST http://localhost:8000/api/v1/events/ingest \
  -H "Content-Type: application/json" \
  -d '{"user_email": "target@example.com", "event_type": "mfa_push_sent", "ip_address": "1.2.3.4"}'
```

View the dashboard by visiting `http://localhost:8000` in your browser.

## Security Considerations & Limitations
*   **In-Memory Storage:** The current implementation uses in-memory storage for events and alerts. In a high-volume production environment, this should be backed by a highly available data store like Redis.
*   **Rate Limiting:** The ingestion API should be protected by authentication and rate limiting to prevent denial-of-service attacks.

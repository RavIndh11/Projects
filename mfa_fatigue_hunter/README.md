# MFA Fatigue Hunter

A real-time detection engine designed to identify **MFA Fatigue** (also known as MFA Bombing or MFA Spamming) attacks from authentication logs.

## Overview & Problem Statement

Threat actors frequently bypass Multi-Factor Authentication (MFA) by flooding a user's device with push notifications in hopes that the user, experiencing "MFA fatigue," will accidentally or intentionally accept one of the prompts to make the notifications stop. This tool ingests authentication events and evaluates them in real-time, detecting anomalies where multiple rejected or pending MFA requests occur in a short time frame, especially when followed by a successful authentication event.

## Architecture

1.  **FastAPI Application**: Provides a REST API (`/api/events`) to ingest authentication logs (e.g., from an Identity Provider like Okta, Azure AD, or Duo).
2.  **Detection Engine (`MFAFatigueAnalyzer`)**: Evaluates incoming events in real-time, grouping them by user and analyzing temporal patterns against defined thresholds (e.g., 3 rejections within 5 minutes).
3.  **Web Dashboard**: A lightweight, Tailwind CSS-powered dashboard to visualize recent detections, severities, and affected users.
4.  **Logging**: Outputs structured JSON logs suitable for SIEM platforms (e.g., Splunk, ELK).

## Features & Capabilities

-   **Real-time Detection**: Evaluates events as they arrive.
-   **Severity Scoring**:
    -   `HIGH`: Multiple rejected/pending MFA pushes detected within the time window.
    -   `CRITICAL`: Multiple rejected/pending pushes followed by a successful login (highly indicative of a compromised account).
-   **Structured JSON Logging**: Easy integration with enterprise log collectors.
-   **Interactive Dashboard**: View alerts and anomalies quickly.
-   **Containerized**: Ready for production deployment using Docker.

## Installation & Setup

### Native Execution

1.  Create and activate a virtual environment (optional but recommended):
    ```bash
    python -m venv venv
    source venv/bin/activate
    ```
2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3.  Copy the example environment file:
    ```bash
    cp .env.example .env
    ```
4.  Run the application:
    ```bash
    uvicorn app.main:app --host 127.0.0.1 --port 8000
    ```

### Docker Deployment

1.  Build and run using Docker Compose:
    ```bash
    docker-compose up --build
    ```
2.  The application will be available at `http://localhost:8000`.

## Usage Examples

Send an authentication event to the API:

```bash
curl -X POST "http://localhost:8000/api/events" \
     -H "Content-Type: application/json" \
     -d '{
           "user_id": "alice@example.com",
           "status": "REJECTED",
           "source_ip": "192.168.1.100",
           "device_info": "iOS 16.5"
         }'
```

After sending multiple `REJECTED` events (e.g., 3 within 5 minutes) followed by a `SUCCESS` event, the API will return a `CRITICAL` detection result and log the anomaly.

## Security Considerations & Limitations

-   **Authentication**: The `/api/events` endpoint is currently unauthenticated in this base implementation. In a production environment, it should be secured using API keys or mutual TLS to prevent unauthorized log injection.
-   **Data Persistence**: Currently, events are held in memory. For a highly available production deployment, this should be backed by a persistent data store like Redis.
-   **Time Synchronization**: The system relies on accurate timestamps from incoming events. Ensure the systems generating the logs are NTP synchronized.

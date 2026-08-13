# Auth Anomaly Hunter

Auth Anomaly Hunter is a real-time authentication anomaly detection engine designed for Security Operations Centers (SOC). It ingests streaming authentication events and identifies high-risk activities such as "Impossible Travel" and "Brute Force" attempts.

## Problem Statement
Authentication logs are often noisy and voluminous. SOC analysts struggle to manually correlate events across disparate geographic locations or identify rapid, distributed brute-force attacks against specific accounts.

Auth Anomaly Hunter solves this by maintaining stateful tracking of user authentication events, automatically calculating Haversine distances to flag impossible travel speeds, and maintaining rolling time-windows to detect localized brute force attempts.

## Architecture

```text
[ Identity Provider / Web App ]
         |
    (POST /api/v1/events)
         |
         v
[ FastAPI Ingestion Endpoint ]
         |
         v
[ Anomaly Detection Engine ]
   -> Haversine Distance Calculator (Impossible Travel)
   -> Rolling Time Window (Brute Force)
         |
         +--> [ JSON Logs (SIEM/Logstash) ]
         |
         v
[ Lightweight SOC Dashboard (HTML/Tailwind) ]
```

## Features
- **Impossible Travel Detection**: Calculates distance and speed between successive logins. If the speed exceeds the configured threshold (e.g., 900 km/h), it triggers a High severity alert.
- **Brute Force Detection**: Tracks failed logins over a rolling time window. If failures exceed a threshold within the window, a Medium severity alert is generated.
- **SOC Dashboard**: A lightweight, Tailwind CSS powered dashboard to quickly view recent anomalies.
- **SIEM Ready**: Emits structural JSON logs for easy ingestion by Splunk, ELK, or Datadog.

## Installation & Setup

### Using Docker (Recommended)
1. Clone the repository.
2. Build and start the container:
   ```bash
   docker compose up --build -d
   ```
3. Access the dashboard at `http://localhost:8000`.

### Native Setup
1. Create a virtual environment and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
2. Run the application:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

## Usage Examples

### Ingesting a Normal Event
```bash
curl -X POST http://localhost:8000/api/v1/events \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "jdoe",
    "timestamp": "2023-10-27T10:00:00Z",
    "ip_address": "192.168.1.100",
    "status": "success",
    "location": {"lat": 40.7128, "lon": -74.0060}
  }'
```

### Triggering Impossible Travel
Send another event for `jdoe` 10 minutes later from London:
```bash
curl -X POST http://localhost:8000/api/v1/events \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "jdoe",
    "timestamp": "2023-10-27T10:10:00Z",
    "ip_address": "8.8.8.8",
    "status": "success",
    "location": {"lat": 51.5074, "lon": -0.1278}
  }'
```

## Security Considerations
- **Input Validation**: Strict Pydantic models prevent injection attacks (Path Traversal, XSS, etc.).
- **Container Hardening**: The Dockerfile runs the application as a non-root user (`appuser`).
- **Production State Management**: The current engine stores state in memory. For a multi-node production deployment, the state dictionary should be replaced with a distributed store like Redis.

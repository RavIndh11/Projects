# Auth Anomaly Hunter

**Auth Anomaly Hunter** is a lightweight, real-time detection engine designed for Security Operations Centers (SOC). It ingests authentication logs and analyzes them for "Impossible Travel" anomalies—identifying when a user logs in from two geographically distant locations in an impossibly short timeframe.

## Problem Statement

Compromised credentials often lead to logins from threat actors located in different countries or regions than the legitimate user. By calculating the physical distance between two consecutive IP addresses and the time elapsed between logins, this tool can detect superhuman travel speeds, alerting analysts to potential account takeover (ATO) events.

## Architecture

1. **Log Ingestion (API)**: FastAPI endpoint `/api/v1/logs` receives JSON logs.
2. **Geo-Location**: Maps IPs to latitude/longitude (using a free API with aggressive in-memory caching).
3. **Analyzer**: Calculates distance using the Haversine formula and determines if travel speed exceeds plausible limits (e.g., > 1000 km/h).
4. **State Management**: Thread-safe in-memory store tracks the last known login state per user.
5. **Dashboard**: A TailwindCSS-styled HTML dashboard displays real-time critical alerts.

## Features

- **Real-Time Analysis**: Analyzes logs upon ingestion.
- **Strict Validation**: Uses Pydantic to ensure IP addresses and timestamps are valid, preventing injection attacks.
- **Structured Logging**: Outputs JSON formatted logs for easy integration with SIEMs (Splunk, ELK).
- **SOC Dashboard**: A clean, single-page view of recent high-severity alerts.
- **Hardened Deployment**: Dockerized to run as a non-root user (`appuser`) on a slim base image.

## Installation & Setup

### Native (Local Development)

1. Navigate to the project directory:
   ```bash
   cd auth_anomaly_hunter
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
           "ip_address": "8.8.8.8",
           "timestamp": "2023-10-27T10:00:00Z",
           "status": "success"
         }'
```

To trigger an alert, send a second request shortly after with a geographically distant IP (e.g., `1.1.1.1`).

### Viewing the Dashboard
Navigate your browser to `http://localhost:8000/` to view the SOC dashboard.

## Security Considerations & Limitations

- **State Persistence**: Currently, state is held in-memory. For a multi-node production deployment, this should be replaced with Redis.
- **Geo-IP Accuracy**: The accuracy depends on the underlying GeoIP service. Threat actors using VPNs terminating near the victim might bypass this specific check.
- **Input Sanitization**: Pydantic strictly validates schemas. However, rate-limiting should be applied at the API Gateway level to prevent denial-of-service (DoS) via log flooding.

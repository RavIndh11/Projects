# Kube Audit Sentinel

## Overview & Problem Statement
Kubernetes Audit Logs provide a comprehensive record of all interactions with the cluster API. However, interpreting these logs in real-time to detect malicious activity or misconfigurations is challenging due to high log volume and complex JSON structures.

**Kube Audit Sentinel** is a lightweight, high-performance security analysis tool designed to ingest Kubernetes Audit Logs, detect anomalous and highly privileged actions, and provide a clear real-time SOC dashboard for security analysts. It acts as a guardrail and detection engine for Kubernetes API security.

## Architecture
```text
[ K8s API Server ] --(Audit Logs)--> [ Kube Audit Sentinel (FastAPI) ]
                                            |
                                            |--> 1. Data Validation (Pydantic)
                                            |--> 2. Detection Engine (Analyzer)
                                            |       - Pod Exec Detection
                                            |       - Anonymous Access Detection
                                            |       - Privileged RoleBinding Detection
                                            |       - Secrets Access Monitoring
                                            |--> 3. Alert Generation (JSON logs)
                                            |
                                   [ Web Dashboard (Tailwind + JS) ]
```

## Features & Capabilities
- **Real-time API Ingestion**: Accepts standard `audit.k8s.io/v1` Audit Event payloads via a REST API.
- **Robust Detection Engine**: Pre-configured rules for critical K8s security events.
- **SOC Web Dashboard**: A lightweight, auto-refreshing dashboard built with Tailwind CSS to visualize alerts and severity.
- **Structured JSON Logging**: All alerts are logged in JSON format, making it trivial to forward to a SIEM (Elasticsearch, Splunk, Datadog).
- **Container Hardened**: Production-ready Dockerfile running as a non-root user.

## Installation & Setup

### Prerequisites
- Python 3.11+
- Docker and Docker Compose (optional, for containerized deployment)

### Native Execution
1. Clone the repository and navigate to the directory:
   ```bash
   cd kube_audit_sentinel
   ```
2. Set up a virtual environment and install dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
3. Copy the environment variables:
   ```bash
   cp .env.example .env
   ```
4. Run the FastAPI server:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```
5. Access the dashboard at `http://localhost:8000/`.

### Docker Execution
1. Navigate to the directory:
   ```bash
   cd kube_audit_sentinel
   ```
2. Build and start the container:
   ```bash
   docker compose up --build -d
   ```
3. Access the dashboard at `http://localhost:8000/`.

## Usage Examples

You can test the detection engine by sending a sample Kubernetes Audit Event payload to the `/api/v1/analyze` endpoint.

**Test Payload (Anonymous Access Simulation):**
```bash
curl -X POST "http://localhost:8000/api/v1/analyze" -H "Content-Type: application/json" -d '{
    "kind": "Event",
    "apiVersion": "audit.k8s.io/v1",
    "level": "RequestResponse",
    "auditID": "1234-abcd",
    "stage": "ResponseComplete",
    "requestURI": "/api/v1/namespaces/default/pods",
    "verb": "list",
    "user": {
        "username": "system:anonymous"
    }
}'
```

**Check Alerts via API:**
```bash
curl "http://localhost:8000/api/v1/alerts"
```

## Security Considerations & Limitations
- **Statefulness**: Currently, the application holds the last 100 alerts in memory. For a production deployment, this should be backed by a database (e.g., PostgreSQL or Redis) or alerts should be strictly forwarded to a SIEM.
- **Authentication**: The API endpoints (`/api/v1/analyze`, `/`) do not currently require authentication. In a real-world scenario, this service should be deployed behind an API Gateway or configured with token-based authentication (e.g., Bearer tokens).
- **Threat Model**: The tool relies on the integrity of the audit logs sent by the Kubernetes API server. If the API server is compromised or log forwarding is disrupted, the Sentinel will not detect malicious actions.

## Future Improvements
- Add persistent storage (SQLite/PostgreSQL) for alerts.
- Implement API Key authentication for log ingestion endpoints.
- Add support for custom, dynamic rule configuration via YAML files.

# C2 Beacon Hunter

## Overview
C2 Beacon Hunter is a defensive security automation tool designed to detect potential Command & Control (C2) beaconing behavior in network connection logs. Threat actors often use automated scripts (beacons) that reach out to a C2 server at regular intervals. By analyzing the time intervals (jitter) and connection frequency between internal hosts and external endpoints, this tool identifies highly robotic, repetitive network behavior characteristic of malware infections.

## Problem Statement
Detecting advanced malware C2 channels is challenging because beacons can blend in with normal HTTP/HTTPS traffic. Standard rule-based IDSs often miss custom malware. C2 Beacon Hunter provides a behavioral analysis layer, identifying threats based on communication cadence (low jitter percentage and high frequency) rather than relying solely on static signatures.

## Features
- **Behavioral Analysis**: Calculates jitter (standard deviation / mean interval) of connection times to detect robotic communication.
- **RESTful API**: Fast, JSON-based log ingestion endpoint suitable for integration with SIEMs (e.g., Splunk, ELK).
- **SOC Dashboard**: A lightweight, TailwindCSS-powered Web UI for security analysts to quickly triage alerts.
- **Security-First Design**: API key authentication, strict Pydantic input validation to prevent injection, and structured JSON logging.
- **Production-Ready Docker**: Containerized running as a non-root user with read-only file systems and isolated networks.

## Architecture
1. **Log Source (SIEM / Firewall / EDR)** sends batched connection logs (JSON) to the API.
2. **FastAPI Web Service** validates the input structure using Pydantic.
3. **Analyzer Module** groups connections by Source/Destination IP and Port, computes time deltas, calculates standard deviation and mean to find the jitter percentage.
4. **Scoring Engine** evaluates jitter and connection count, tagging threats as Low, Medium, High, or Critical severity.
5. **SOC Dashboard** dynamically visualizes the most recent alerts for human analysts.

## Installation Instructions

### Method 1: Docker (Recommended)
1. Clone the repository and navigate to the directory:
   ```bash
   cd c2_beacon_hunter
   ```
2. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
3. Update `.env` with a strong `API_KEY`.
4. Build and run using Docker Compose:
   ```bash
   docker-compose up --build -d
   ```
5. The API and Dashboard will be available at `http://localhost:8000`.

### Method 2: Native Python
1. Ensure Python 3.11+ is installed.
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the application:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

## Usage Examples

### Ingesting Logs via API
Send an HTTP POST request to `/api/v1/analyze` with your network logs.

```bash
curl -X POST "http://localhost:8000/api/v1/analyze" \
     -H "X-API-Key: default-dev-key" \
     -H "Content-Type: application/json" \
     -d '{
  "logs": [
    {
      "timestamp": "2023-10-27T10:00:00Z",
      "src_ip": "192.168.1.50",
      "dst_ip": "203.0.113.10",
      "dst_port": 443,
      "bytes_sent": 500,
      "bytes_received": 1200
    },
    {
      "timestamp": "2023-10-27T10:01:00Z",
      "src_ip": "192.168.1.50",
      "dst_ip": "203.0.113.10",
      "dst_port": 443,
      "bytes_sent": 510,
      "bytes_received": 1150
    },
    {
      "timestamp": "2023-10-27T10:02:00Z",
      "src_ip": "192.168.1.50",
      "dst_ip": "203.0.113.10",
      "dst_port": 443,
      "bytes_sent": 490,
      "bytes_received": 1190
    },
    {
      "timestamp": "2023-10-27T10:03:00Z",
      "src_ip": "192.168.1.50",
      "dst_ip": "203.0.113.10",
      "dst_port": 443,
      "bytes_sent": 505,
      "bytes_received": 1210
    },
    {
      "timestamp": "2023-10-27T10:04:00Z",
      "src_ip": "192.168.1.50",
      "dst_ip": "203.0.113.10",
      "dst_port": 443,
      "bytes_sent": 495,
      "bytes_received": 1205
    }
  ]
}'
```

**Expected JSON Response:**
```json
{
  "status": "success",
  "processed_logs": 5,
  "alerts_found": 1,
  "alerts": [
    {
      "src_ip": "192.168.1.50",
      "dst_ip": "203.0.113.10",
      "dst_port": 443,
      "connection_count": 5,
      "jitter_percent": 0.0,
      "avg_interval_seconds": 60.0,
      "severity": "High",
      "description": "Potential C2 beacon detected. 5 connections with 0.0% jitter at ~60.0s intervals."
    }
  ]
}
```

### Viewing the Dashboard
Simply navigate to `http://localhost:8000/` in your browser to view the SOC dashboard displaying recent high-fidelity alerts.

## Security Considerations
- **API Key Exposure**: The default configuration uses a hardcoded dev key. In production, securely inject the `API_KEY` environment variable using a secrets manager.
- **DDoS/Resource Exhaustion**: The tool currently performs in-memory analysis. Submitting millions of logs in a single batch could cause memory exhaustion. Implement strict payload size limits or streaming ingestion in front of this service in a production environment.

## Limitations
- **Evasion Tactics**: Highly sophisticated malware uses randomized, high-jitter communication (e.g., 50%+ jitter) or uses legitimate services (e.g., Slack, Twitter) which may bypass this statistical check or blend too well with normal traffic.
- **Statefulness**: Currently, the analyzer only evaluates a single batch of logs at a time. It does not maintain state across multiple API requests (e.g., logs sent hourly).

## Future Improvements
- **Stateful Time-Series Database**: Integrate Redis or TimescaleDB to track connections over days/weeks instead of just per-batch.
- **Machine Learning**: Introduce Isolation Forests or Autoencoders to establish a baseline of "normal" internal traffic, rather than relying on hardcoded jitter thresholds.
- **Byte Size Consistency Check**: Analyze payload sizes (bytes sent/received) as beacons often transmit the exact same amount of keep-alive data.
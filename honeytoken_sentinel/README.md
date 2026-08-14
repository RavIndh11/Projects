# Honeytoken Sentinel

## Overview
Honeytoken Sentinel is a Defensive Security and SOC automation tool. It allows security teams to generate web-based "honeytokens" (canary URLs) that can be embedded into documents, internal wikis, or source code. If an attacker accesses these URLs (e.g., during reconnaissance or after exfiltrating data), the tool immediately logs the request (IP, User-Agent, Headers) and displays it on a dashboard.

This provides high-fidelity, low-noise alerts indicative of compromise.

## Architecture
- **FastAPI Backend**: Handles token generation and deception endpoints.
- **SQLite Database**: Lightweight, embedded storage for tokens and triggered alerts.
- **Web UI**: Tailwind CSS-powered dashboard to view token statuses and alerts.
- **Logging**: Structured JSON logging for easy integration with SIEMs (e.g., Splunk, ELK).

## Features
- Create canary URLs with custom severities (Low, Medium, High, Critical).
- Decoy responses (returns 404 to the attacker to avoid raising suspicion).
- Real-time dashboard for alert monitoring.
- Non-root, hardened Docker container deployment.

## Installation & Setup

### Docker (Recommended)
1. Clone the repository and navigate to the directory.
2. Copy the environment file:
   ```bash
   cp .env.example .env
   ```
3. Build and run with Docker Compose:
   ```bash
   docker compose up --build -d
   ```
4. Access the dashboard at `http://localhost:8000/`.

### Native Run
1. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```
2. Run the application:
   ```bash
   uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```

## Security Considerations
- **No Path Traversal/Injection**: Pydantic models strictly validate token creation inputs.
- **Info Disclosure**: Invalid token triggers redirect safely without disclosing existence.
- **Container Hardening**: The Dockerfile runs the application as a non-root `appuser` (UID 10001) and sets `no-new-privileges:true`.

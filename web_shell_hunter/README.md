# Web Shell Hunter

## Overview & Problem Statement
Web Shell Hunter is a real-time detection engine designed to identify web shells and obfuscated payloads commonly dropped by attackers during post-exploitation. It provides a FastAPI backend for scanning payloads and a SOC-ready dashboard for immediate analysis, enabling defenders to quickly categorize and respond to potential threats.

## Architecture
- **API (FastAPI)**: Exposes a `/api/scan` endpoint for checking payloads.
- **Analyzer**: Computes Shannon entropy and regex-based signatures (e.g., `eval`, `base64_decode`, `system`).
- **Dashboard**: A Tailwind CSS-based web UI served natively by FastAPI for interactive checking.

## Features & Capabilities
- **Signature Detection**: Identifies common PHP/Linux web shell functions.
- **Entropy Analysis**: Detects highly obfuscated or packed payloads using Shannon entropy.
- **Severity Scoring**: Categorizes threats as Low, Medium, High, or Critical.
- **Structured Logging**: Outputs JSON formatted logs suitable for SIEM ingestion.

## Installation & Setup

### Native Execution
```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Docker Execution
```bash
docker compose up --build
```
Access the dashboard at `http://localhost:8000`.

## Security Considerations & Limitations
- **Obfuscation**: Advanced adversaries may use custom encoders that evade simple regex.
- **Future Improvements**: Integrating ML models for anomaly detection beyond statistical entropy, and extending support for JSP/ASPX web shells.

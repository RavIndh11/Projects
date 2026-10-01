# Web Shell Hunter

## Overview & Problem Statement
Web Shell Hunter is a lightweight, real-time security API and dashboard designed to detect web shells and obfuscated payloads in files. It addresses the critical gap of identifying malicious scripts dropped by attackers during compromise, utilizing signature-based detection for known threats (e.g., PHP `eval`, `system`) and entropy analysis to catch heavily obfuscated or base64-encoded payloads that evade standard signatures.

## Architecture
The system consists of three main components:
1.  **Scanning Engine (`app/engine.py`)**: Core logic utilizing Regex for signature matching and Shannon Entropy calculation for obfuscation detection.
2.  **FastAPI Backend (`app/main.py`)**: Exposes REST endpoints (`/api/v1/scan`) for file submission, featuring strict Pydantic model validation to prevent path traversal, and emits structured JSON logs.
3.  **Real-Time Dashboard (`app/templates/index.html`)**: A Tailwind CSS powered, auto-refreshing UI that displays recent scan results, categorized by threat severity (Clean, Suspicious, Malicious).

## Features & Capabilities
*   **Signature Detection**: Catches common PHP, JSP, and ASP web shell patterns.
*   **Obfuscation Detection**: Flags high-entropy strings indicative of encoded payloads.
*   **Structured Logging**: Outputs JSON formatted logs ready for SIEM ingestion.
*   **Input Validation**: Strict validation against path traversal.
*   **Containerized**: Production-ready Docker setup running as a non-root user.

## Installation & Setup

### Native Execution
1.  Install dependencies: `pip install -r requirements.txt`
2.  Run the server: `uvicorn app.main:app --host 127.0.0.1 --port 8000`

### Docker Deployment
1.  Copy `.env.example` to `.env`.
2.  Build and start: `docker compose up --build`
3.  Access the dashboard at `http://localhost:8000`

## Usage Examples

**Scan a clean file:**
```bash
curl -X POST "http://localhost:8000/api/v1/scan" \
     -H "Content-Type: application/json" \
     -d '{"file_path": "var/www/html/index.php", "file_content": "<?php echo \"Hello\"; ?>"}'
```

**Scan a malicious file:**
```bash
curl -X POST "http://localhost:8000/api/v1/scan" \
     -H "Content-Type: application/json" \
     -d '{"file_path": "var/www/html/shell.php", "file_content": "<?php system($_GET[\"cmd\"]); ?>"}'
```

## Security Considerations & Limitations
*   **Limitations**: The current signature set is simplistic for demonstration. Real-world deployment requires a comprehensive signature database. Entropy checks might produce false positives on minified scripts or compressed data.
*   **Threat Model**: Assumes the API is placed behind an authentication gateway or within an internal SOC network, as it currently lacks built-in authentication.

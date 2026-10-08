# Secure Upload Gateway 🛡️

A real-time defensive security microservice that intercepts and analyzes file uploads for common vulnerabilities like extension spoofing, Zip Slip (path traversal), and polyglot payloads.

## Overview & Problem Statement
File uploads are a common attack vector. Applications often naively trust the file extension or the provided MIME type, allowing attackers to upload malicious payloads. The Secure Upload Gateway acts as an intermediary, thoroughly analyzing files before they reach the backend storage or processing systems.

## Features & Capabilities
*   **Extension Spoofing Detection:** Uses `libmagic` to determine the true MIME type of a file and compares it against a strict allowlist and the provided extension.
*   **Zip Slip Protection:** Analyzes ZIP archives for embedded path traversal attacks (e.g., `../../../etc/passwd`).
*   **Polyglot Detection:** Performs heuristic checks for embedded script tags or PHP code within seemingly benign files like images or PDFs.
*   **Lightweight Dashboard:** A web UI built with Tailwind CSS to view recent analysis results in real-time.
*   **Structured Logging:** Outputs findings in JSON format for easy ingestion into SIEMs or log aggregators.

## Architecture
The gateway is built with FastAPI. It exposes an `/upload` endpoint. When a file is uploaded, it is passed through the analysis engine (`analyzer.py`), which runs multiple concurrent checks. The result is returned as a JSON response detailing the threat severity and findings, and is logged and displayed on the dashboard.

## Installation & Setup

### Native Setup (Requires Python 3.11+ and libmagic)
1.  Install the system dependency: `sudo apt-get install libmagic1`
2.  Install Python dependencies: `pip install -r requirements.txt`
3.  Run the application: `uvicorn app.main:app --reload`
4.  Access the dashboard at `http://127.0.0.1:8000/`

### Docker Deployment (Recommended)
1.  Ensure you have Docker and Docker Compose installed.
2.  Run `docker-compose up --build -d`
3.  Access the dashboard at `http://localhost:8000/`

## Usage Examples

**Upload a safe file:**
```bash
curl -F "file=@safe_document.pdf" http://localhost:8000/upload
```

**Upload a spoofed file:**
```bash
# Rename an executable to .pdf and upload it
curl -F "file=@malicious.pdf" http://localhost:8000/upload
```

## Security Considerations
*   This tool provides a first line of defense but should not replace robust backend processing and sandboxing.
*   Polyglot detection is currently heuristic-based and may not catch highly sophisticated or obfuscated payloads.
*   Ensure that the `MAX_UPLOAD_SIZE` environment variable is configured appropriately to prevent Denial of Service (DoS) attacks via massive file uploads.

# Secure Upload Gateway

## Overview & Problem Statement
File uploads are a common attack vector for web applications. The Secure Upload Gateway is a defensive security microservice designed to intercept and analyze file uploads before they are processed or stored by downstream applications. It detects common vulnerabilities such as extension spoofing, polyglots (files containing multiple formats, e.g., an image with embedded PHP), and Zip Slip (path traversal in zip archives).

## Architecture
The gateway acts as an API proxy.
1. **Client** uploads a file to the Gateway.
2. **FastAPI Application** receives the file in memory.
3. **Analyzer Module** inspects the file contents using heuristics, `python-magic` for MIME type detection, and `zipfile` for archive analysis.
4. **Results** are returned to the client/downstream service in a structured JSON format, detailing the detected MIME type, threat findings, and a computed risk severity.
5. All activities are logged using structured JSON for SIEM integration.

## Features
- **In-Memory Analysis**: Files are processed directly from memory to prevent disk-based attacks (like race conditions or local execution).
- **Extension Spoofing Detection**: Compares the file's declared extension with its actual MIME type.
- **Polyglot Detection**: Basic heuristics to identify suspicious code strings in non-executable file formats (like images).
- **Zip Slip Detection**: Scans zip file entries for path traversal payloads (`../` or absolute paths).
- **SIEM-Compatible Logging**: Outputs logs in JSON format for easy ingestion by monitoring tools.
- **SOC Dashboard**: A simple web UI for analysts to manually test and review file uploads.

## Installation & Setup

### Native Execution
1. Install system dependencies: `sudo apt-get install -y libmagic1`
2. Create and activate a virtual environment: `python -m venv venv && source venv/bin/activate`
3. Install Python dependencies: `pip install -r requirements.txt`
4. Run the server: `uvicorn app.main:app --host 127.0.0.1 --port 8000`

### Docker Execution
1. Build and run using Docker Compose: `docker-compose up --build -d`

## Usage Examples

### Using the Dashboard
Navigate to `http://localhost:8000/` in your browser to access the Web UI.

### Using the API
```bash
curl -X POST -F "file=@test.jpg" http://localhost:8000/api/analyze
```

## Security Considerations & Limitations
- **Memory Limits**: The application currently processes files entirely in memory. While this prevents certain disk-based attacks, it makes the service vulnerable to Denial of Service (DoS) if large files are uploaded. A robust implementation should stream large files or enforce strict size limits at the load balancer level.
- **Heuristics vs Signatures**: The polyglot detection relies on simple string matching. More advanced attackers can obfuscate payloads. Integration with an antivirus engine (like ClamAV) or a more sophisticated yara-rule engine is recommended for a production environment.
- **Safe Fallbacks**: If MIME type detection fails, the system defaults to a generic type, which may result in false negatives.

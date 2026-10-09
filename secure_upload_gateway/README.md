# Secure Upload Gateway

## Overview & Problem Statement
File uploads are a common attack vector for web applications. The **Secure Upload Gateway** is a defensive security microservice designed to intercept, analyze, and validate file uploads in real-time before they reach internal storage or downstream applications.

It solves critical security gaps by detecting:
- **Extension Spoofing**: Attackers masking executable files as benign formats (e.g., `malicious.exe` renamed to `invoice.pdf`).
- **Zip Slip Vulnerabilities**: Directory traversal payloads embedded in ZIP archives intended to overwrite sensitive system files upon extraction.
- **Embedded Malware Payloads**: High-risk file types hidden inside compressed archives.

## Architecture
The gateway acts as an API-first inspection layer. It receives files, processes them entirely in memory (to avoid disk-based path traversal and race conditions), and returns a risk assessment.

```
[ Client ] --> [ FastAPI Gateway ]
                     |
                     +--> 1. MIME & Magic Byte Validation
                     +--> 2. Extension Verification
                     +--> 3. In-Memory ZIP Inspection (Deep Scan)
                     |
               [ SIEM / Logger (JSON structured logs) ]
```

## Features & Capabilities
- **Strict In-Memory Processing**: ZIP archives are inspected without touching the disk, preventing path traversal during the scan itself.
- **Magic Byte Verification**: Cross-references the declared file extension against actual file contents using `python-magic`.
- **Zip Slip Detection**: Analyzes internal archive paths for `../` or absolute paths.
- **Structured JSON Logging**: Emits SIEM-compatible JSON logs for easy ingestion into SOC monitoring tools (Splunk, ELK).
- **Web Dashboard**: Included UI for SOC analysts to manually upload and inspect suspicious artifacts.

## Installation & Setup

### Docker (Recommended)
The application is fully containerized, runs as a non-root user, and includes a healthcheck.

```bash
cd secure_upload_gateway

# 1. Copy environment variables
cp .env.example .env

# 2. Build and run the container
docker compose up --build -d
```
The gateway UI will be available at `http://localhost:8000`.

### Native Setup (Development)
Requires Python 3.11+ and system dependency `libmagic`.

```bash
# Ubuntu/Debian
sudo apt-get install -y libmagic1

# Install requirements
pip install -r requirements.txt

# Run the server
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Usage Examples

### Web Dashboard
Navigate to `http://localhost:8000/` to use the interactive drag-and-drop analysis UI.

### API Endpoint (`/api/v1/analyze`)
You can programmatically submit files for analysis.

```bash
# Submit a normal file
curl -X POST "http://localhost:8000/api/v1/analyze" \
  -H "accept: application/json" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@safe_document.pdf"
```

**Example Output (Spoofed File):**
```json
{
  "is_safe": false,
  "risk_score": 100,
  "threats_found": [
    "Extension spoofing detected: '.pdf' does not match 'text/plain'"
  ],
  "file_type": "text/plain",
  "details": {
    "detected_mime": "text/plain",
    "extension": ".pdf",
    "file_size_bytes": 1024
  }
}
```

## Security Considerations & Limitations
- **File Size**: Currently limited to 50MB per upload for POC purposes. Extremely large files or "Zip Bombs" (Decompression bombs) are not explicitly mitigated in this version beyond the initial size check.
- **YARA Signatures**: This version focuses on structure and metadata. Future iterations should integrate a YARA engine for deep byte-pattern matching.
- **Antivirus Integration**: This service is a pre-filter; it should be used in conjunction with a dedicated AV scanner (like ClamAV) for signature-based malware detection.

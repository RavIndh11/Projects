# Secure Upload Gateway

## Overview & Problem Statement
Applications frequently accept file uploads (e.g., avatars, document submissions) without deep inspection. Attackers can exploit this by uploading polyglot files (e.g., PHP code hidden inside a valid GIF image) or malicious archives designed to exploit vulnerabilities like Zip Slip (path traversal via extracted zip files).

**Secure Upload Gateway** is a defensive security microservice that intercepts, analyzes, and sanitizes file uploads before they reach the main application backend. It acts as a protective shield against file-based attacks.

## Architecture
```
[ Client / Main App ] -> POST /api/v1/scan (File Upload)
                                 |
                          [ Secure Gateway ]
                                 |
         +-----------------------+------------------------+
         |                       |                        |
[ Magic Bytes Check ]   [ Polyglot / Script Check ]   [ Zip Slip Check ]
         |                       |                        |
         +-----------------------+------------------------+
                                 |
                     [ Analysis Aggregator ]
                                 |
[ Response to Client (JSON) ] <--+--> [ JSON Logs -> SIEM ]
```

## Features & Capabilities
- **Magic Bytes Verification**: Compares the file extension against the file's actual content (magic bytes) to detect extension spoofing.
- **Polyglot & Embedded Script Detection**: Scans ostensibly binary files (like images) for embedded web shells or scripts (e.g., `<?php`, `<script>`).
- **Zip Slip Prevention**: Analyzes `.zip` archives in memory to detect malicious path traversal sequences (e.g., `../../../etc/passwd`).
- **Structured SOC Logging**: Emits JSON-formatted logs suitable for ingestion into SIEMs or Logstash, tagged with analysis severity (Low, Medium, High, Critical).
- **Lightweight Web UI**: Includes a Tailwind CSS-powered dashboard for manual analysis and testing.

## Installation & Setup

### Native (Python)
1. Clone the repository and navigate to the directory:
   ```bash
   cd secure_upload_gateway
   ```
2. Install the requirements:
   ```bash
   pip install -r requirements.txt
   ```
3. Start the application:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

### Docker (Recommended)
1. Navigate to the directory:
   ```bash
   cd secure_upload_gateway
   ```
2. Run using Docker Compose:
   ```bash
   docker compose up --build
   ```
   *Note: Ensure you copy `.env.example` to `.env` if required by your configuration.*

## Usage Examples

### Web Dashboard
Open your browser to `http://localhost:8000/` and use the UI to upload and scan files interactively.

### API Usage
You can integrate this microservice into your main backend by proxying file uploads to the `/api/v1/scan` endpoint.

**Request:**
```bash
curl -X POST -F "file=@test.pdf" http://localhost:8000/api/v1/scan
```

**Response (Clean File):**
```json
{
  "status": "success",
  "result": {
    "filename": "test.pdf",
    "is_safe": true,
    "severity": "Low",
    "matched_rules": [],
    "details": [
      "No threats detected."
    ]
  },
  "message": null
}
```

**Response (Malicious Polyglot):**
```json
{
  "status": "success",
  "result": {
    "filename": "polyglot.pdf",
    "is_safe": false,
    "severity": "Critical",
    "matched_rules": [
      "embedded_script_detected"
    ],
    "details": [
      "Found suspicious embedded script tags (e.g., <?php, <script>)."
    ]
  },
  "message": null
}
```

## Security Considerations & Limitations
- **In-Memory Processing**: The current implementation loads files into memory for analysis. While fast, this may be susceptible to DoS if extremely large files are uploaded. The `MAX_UPLOAD_SIZE` should be enforced via an API gateway or reverse proxy (like Nginx) before reaching this service.
- **Evasion**: The embedded script signatures use basic regex patterns. Advanced obfuscation might bypass these checks. Future versions could integrate entropy analysis or machine learning to detect obfuscated payloads.
- **Archive Extraction**: The Zip Slip check inspects the archive index but does not extract it. Ensure that the downstream application uses safe extraction methods even if the gateway deems the file safe.

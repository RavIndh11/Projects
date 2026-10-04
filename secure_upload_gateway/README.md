# Secure Upload Gateway

## Overview & Problem Statement

File uploads are a common attack vector for web applications. The **Secure Upload Gateway** is a defensive security microservice designed to intercept and analyze file uploads in real-time before they reach application logic or storage. It identifies and blocks sophisticated attacks that bypass simple extension checks.

This tool solves the gap of standardizing secure file handling by identifying:
- **Extension Spoofing:** When an attacker uploads a malicious file (e.g., `.php`) but renames it to an image extension (`.png`), bypassing basic checks.
- **Embedded Polyglots:** When valid image files contain embedded malicious scripts (e.g., `<script>`, `<?php`) intended to be executed if served directly or included by backend logic.
- **Zip Slip Vulnerabilities:** When archive files contain directory traversal payloads (e.g., `../../../etc/passwd`) designed to overwrite system files upon extraction.

## Architecture

```text
[ Client (Web/API) ] --> POST /api/analyze --> [ Secure Upload Gateway (FastAPI) ]
                                                       |
                                                       v
                                            [ Analysis Engine In-Memory ]
                                            - Magic Bytes Validation
                                            - Polyglot Signature Scan
                                            - Zip Traversal Analysis
                                                       |
                                                       v
                                        [ Structured JSON Logs for SIEM/SOC ]
                                                       |
                                                       v
[ Threat Report (Clean/Malicious) ] <-------------------
```

## Features & Capabilities

- **Real-Time Analysis**: Processes files in memory without touching disk, preventing accidental execution or storage of malware during analysis.
- **Deep Content Inspection**: Validates file integrity using Magic Bytes.
- **Polyglot Detection**: Scans file contents against known malicious signatures.
- **Zip Slip Defense**: Safely inspects Zip entry metadata for path traversal without extracting contents.
- **SOC-Ready**: Outputs structured JSON logs containing threat severity and details for easy ingestion into SIEMs (Splunk, ELK, etc.).
- **Lightweight UI**: Includes a web dashboard for manual analyst verification.
- **Hardened Deployment**: Runs as a non-root user in a minimal Docker container.

## Installation & Setup

### Native Execution

1. Navigate to the project directory:
   ```bash
   cd secure_upload_gateway
   ```
2. Create and activate a virtual environment (optional but recommended).
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Copy the environment template:
   ```bash
   cp .env.example .env
   ```
5. Run the application:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

### Docker Deployment

1. Build and run using Docker Compose:
   ```bash
   docker compose up --build -d
   ```
2. The application will be available at `http://localhost:8000`.

## Usage Examples

### Web UI
Navigate to `http://localhost:8000` in your browser to use the interactive dashboard.

### API via cURL

**Clean File Upload:**
```bash
curl -X POST "http://localhost:8000/api/analyze" -F "file=@legit_image.png"
```
**Expected Response:**
```json
{
  "filename": "legit_image.png",
  "status": "clean",
  "threats": [],
  "severity": "low"
}
```

**Malicious File (Extension Spoofing):**
```bash
# Assuming bad.pdf was renamed to bad.png
curl -X POST "http://localhost:8000/api/analyze" -F "file=@bad.png"
```
**Expected Response:**
```json
{
  "filename": "bad.png",
  "status": "malicious",
  "threats": [
    {
      "type": "extension_spoofing",
      "description": "File extension 'png' does not match actual file type 'pdf'"
    }
  ],
  "severity": "high"
}
```

## Security Considerations & Limitations

- **In-Memory Constraints**: This microservice processes files in-memory to prevent disk-based attacks. As a result, it is subject to memory limits (`MAX_UPLOAD_SIZE` is enforced). It is not designed for gigabyte-sized files.
- **Signature Evasion**: The polyglot detection relies on known signatures (regex). Highly obfuscated or novel payloads might evade detection. It should be used in conjunction with a dedicated AV/EDR solution for comprehensive defense.
- **Threat Model Assumptions**: Assumes the network path to this microservice is secure (e.g., deployed behind an API Gateway or WAF with TLS termination).

# Secure Upload Gateway

## Overview & Problem Statement
File upload endpoints are notorious vectors for severe security vulnerabilities. Attackers commonly exploit them using:
1. **Extension Spoofing / Polyglots:** Bypassing simplistic `.extension` filters by uploading executable code (e.g., PHP, HTML) masked as an image (`.jpg`).
2. **Zip Slip (Path Traversal via Archives):** Uploading crafted `.zip` archives containing malicious relative (`../../../etc/passwd`) or absolute paths. If extracted unsafely, these files overwrite critical system files.

**Secure Upload Gateway** is a defensive security microservice that acts as an intercepting proxy. It analyzes uploaded files completely in memory—preventing the analyzer itself from being compromised by race conditions or filesystem path traversal—and logs structured security intelligence to a SOC Dashboard and SIEM.

## Architecture

```text
[ User / Attacker ]
       | (File Upload via HTTP POST)
       v
[ Secure Upload Gateway (FastAPI) ]
       |-- 1. Size Validation (Memory Limit Enforcement)
       |-- 2. Magic Byte & MIME Analysis (python-magic)
       |-- 3. Extension Spoofing Detection
       |-- 4. In-Memory Zip Slip Analysis (io.BytesIO + zipfile)
       v
[ SIEM / Logstash ] <--- (JSON Structured Logs via python-json-logger)
       |
[ SOC Dashboard ] <----- (Real-time Tailwind CSS UI)
```

## Features & Capabilities
* **In-Memory Zip Slip Detection:** Analyzes ZIP headers for absolute paths and `../` traversal sequences without ever writing to disk.
* **MIME-type vs Extension Spoofing Detection:** Utilizes libmagic to verify that the true magic bytes of the file match the claimed extension.
* **Structured SIEM Logging:** Emits JSON-formatted logs for immediate ingestion into ElasticSearch, Splunk, or Logstash.
* **Real-time SOC Dashboard:** A lightweight Tailwind CSS interface for security analysts to monitor upload telemetry and threat intelligence in real-time.
* **Hardened Container:** Docker deployment runs as a non-root `appuser` with functional healthchecks.

## Installation & Setup

### Docker (Recommended)
1. Ensure Docker and Docker Compose are installed.
2. Build and run the container:
   ```bash
   docker compose up --build
   ```
3. Access the SOC Dashboard at `http://localhost:8000`.

### Native (Local Development)
1. Install the `libmagic` system dependency:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install libmagic1

   # macOS
   brew install libmagic
   ```
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the development server:
   ```bash
   uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```

## Usage Examples

**Uploading a safe file:**
```bash
curl -X POST -F "file=@safe_document.pdf" http://localhost:8000/upload
```
*Expected JSON Response (200 OK):* `{"id": "...", "filename": "safe_document.pdf", "is_safe": true, "threats": [], "mime_type": "application/pdf", "size": 1024}`

**Uploading a spoofed extension (e.g., EICAR.txt renamed to .jpg):**
```bash
mv EICAR.txt EICAR.jpg
curl -X POST -F "file=@EICAR.jpg" http://localhost:8000/upload
```
*Expected JSON Response (200 OK):* `{"is_safe": false, "threats": ["Extension spoofing detected: .jpg does not match text/plain"], ...}`

## Security Considerations & Limitations
* **Memory Limits:** The gateway processes files in memory to mitigate filesystem risks. By default, uploads are capped at 5MB via the `MAX_UPLOAD_SIZE` environment variable to prevent OOM (Out Of Memory) Denial of Service attacks.
* **Malware Signatures:** This tool detects structural upload attacks (spoofing, Zip Slip). It does **not** perform signature-based malware scanning (e.g., ClamAV) or dynamic sandboxing. It should be used in conjunction with an AV scanning pipeline.
* **Password-Protected Archives:** The current ZIP analysis does not recurse into password-protected archives or nested archives (ZIP bombs).

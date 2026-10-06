# Secure Upload Gateway

A defensive security microservice and SOC automation tool designed to intercept, analyze, and quarantine file uploads before they reach internal storage systems.

## Overview & Problem Statement
Unrestricted file uploads are a critical security risk. Attackers often attempt to upload:
- Executables disguised as images (Extension Spoofing).
- Valid images with embedded malicious scripts (Polyglots).
- Malicious archives designed to overwrite system files upon extraction (Zip Slip).

**Secure Upload Gateway** acts as a middle-layer proxy, statically analyzing file uploads for these vulnerabilities in real-time, providing immediate feedback via a REST API and a web dashboard suitable for SOC analysts.

## Architecture
```text
[ Client / Attacker ]
        | (Uploads file)
        v
[ FastAPI REST Endpoint ]
        |
[ FileAnalyzer Engine ]
   ├── Magic Bytes Analysis (Extension Spoofing)
   ├── Regex / Signature Analysis (Polyglots, embedded PHP/JS)
   └── Zip Archive Inspection (Zip Slip traversal paths)
        |
[ Structured JSON Logs ] ---> (Shipped to SIEM / ELK)
        |
[ Response to Client ] (Allow / Block / Quarantine)
```

## Features & Capabilities
*   **Extension Spoofing Detection:** Validates the file extension against the true MIME type using `libmagic`.
*   **Polyglot Detection:** Scans non-script files (images, PDFs) for embedded PHP, JavaScript, or executable (`ELF`, `MZ`) signatures.
*   **Zip Slip Prevention:** Recursively inspects `.zip` archives for path traversal characters (`../`, `/`) without extracting the payload.
*   **SOC Dashboard:** A lightweight Tailwind CSS + HTML UI to upload files and visualize security findings.
*   **Structured Logging:** Outputs standard JSON logs via `python-json-logger` for easy SIEM integration.

## Installation & Setup

### Native Setup
1.  Clone the repository and navigate to the directory:
    ```bash
    cd secure_upload_gateway
    ```
2.  Install dependencies (requires `libmagic1` on Linux):
    ```bash
    sudo apt-get install libmagic1
    pip install -r requirements.txt
    ```
3.  Run the FastAPI server:
    ```bash
    uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
    ```

### Docker Setup
The application includes a production-ready, hardened Docker container (non-root user, capability drops).

1.  Build and run using Docker Compose:
    ```bash
    docker compose up --build
    ```
2.  Access the UI at `http://localhost:8000`.

## Usage Examples

### Web UI
Open your browser to `http://localhost:8000` to access the drag-and-drop SOC analyst dashboard.

### API Endpoint (`/api/analyze`)
You can programmatically analyze files using `curl`:

```bash
curl -X POST "http://localhost:8000/api/analyze" \
  -H "accept: application/json" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@/path/to/suspect_file.jpg"
```

**Example Response (Polyglot Detected):**
```json
{
  "filename": "suspect_file.jpg",
  "is_safe": false,
  "overall_severity": "Critical",
  "findings": [
    {
      "vulnerability": "Polyglot / Embedded Script",
      "severity": "Critical",
      "description": "PHP code detected inside a non-script file format"
    }
  ],
  "mime_type": "image/jpeg",
  "extension": ".jpg"
}
```

## Security Considerations & Limitations
*   **Static Analysis Only:** This tool relies on static signature matching and magic bytes. It does not execute files in a sandbox (dynamic analysis) to observe behavior.
*   **Large Files:** Very large files may consume significant memory as the analysis currently reads the file into a memory buffer. Future improvements should stream large files in chunks.
*   **Evasion:** Sophisticated attackers might obfuscate embedded scripts to evade basic regex signatures. Integrating a robust YARA engine would be a strong next step.

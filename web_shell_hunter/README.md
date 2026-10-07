# Web Shell Hunter 🛡️

A real-time security API and dashboard designed to detect web shells and obfuscated payloads using signatures and entropy analysis.

## Overview & Problem Statement
Attackers often upload web shells (e.g., PHP, ASP, JSP files) or highly obfuscated payloads (Base64/Hex encoding) to gain persistent access to a compromised server. Traditional basic static analysis might miss these or fail to quickly flag them for Security Operations Center (SOC) teams. **Web Shell Hunter** acts as a defensive security tool to automatically scan files or text snippets and assess their threat level in real-time.

## Architecture
1.  **FastAPI Backend:** Handles incoming text or file upload requests.
2.  **Detection Engine:**
    *   **Signature Matching:** Uses pre-compiled regex to match common web shell patterns (e.g., `eval(base64_decode(`, `system(`, `Runtime.getRuntime().exec(`).
    *   **Entropy Analysis:** Calculates Shannon entropy to detect highly randomized/obfuscated strings often used in payloads.
3.  **Logging:** Structured JSON logging for SIEM integration.
4.  **Dashboard:** A lightweight HTML/Tailwind frontend to visualize results, risk scores, and threat levels.

## Features & Capabilities
*   **Real-time Analysis:** API endpoints for immediate scanning.
*   **Heuristic Scoring:** Combines signature matches and high entropy to calculate a robust risk score (0-100).
*   **Threat Categorization:** Categorizes risk into Low, Medium, High, and Critical.
*   **SOC Ready Logging:** JSON structured logs without duplicate fields.
*   **Containerized:** Production-ready Dockerfile and docker-compose setup.

## Installation & Setup

### Native Execution (Python 3.11+)
```bash
# 1. Navigate to the project directory
cd web_shell_hunter

# 2. Create a virtual environment and install dependencies
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Run the application
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Docker Execution
```bash
# 1. Navigate to the project directory
cd web_shell_hunter

# 2. Build and start the container
docker-compose up --build -d
```
The application will be accessible at `http://localhost:8000`.

## Usage Examples

### Dashboard
Navigate to `http://localhost:8000` to use the interactive UI. You can upload a file or paste raw text.

### API (Text Scan)
```bash
curl -X POST http://localhost:8000/api/scan/text \
     -H "Content-Type: application/json" \
     -d '{"content": "<?php eval(base64_decode($_POST[\"cmd\"])); ?>", "filename": "test.php"}'
```

**Response:**
```json
{
  "filename": "test.php",
  "is_malicious": true,
  "risk_score": 30.0,
  "entropy": 4.12,
  "matched_signatures": [
    "eval_payload"
  ],
  "threat_level": "Medium"
}
```

### API (File Upload Scan)
```bash
curl -X POST http://localhost:8000/api/scan/file \
     -F "file=@/path/to/suspicious_file.php"
```

## Security Considerations & Limitations
*   **Evasion:** Highly customized obfuscators might bypass static signatures. Entropy analysis helps, but advanced actors can pad payloads to lower entropy.
*   **False Positives:** High entropy might trigger on legitimate cryptographic keys or compiled binaries if scanned mistakenly.
*   **Execution Environment:** This tool is for *static analysis*. It does not execute the payload (dynamic analysis/sandboxing).
*   **Hardening:** The Docker container runs as a non-root user for defense-in-depth. Ensure appropriate network controls (WAF, reverse proxy) are placed in front of this API in production.

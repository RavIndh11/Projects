# MFA Fatigue Hunter

**MFA Fatigue Hunter** is a real-time detection engine designed to identify MFA Fatigue (MFA Bombing) attacks from authentication logs.

## Problem Statement

MFA Fatigue attacks occur when a threat actor bombards a user's device with MFA push notifications, hoping the user will eventually accept one out of frustration, habit, or confusion. This tool detects high-frequency sequences of denied or ignored MFA prompts, particularly when followed by an accepted prompt.

## Features
- **Real-Time Analysis:** Analyzes authentication and MFA logs upon ingestion to detect patterns of abuse.
- **RESTful API:** Exposes endpoints for log ingestion and alert retrieval.
- **SOC Dashboard:** A lightweight TailwindCSS-powered Web UI for security analysts.
- **Secure Deployment:** Dockerized with non-root user, read-only file systems, and strict Pydantic input validation.

## Installation & Setup

### Docker (Recommended)
1. Navigate to the project directory:
   ```bash
   cd mfa_fatigue_hunter
   ```
2. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
3. Update `.env` with your secure `API_KEY`.
4. Build and run using Docker Compose:
   ```bash
   docker-compose up --build -d
   ```
5. The API and Dashboard will be available at `http://localhost:8000`.

### Native Python
1. Ensure Python 3.11+ is installed.
2. Create and activate a virtual environment:
   ```bash
   cd mfa_fatigue_hunter
   python -m venv venv
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the application:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

## Usage
Submit JSON logs to the API:

```bash
curl -X POST "http://localhost:8000/api/v1/logs" \
     -H "X-API-Key: default-dev-key" \
     -H "Content-Type: application/json" \
     -d '{
  "logs": [
    {
      "timestamp": "2023-10-27T10:00:00Z",
      "user_id": "alice@example.com",
      "action": "mfa_prompt_denied"
    },
    {
      "timestamp": "2023-10-27T10:00:10Z",
      "user_id": "alice@example.com",
      "action": "mfa_prompt_denied"
    },
    {
      "timestamp": "2023-10-27T10:00:20Z",
      "user_id": "alice@example.com",
      "action": "mfa_prompt_accepted"
    }
  ]
}'
```

## Security Considerations
- Uses strict Pydantic schemas to validate logs.
- The `API_KEY` prevents unauthorized log injection.
- Docker image runs as `appuser`.
# MFA Fatigue Hunter

**MFA Fatigue Hunter** is a defensive cybersecurity tool designed to detect real-time Multi-Factor Authentication (MFA) fatigue (or "prompt bombing") attacks.

Attackers with stolen credentials frequently spam victim users with continuous MFA push notifications in hopes the victim will mistakenly approve a request to make it stop. This project identifies this pattern and flags if a successful login occurs during or immediately after a fatigue attack, alerting the SOC of a potentially compromised account.

## Features & Capabilities
- **Event Ingestion API**: Lightweight FastAPI endpoint designed to receive webhooks from Identity Providers (IdPs) like Okta, Azure AD, or Duo.
- **Fatigue Detection Logic**: Identifies anomalous behavior when a user receives a high volume of `mfa_prompt` events within a short timeframe.
- **Prompt Bombing Success Detection**: Specifically detects if an `mfa_success` event occurs during an active fatigue window, flagging the incident as Critical.
- **SOC Dashboard**: A live, web-based UI built with TailwindCSS for real-time visualization of identity alerts and threat severities.
- **Production Ready**: Fully containerized setup via Docker/Docker Compose configured to run securely using a non-root user and automated health checks.

## Architecture
```text
[ Identity Provider ] ---> Webhook POST ---> [ MFA Fatigue Hunter API ]
    (Okta/Azure AD)                              |
                                                 |--> [ Detector Logic ]
                                                         |-- Tracks time-window rate limits
                                                         |-- Detects 'Fatigue' & 'Success'
                                                         |--> [ SOC Dashboard UI ]
```

## Setup & Execution

### Option 1: Native Local Environment

1. Set up your Python virtual environment and install requirements:
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
2. Start the application:
   ```bash
   uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```
3. Run the test suite:
   ```bash
   PYTHONPATH=. pytest tests/
   ```

### Option 2: Docker Deployment
1. Ensure Docker and Docker Compose are installed.
2. Initialize environment variables (if required):
   ```bash
   cp .env.example .env
   ```
3. Build and launch the container:
   ```bash
   docker compose up --build -d
   ```
4. Access the SOC Dashboard: Navigate to `http://localhost:8000` in your web browser.

## Usage Example (Simulating an Attack)
You can test the tool by sending simulated IdP webhooks to the ingestion endpoint:

**1. Send 5 simulated MFA prompts rapidly (Fatigue attack)**
```bash
for i in {1..5}; do
  curl -X POST http://localhost:8000/api/events \
       -H "Content-Type: application/json" \
       -d '{"user_email":"victim@example.com","event_type":"mfa_prompt","source_ip":"192.168.1.100"}'
done
```
*Result: The dashboard will show a High severity "Possible MFA Fatigue Attack" alert.*

**2. Send a successful MFA event simulating a victim accepting the prompt**
```bash
curl -X POST http://localhost:8000/api/events \
     -H "Content-Type: application/json" \
     -d '{"user_email":"victim@example.com","event_type":"mfa_success","source_ip":"192.168.1.100"}'
```
*Result: The dashboard will immediately show a Critical severity "SUCCESSFUL MFA PROMPT BOMBING" alert.*

## Security Considerations & Limitations
- **In-Memory Storage**: The current implementation stores state in memory for simplicity. In a true enterprise deployment, this should be backed by Redis or an external database to persist state across instances and restarts.
- **IdP Configuration**: You must configure your Identity Provider's event logs or webhooks to transform to the required `AuthEvent` schema before ingestion.

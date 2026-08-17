# GraphQL Inspector

## Overview & Problem Statement
GraphQL endpoints often suffer from misconfigurations, the most common being enabling Introspection in production. When introspection is enabled, an attacker can query the endpoint to retrieve the entire API schema. This schema maps out all available queries, mutations, types, and fields. Often, developers unintentionally expose sensitive fields (e.g., `passwordResetToken`, `internalAPIKey`, `ssn`) or backend mutations that should not be publicly accessible.

**GraphQL Inspector** is a Defensive Security / AppSec tool designed to automate the discovery of these risks. It probes a target GraphQL endpoint to check if introspection is enabled, and if so, it parses the schema to flag overtly sensitive field names, alerting security engineers to potential data leaks.

## Architecture
```text
[ User (SOC / AppSec) ]
       | (URL Input via UI/API)
       v
[ GraphQL Inspector (FastAPI) ]
       |
       | 1. URL Validation (SSRF Check)
       | 2. Introspection Query (`__schema`)
       v
[ Target GraphQL Endpoint ]
       | (Schema Response)
       v
[ Analysis Engine ] ---> [ Keyword/Heuristic Matching on Field Names ]
       |
       v
[ Web Dashboard / JSON API Response ]
```

## Features & Capabilities
- **Introspection Detection**: Automatically verifies if a GraphQL endpoint permits introspection queries.
- **Sensitive Data Heuristics**: Analyzes the returned schema for fields containing sensitive keywords (e.g., "password", "token", "ssn", "secret").
- **SSRF Mitigation**: Implements basic URL validation and IP resolution checks to prevent scanning internal networks (e.g., `localhost`, AWS Metadata).
- **Web Dashboard**: A lightweight, Tailwind CSS-based UI for easy manual testing.
- **REST API**: Integrates easily into CI/CD or SOC automation pipelines via the `/api/analyze` endpoint.
- **Docker Ready**: Runs as a non-root user in a minimal container.

## Installation & Setup

### Option 1: Docker (Recommended)
1. Navigate to the directory:
   ```bash
   cd graphql_inspector
   ```
2. Build and run the container:
   ```bash
   docker-compose up --build -d
   ```
3. Access the Web Dashboard at: `http://localhost:8000`

### Option 2: Native Setup (Python 3.11+)
1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the server:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

## Usage Examples

### Web Dashboard
Navigate to `http://localhost:8000/`. Enter a target URL (e.g., `https://api.example.com/graphql`) and click "Scan Endpoint".

### API Request
```bash
curl -X POST http://localhost:8000/api/analyze \
     -H "Content-Type: application/json" \
     -d '{"url": "https://api.example.com/graphql"}'
```

### API Response
```json
{
  "url": "https://api.example.com/graphql",
  "introspection_enabled": true,
  "error_message": null,
  "sensitive_fields": [
    {
      "type_name": "User",
      "field_name": "passwordHash",
      "reason": "Matches sensitive keyword: 'password'"
    }
  ],
  "total_types": 45
}
```

## Security Considerations & Limitations
- **DNS Rebinding**: The SSRF protection resolves the hostname to an IP address before the HTTP request. However, `httpx` will resolve the hostname again during the request. This Time-Of-Check to Time-Of-Use (TOCTOU) gap leaves a theoretical window for DNS rebinding attacks. In a hardened environment, the HTTP client should be forced to connect to the pre-resolved safe IP.
- **Heuristic Limitations**: The detection relies on substring matching of English keywords. It will not detect sensitive fields named obscurely (e.g., `usr_pwd`) or in other languages.
- **Introspection Disabled**: If introspection is disabled, this tool cannot analyze the schema. However, tools like Clairvoyance can attempt schema brute-forcing, which is out of scope for this basic analyzer.

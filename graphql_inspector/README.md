# GraphQL Inspector

## Overview & Problem Statement
GraphQL APIs are powerful but often expose a significant attack surface if not properly secured. Because clients can dictate exactly what data they want, an attacker can construct malicious queries that cause Denial of Service (DoS) via deep nesting, resource exhaustion via excessive aliases, or information disclosure via unprotected introspection.

**GraphQL Inspector** is a defensive security tool designed to identify these potentially malicious GraphQL queries before they hit the backend resolvers.

## Architecture
The tool acts as a proxy or sidecar service. It receives a GraphQL query and parses it into an Abstract Syntax Tree (AST) to evaluate security rules.

```text
[Client] ---> [GraphQL Inspector (FastAPI)] ---> (Risk Score & Security Flags)
                    |
                    +--> AST Parser
                    +--> Rules Engine:
                         - Introspection Check
                         - Depth Calculation
                         - Alias Counting
```

## Features & Capabilities
- **Deep Nesting Detection:** Calculates maximum depth of the query to prevent CPU/Memory exhaustion (DoS).
- **Excessive Alias Detection:** Counts aliases to prevent batching attacks.
- **Introspection Detection:** Flags queries that attempt to read the `__schema` or `__type` meta-fields.
- **SOC Dashboard UI:** A lightweight Tailwind CSS dashboard to paste queries and get immediate visual feedback on risk score and severity.
- **JSON Structured Logging:** Ready for integration with SIEMs (Splunk, Elastic) with parseable JSON logs.

## Installation & Setup

### Native (Local Python)
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### Docker
```bash
docker compose up --build
```
The application will be available at `http://localhost:8000`.

## Usage Examples

**API Request:**
```bash
curl -X POST http://localhost:8000/api/v1/inspect \
     -H "Content-Type: application/json" \
     -d '{"query": "query { __schema { types { name } } }"}'
```

**API Response:**
```json
{
  "status": "success",
  "risk_score": "Medium",
  "flags": [
    {
      "rule_id": "GRAPHQL_INTROSPECTION",
      "description": "Introspection query detected",
      "severity": "Medium"
    }
  ],
  "metrics": {
    "depth": 3,
    "aliases": 0,
    "introspection": true
  }
}
```

## Security Considerations & Limitations
- **Current Limitations:** The introspection check currently uses simple string matching combined with AST fallback for speed. A more robust implementation would rely purely on full AST traversal. It also does not currently rate-limit the incoming inspection requests.
- **Hardening:** The provided Dockerfile runs the application as a non-root user (`appuser` UID 10001) to minimize container breakout risks.

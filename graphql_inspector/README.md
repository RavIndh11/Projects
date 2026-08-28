# GraphQL Inspector

A defensive security tool designed to identify and analyze potentially malicious GraphQL queries. It specifically targets Denial of Service (DoS) attacks via deep nesting and excessive aliases, as well as Information Disclosure via unauthorized introspection queries.

## Problem Statement

GraphQL APIs give immense power to the client. Without proper guardrails, an attacker can construct queries that consume excessive server resources (DoS) or extract the entire API schema (Introspection). This tool serves as a lightweight, deployable inspector that acts as a defensive proxy or SOC analysis utility to detect these threats in real-time.

## Architecture

The system is built on **FastAPI** with strict input validation via **Pydantic**.
The core analysis engine leverages **graphql-core** to walk the Abstract Syntax Tree (AST) of the incoming GraphQL query and measure depth, alias limits, and introspection usage against configurable thresholds.

## Features

- **Query Depth Analysis:** Detects and scores deeply nested queries (e.g., recursive relationships).
- **Alias Counting:** Detects excessive aliases often used in batched query attacks.
- **Introspection Detection:** Flags queries attempting to map the API structure (`__schema`, `__type`).
- **Structured JSON Logging:** Native support for ingestion into SIEMs (ELK, Splunk).
- **SOC Web Dashboard:** A lightweight Tailwind UI for analysts to manually evaluate payloads.
- **Secure by Default:** Containerized as a non-root user (`appuser`).

## Installation & Setup

### Local Execution (Python 3.11+)

1. Create a virtual environment and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
2. Run the application:
   ```bash
   uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```
3. Access the dashboard at `http://127.0.0.1:8000`.

### Docker Deployment (Recommended)

1. Copy the environment file:
   ```bash
   cp .env.example .env
   ```
2. Build and run the container securely:
   ```bash
   docker compose up --build -d
   ```

## Usage Example

**API Request:**
```bash
curl -X POST http://localhost:8000/api/analyze \
     -H "Content-Type: application/json" \
     -d '{
       "query": "query { __schema { types { name } } }",
       "max_depth_limit": 5,
       "max_alias_limit": 5,
       "allow_introspection": false
     }'
```

**Response:**
```json
{
  "status": "success",
  "message": null,
  "depth": 3,
  "aliases": 0,
  "introspection": true,
  "field_count": 3,
  "issues": [
    "Introspection query detected. Potential Information Disclosure."
  ],
  "risk_score": 50,
  "severity": "High",
  "is_safe": false
}
```

## Security Considerations
- This tool analyzes the query statically; it does not execute it. It is designed to sit *in front* of your GraphQL server or alongside your log ingestion pipelines.
- Ensure appropriate rate limiting is applied to the inspector's endpoints.

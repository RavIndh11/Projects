# GraphQL Inspector

GraphQL Inspector is a defensive security tool designed to automate the discovery of exposed GraphQL introspection endpoints and analyze their schemas for sensitive fields and available mutations.

## Overview & Problem Statement
GraphQL endpoints often leave introspection enabled in production environments. Introspection allows anyone to query the API for its complete schema, revealing data types, queries, mutations, and fields. This represents a significant information disclosure risk.

Attackers leverage introspection to:
- Discover hidden administrative mutations (e.g., `deleteUser`, `createAdmin`).
- Find sensitive data fields inadvertently exposed in the API (e.g., `user.password`, `apiToken`, `ssn`).
- Map the entire attack surface of the application.

**GraphQL Inspector** solves this by providing SOC analysts and security engineers with a simple, robust tool to query a target GraphQL URL, parse its schema, and automatically flag high-risk exposures.

## Features & Capabilities
- **Introspection Detection**: Accurately determines if introspection is enabled on a target endpoint.
- **Sensitive Field Analysis**: Parses the schema to identify fields matching sensitive keywords (e.g., password, token, key).
- **Mutation Discovery**: Extracts and lists all available mutations exposed by the API.
- **Threat Scoring**: Automatically calculates a threat severity (Low, Medium, High, Critical) based on the presence of sensitive fields and mutations.
- **Custom Headers Support**: Allows injecting `Authorization` or custom headers needed to reach protected endpoints.
- **Modern Web UI**: A clean, responsive dashboard built with Tailwind CSS for manual analysis.
- **JSON API**: Can be integrated into existing SOC automation pipelines via its REST API.

## Architecture

1. **User/Analyst** submits a GraphQL URL and optional headers via the Web UI or API.
2. **FastAPI Backend** (`app/main.py`) validates the request using Pydantic models.
3. **Core Logic** (`app/core.py`) uses `httpx` to send a standardized GraphQL introspection query.
4. If successful, the schema is parsed to extract types, fields, and mutations.
5. Findings are evaluated against a predefined list of sensitive keywords.
6. A final threat severity is calculated and returned to the user.

## Installation & Setup

### Native Execution

1. Ensure Python 3.11+ is installed.
2. Clone the repository and navigate to the project directory:
   ```bash
   cd graphql_inspector
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the application:
   ```bash
   uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```

### Docker (Recommended)

1. Navigate to the project directory:
   ```bash
   cd graphql_inspector
   ```
2. Build and start the container using Docker Compose:
   ```bash
   docker-compose up --build -d
   ```
3. Access the Web UI at `http://localhost:8000`.

## Usage Examples

### Using the API

You can programmatically analyze an endpoint using the `/api/analyze` route.

**Request:**
```bash
curl -X POST http://localhost:8000/api/analyze \
     -H "Content-Type: application/json" \
     -d '{"url": "https://api.example.com/graphql", "headers": {"Authorization": "Bearer TOKEN"}}'
```

**Response:**
```json
{
  "url": "https://api.example.com/graphql",
  "introspection_enabled": true,
  "sensitive_fields": [
    "User.password",
    "Account.api_key"
  ],
  "mutations": [
    "createUser",
    "deleteAccount"
  ],
  "severity": "Critical",
  "error": null
}
```

## Security Considerations & Limitations
- **SSRF Risk**: The tool makes outward HTTP requests to user-supplied URLs. In a production deployment, ensure the Docker container is deployed in an isolated network segment (e.g., VPC without access to internal metadata services) to prevent Server-Side Request Forgery attacks.
- **Rate Limiting**: The current implementation does not limit outbound requests. Ensure it is placed behind an API gateway with rate limiting to prevent abuse.
- **Keyword Variations**: The sensitive field detection relies on keyword matching. Highly obfuscated or non-standard naming conventions for sensitive data might be missed.

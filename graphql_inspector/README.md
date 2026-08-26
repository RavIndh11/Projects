# GraphQL Inspector

GraphQL Inspector is a Defensive Security tool designed to analyze and defend against common GraphQL attacks. It acts as an inspection layer that evaluates incoming GraphQL queries for potential vulnerabilities before they reach your main application.

## Overview & Problem Statement

GraphQL APIs are incredibly flexible, which makes them powerful but also susceptible to specific types of attacks:
-   **Denial of Service (DoS):** Attackers can craft deeply nested queries or use excessive aliasing to overwhelm the server's resources.
-   **Information Disclosure:** Introspection queries (`__schema`, `__type`) can expose the entire API schema to attackers, giving them a roadmap of your data structure.

This tool solves these problems by providing a lightweight, fast inspection engine that parses queries and identifies these risks based on configurable thresholds.

## Architecture

The system consists of:
1.  **FastAPI Backend:** Provides a REST API (`/api/inspect` and `/api/inspect/batch`) for integration into API Gateways, WAFs, or SIEM pipelines.
2.  **GraphQLInspector Logic:** A Python class that analyzes query strings for depth, aliases, and introspection patterns using regex and token parsing.
3.  **Web Dashboard:** A Tailwind-styled UI for manual SOC analysis and testing of queries.

```text
[ Client/Attacker ] -> (GraphQL Query) -> [ GraphQL Inspector (FastAPI) ]
                                                |-- Analyzes Depth
                                                |-- Analyzes Aliases
                                                |-- Detects Introspection
                                                `-> Returns InspectionResult (Safe/Vulnerable)
```

## Features & Capabilities

-   **Introspection Detection:** Flags `__schema` and `__type` queries.
-   **Nesting Depth Analysis:** Calculates the depth of the query to prevent CPU/memory exhaustion.
-   **Alias Counting:** Estimates the number of aliases to prevent batching attacks.
-   **Batch Processing:** Supports analyzing multiple queries in a single request.
-   **Structured JSON Logging:** Outputs logs in a format easily consumable by SIEMs (like Splunk or ELK).
-   **Containerized & Hardened:** Runs as a non-root user in a lightweight Docker container.

## Installation & Setup

### Native (Python)

```bash
cd graphql_inspector
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### Docker (Recommended)

```bash
cd graphql_inspector
docker compose up --build -d
```

The service will be available at `http://localhost:8000`.

## Usage Examples

### 1. Web Dashboard
Navigate to `http://localhost:8000/` in your browser to use the interactive dashboard.

### 2. API Request (Single Query)

```bash
curl -X POST "http://localhost:8000/api/inspect" \
     -H "Content-Type: application/json" \
     -d '{"query": "{ __schema { types { name } } }"}'
```

**Response:**
```json
{
  "is_safe": false,
  "findings": [
    "Introspection query detected"
  ],
  "metrics": {
    "depth": 3,
    "aliases": 0,
    "has_introspection": true
  }
}
```

## Security Considerations & Limitations

-   **Regex Limitations:** The current implementation uses regex and basic parsing for speed and simplicity. While effective for common patterns, advanced obfuscation might bypass these checks. In a production environment, integrating a full GraphQL AST parser (like `graphql-core`) would be more robust.
-   **No Authentication:** The API currently does not require authentication. It is intended to be run in an internal network or protected by an API Gateway.
-   **Hardcoded Thresholds:** The maximum depth (5) and maximum aliases (10) are currently set during initialization. These should ideally be configurable via environment variables in future iterations.
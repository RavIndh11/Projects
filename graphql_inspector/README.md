# GraphQL Inspector

## Overview & Problem Statement
GraphQL endpoints are frequently targeted by attackers due to the powerful querying capabilities they offer. If improperly secured, an attacker can launch Denial of Service (DoS) attacks by crafting deeply nested queries or using excessive aliases. Furthermore, information disclosure can occur if introspection queries are left enabled in production.

**GraphQL Inspector** is a defensive security tool designed to identify potentially malicious GraphQL queries before they hit the server. It parses the incoming query into an Abstract Syntax Tree (AST) and traverses it to identify security violations without needing to execute the query.

## Architecture
1. **Client / API Gateway**: Forwards the raw GraphQL query to the Inspector.
2. **GraphQL Inspector API**: A FastAPI application that receives the query.
3. **AST Parser & Security Visitor**: Converts the query to an AST using `graphql-core`. A custom `Visitor` traverses the AST checking for:
   - Deep query nesting.
   - Excessive aliases.
   - Unauthorized introspection queries.
4. **Log Sink / SIEM**: The application outputs structured JSON logs for tracking malicious attempts.
5. **Response**: Returns a validation result with a list of violations (if any).

## Features
- **Deep Nesting Detection**: Prevent DoS by restricting maximum query depth.
- **Alias Limiting**: Prevent batching attacks and DoS by limiting the number of aliases in a single query.
- **Introspection Blocking**: Detect and block `__schema`, `__type`, and `__typename` queries to prevent information disclosure.
- **Web UI**: A built-in Tailwind UI for testing queries and visualizing results.
- **Structured Logging**: Outputs logs in JSON format for easy ingestion by SIEMs (e.g., Elasticsearch, Splunk).
- **Secure by Default**: Containerized running as a non-root user.

## Installation & Setup

### Native Execution

1. Navigate to the project directory:
   ```bash
   cd graphql_inspector
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```

4. Access the UI at `http://127.0.0.1:8000/`.

### Docker Execution

1. Create a `.env` file from the example:
   ```bash
   cp .env.example .env
   ```

2. Build and start the container:
   ```bash
   docker-compose up --build -d
   ```

3. Access the UI at `http://localhost:8000/`.

## Usage Examples

### API Request

```bash
curl -X POST "http://localhost:8000/api/inspect" \
     -H "Content-Type: application/json" \
     -d '{
           "query": "{ users { friends { friends { id } } } }",
           "max_depth": 2,
           "max_aliases": 3,
           "allow_introspection": false
         }'
```

### Example Response (Violation)

```json
{
  "is_valid": false,
  "violations": [
    {
      "issue_type": "Max Depth Exceeded",
      "message": "Query depth exceeds maximum allowed depth of 2",
      "severity": "High"
    }
  ],
  "error": null
}
```

## Security Considerations & Limitations
- **Query Complexity**: This tool currently checks raw depth and aliases. It does not calculate precise query cost/complexity based on schema types.
- **Fragment Spreads**: Complex circular fragment definitions might bypass simple depth checks if not fully evaluated. This implementation provides a baseline defense against obvious payloads.
- **Deployment**: This tool is designed to run behind a gateway or WAF as an additional defensive layer, or directly integrated into application middleware.

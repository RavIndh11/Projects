# AI Agent Policy Guard

A defensive security proxy that evaluates AI Agent tool execution requests against predefined YAML policies. This tool acts as a guardrail, preventing unauthorized or unsafe actions by AI agents by validating their tool requests in real-time.

## Architecture

1. **AI Agent**: Initiates a tool execution request.
2. **Policy Guard**: Intercepts the request via the `/evaluate` endpoint.
3. **Policy Engine**: Loads YAML policies and evaluates the request against:
   - Allowed / Denied Tools.
   - Required Arguments.
   - Argument Constraints (Regex matching).
4. **Dashboard**: A web UI that displays real-time execution logs and evaluation results.
5. **Logger**: Outputs structured JSON logs for SIEM integration.

## Features

- **YAML-Based Policies**: Define granular access controls per agent ID.
- **Regex Constraints**: Validate tool arguments against regex patterns to prevent unsafe inputs (e.g., path traversal).
- **Web Dashboard**: Monitor agent activity and policy evaluations in real-time.
- **Structured Logging**: JSON-formatted logs ready for SIEM ingestion.

## Setup & Installation

### Option 1: Docker (Recommended)

1. Clone the repository and navigate to the `ai_agent_policy_guard` directory.
2. Create environment variables:
   ```bash
   cp .env.example .env
   ```
3. Build and run with Docker Compose:
   ```bash
   docker compose up --build -d
   ```

### Option 2: Native Setup

1. Create a virtual environment and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
2. Start the FastAPI server:
   ```bash
   uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```

## Usage Examples

### 1. Define a Policy

Create a policy file in the `policies/` directory (e.g., `policies/agent-123.yaml`):

```yaml
agent_id: "agent-123"
denied_tools:
  - "delete_database"
allowed_tools:
  read_file:
    required_args:
      - "filepath"
    arg_constraints:
      filepath: "^/app/data/.*\\.txt$"
```

### 2. Evaluate a Request

Send a request to the `/evaluate` endpoint:

```bash
curl -X POST http://localhost:8000/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent-123",
    "tool_name": "read_file",
    "arguments": {
      "filepath": "/app/data/test.txt"
    }
  }'
```

**Expected Response (Allowed):**
```json
{
  "allowed": true,
  "reason": "All policy checks passed.",
  "matched_rule": "allow"
}
```

**Expected Response (Denied due to constraint):**
```bash
curl -X POST http://localhost:8000/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent-123",
    "tool_name": "read_file",
    "arguments": {
      "filepath": "/etc/passwd"
    }
  }'
```

```json
{
  "allowed": false,
  "reason": "Argument 'filepath' does not match constraint '^/app/data/.*\\.txt$'",
  "matched_rule": "constraint_filepath"
}
```

## Security Considerations

- **Principle of Least Privilege**: Ensure policies grant the minimum necessary permissions to each agent.
- **Input Sanitization**: Regular expressions should be carefully constructed to prevent bypasses.
- **Log Monitoring**: Integrate JSON logs with a SIEM for anomaly detection.

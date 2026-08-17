# AI Agent Policy Guard

## Overview & Problem Statement
As autonomous AI agents become more prevalent, they are frequently granted access to powerful tools like shell execution, file system access, and database querying. If an agent hallucinates, is manipulated via prompt injection, or acts maliciously, these tools can be misused, leading to severe security breaches (e.g., executing destructive commands or exfiltrating sensitive data).

**AI Agent Policy Guard** is a lightweight, defensive security proxy that sits between an AI agent and its tool execution environment. It acts as a strict, rule-based gatekeeper, evaluating every requested tool action against a defined YAML policy before allowing execution.

## Features
- **Strict Policy Enforcement**: Define granular allowed/denied tools and parameter constraints using exact matches or Regex patterns.
- **RESTful Evaluation API**: A fast, JSON-based API endpoint for agents to request tool execution permission.
- **SOC Web Dashboard**: A lightweight, Tailwind CSS-styled UI for analysts to manually test payloads, view the active policy, and monitor live evaluation logs.
- **Structured JSON Logging**: Logs all evaluations (allowed and blocked) in structured JSON format for seamless ingestion into SIEMs or log collectors.
- **Hot-Reloading Policies**: Update the security policy on the fly without restarting the service.
- **Secure Containerization**: Production-ready Docker setup running as a non-root user with read-only volume mounts.

## Architecture
```text
[ AI Agent ]
     |
     | (1. Request to execute tool: e.g., shell_execute 'ls -la')
     v
[ AI Agent Policy Guard (FastAPI Proxy) ]
     |
     | (2. Evaluate against policies/default.yaml)
     |
     +--> [ JSON Logs -> SIEM ]
     |
     | (3. Return Allow/Deny Decision)
     v
[ Tool Execution Engine / Host ] (Only executes if Allowed)
```

## Installation & Setup

### Option 1: Docker (Recommended)
1. Clone the repository and navigate to the project directory:
   ```bash
   cd ai_agent_policy_guard
   ```
2. Build and run using Docker Compose:
   ```bash
   docker compose up --build -d
   ```
3. Access the SOC Dashboard at: `http://localhost:8000`

### Option 2: Native Setup (Python 3.11+)
1. Create a virtual environment and install dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
2. Set the required environment variables (optional, defaults are provided):
   ```bash
   export API_KEY="your_secure_api_key_here"
   export POLICY_PATH="policies/default.yaml"
   ```
3. Run the FastAPI application:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

## Usage Examples

### Web Dashboard
Navigate to `http://localhost:8000/` in your browser. Enter the API Key (`dev_api_key` by default). You can manually test payloads, such as:
- **Allowed**: Tool `shell_execute`, Parameters `{"command": "ls -la"}`
- **Blocked**: Tool `shell_execute`, Parameters `{"command": "rm -rf /"}`

### API Request
```bash
curl -X POST http://localhost:8000/api/v1/evaluate \
     -H "Content-Type: application/json" \
     -H "X-API-Key: dev_api_key" \
     -d '{
           "tool_name": "shell_execute",
           "agent_id": "test-agent-01",
           "parameters": {"command": "cat /etc/shadow"},
           "reasoning": "Need to read user hashes"
         }'
```

### API Response (Denied Example)
```json
{
  "allowed": false,
  "reason": "Value 'cat /etc/shadow' for 'command' matched a deny pattern",
  "matched_rule": "prevent_path_traversal"
}
```

## Security Considerations & Limitations
- **Regex Complexity**: Poorly written regular expressions in the policy file could lead to bypasses or ReDoS (Regular Expression Denial of Service) attacks. Keep regex patterns concise and test them thoroughly.
- **Defense in Depth**: This tool enforces policy *before* execution. It does not replace the need for a secure, sandboxed execution environment (e.g., running tools inside unprivileged containers).
- **Future Improvements**:
  - Implement Rate Limiting to prevent brute-force policy discovery by rogue agents.
  - Add support for fetching policies from remote stores (e.g., AWS S3, HashiCorp Vault).

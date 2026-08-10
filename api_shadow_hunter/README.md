# API Shadow Hunter

## Project Overview
API Shadow Hunter is a defensive security tool designed for SOC analysts, Application Security engineers, and Detection engineers. It ingests an application's OpenAPI (Swagger) specification and correlates it against real-world API access logs to identify undocumented endpoints and unused (zombie) APIs.

## Problem Statement
Modern microservices architectures expose hundreds of API endpoints. Often, legacy endpoints, debug routes, or experimental features are pushed to production without being documented in the official OpenAPI specification. These undocumented routes are known as **Shadow APIs** and are frequently targeted by attackers because they lack proper authentication or validation. Similarly, **Zombie APIs** are documented endpoints that are no longer used, increasing the attack surface. API Shadow Hunter bridges the gap between what is documented and what is actually being accessed.

## Features
- **Shadow API Detection**: Flags API paths that exist in access logs but are missing from the OpenAPI specification.
- **Zombie API Detection**: Identifies endpoints that are documented but have zero hits in the logs.
- **Severity Scoring**: Automatically assigns risk severity (Low, Medium, High, Critical) to Shadow APIs based on path heuristics (e.g., `/admin`, `/debug`, `/config`).
- **Path Param Regex Matching**: Intelligently converts OpenAPI path parameters (e.g., `/users/{id}`) into regex patterns to correctly match dynamic log entries (e.g., `/users/123`).
- **Interactive Dashboard**: A clean, Tailwind CSS-powered Web UI for uploading files and analyzing traffic.
- **Containerized**: Production-ready Docker setup with a non-root user.

## Architecture
1. **Input Stage**: The user uploads an OpenAPI specification (YAML/JSON) and a text file containing API access logs.
2. **Parsing Engine**:
   - `analyzer.py` parses the OpenAPI spec to extract documented endpoints and their supported HTTP methods.
   - It converts RESTful path parameters into regular expressions.
3. **Correlation Engine**: The access logs are parsed and matched against the documented paths. Unmatched routes are flagged as Shadow, while unmatched documented routes are flagged as Zombie.
4. **Presentation**: Results are rendered via a FastAPI backend using Jinja2 templates for the dashboard UI.

## Installation Instructions

### Native Execution (Python)
1. Ensure Python 3.11+ is installed.
2. Clone the repository and navigate to the project directory:
   ```bash
   git clone <repo_url>
   cd api_shadow_hunter
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the FastAPI development server:
   ```bash
   uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
   ```

### Docker Execution
1. Ensure Docker and Docker Compose are installed.
2. Build and start the container:
   ```bash
   docker-compose up --build
   ```
3. The dashboard will be available at `http://localhost:8000`.

## Usage Examples

1. Access the web interface at `http://localhost:8000`.
2. Prepare an `openapi.yaml` file and an access log file `logs.txt`.
3. Example Log Format (`logs.txt`):
   ```text
   GET /api/v1/users
   POST /api/v1/users
   GET /api/v1/users/123
   GET /admin/config
   POST /shell
   ```
4. Upload both files through the UI and click "Analyze Traffic".
5. The dashboard will categorize the traffic, highlighting `/admin/config` and `/shell` as Critical Shadow APIs.

## Security Considerations
- **Non-Root Container**: The Docker image is configured to run the application as `appuser` (UID 10001) to prevent container escape privilege escalation.
- **No Secrets**: No hardcoded API keys or secrets are used or required by this application.
- **Input Validation**: The application leverages `Pydantic` models and safe YAML loading (`yaml.safe_load`) to prevent malicious payload execution or XML External Entity (XXE) style attacks in the uploaded specifications.

## Limitations
- Currently relies on a simplified log format (`METHOD /path`). Real-world integration may require extending `parse_logs` to support JSON-formatted logs from Nginx or AWS API Gateway.
- Severity scoring is based on basic string matching heuristics and could be expanded to use machine learning or more complex rule sets.

## Future Improvements
- **SIEM Integration**: Add endpoints to export the analysis report as structured JSON for ingestion into Splunk, ELK, or Datadog.
- **Continuous Monitoring**: Shift from a file-upload model to a webhook or agent-based model for real-time log ingestion and alerting.
- **Authentication**: Add JWT or basic authentication to secure the dashboard.
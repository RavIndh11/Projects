# GraphQL Inspector

GraphQL Inspector is a defensive security tool designed to automate the discovery of exposed GraphQL introspection and sensitive schema fields.

## Overview & Problem Statement

Many organizations deploy GraphQL APIs without disabling introspection, which allows anyone to query the API for its full schema. While useful for development, exposing the schema in production gives attackers a complete map of the API's capabilities, including hidden mutations and sensitive fields (e.g., `password`, `ssn`, `token`).

GraphQL Inspector solves this workflow gap by providing an automated, easy-to-use scanner that:
1. Queries the target endpoint to check if introspection is enabled.
2. Analyzes the returned schema for fields with sensitive names.
3. Provides a clean, SOC-friendly web UI for quick analysis and reporting.

## Architecture

1.  **FastAPI Backend (`app/main.py`)**: Handles API requests, coordinates scanning, and serves the UI.
2.  **Core Scanner (`app/scanner.py`)**: Executes the GraphQL introspection query using `httpx`, parses the JSON response, and applies heuristics to identify sensitive fields.
3.  **Pydantic Models (`app/models.py`)**: Ensures strict input validation (e.g., URL validation) and structures the output.
4.  **Web UI (`app/templates/index.html`)**: A lightweight HTML/Tailwind CSS dashboard for initiating scans and viewing results.
5.  **Docker Orchestration**: Containerized for easy deployment, running securely as a non-root user.

## Features & Capabilities

*   **Automated Introspection Detection**: Quickly verifies if a GraphQL endpoint is exposing its schema.
*   **Sensitive Field Flagging**: Automatically flags fields containing keywords like `password`, `token`, `secret`, `ssn`, etc.
*   **Structured Logging**: Outputs logs in JSON format for easy ingestion into SIEMs/Logstash.
*   **Secure by Default**: Containerized with least privilege (non-root user), strict input validation, and secure Docker practices.

## Installation & Setup

### Option 1: Native Execution (Local Development)

1.  **Clone the repository and navigate to the project directory:**
    ```bash
    cd graphql_inspector
    ```

2.  **Create a virtual environment and install dependencies:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    pip install -r requirements.txt
    ```

3.  **Run the application:**
    ```bash
    uvicorn app.main:app --host 127.0.0.1 --port 8000
    ```

4.  **Access the application:**
    Open your browser and go to `http://127.0.0.1:8000`.

### Option 2: Docker Deployment (Recommended)

1.  **Navigate to the project directory:**
    ```bash
    cd graphql_inspector
    ```

2.  **Copy the environment file:**
    ```bash
    cp .env.example .env
    ```

3.  **Build and start the container:**
    ```bash
    docker compose up --build -d
    ```

4.  **Access the application:**
    Open your browser and go to `http://localhost:8000`.

## Usage Examples

### Web UI
Navigate to the root URL (e.g., `http://localhost:8000`), enter the target GraphQL endpoint URL (e.g., `https://api.example.com/graphql`), and click "Scan Endpoint".

### API Request
You can also trigger a scan via the API:
```bash
curl -X POST http://localhost:8000/scan \
     -H "Content-Type: application/json" \
     -d '{"url": "https://api.example.com/graphql"}'
```

## Security Considerations & Limitations

*   **Threat Model Assumptions**: This tool is designed for authorized security testing and defensive analysis. It assumes the user has permission to scan the target endpoints.
*   **False Positives/Negatives**: The sensitive field detection relies on keyword matching. It may flag benign fields (false positives) or miss sensitive fields with non-standard names (false negatives).
*   **Introspection vs. Actual Vulnerability**: Exposing introspection is a significant information disclosure risk, but it is not inherently an exploit. It maps the attack surface for further investigation.
*   **Future Improvements**:
    *   Add support for authenticated scans (passing headers/tokens).
    *   Implement deeper schema analysis for complex vulnerability patterns (e.g., detecting missing authorization on mutations).
    *   Integrate with CI/CD pipelines to block deployments if introspection is accidentally enabled.

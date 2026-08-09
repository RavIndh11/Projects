# API Shadow Hunter

**API Shadow Hunter** is a defensive security tool designed for Security Operations Center (SOC) analysts and Detection Engineers. It ingests OpenAPI specifications and web server access logs to automatically detect two significant API security risks:

1.  **Shadow APIs**: Endpoints that are actively receiving traffic (found in logs) but are not documented or managed (missing in OpenAPI specs). These pose a high risk of unauthenticated access, data leaks, or unpatched vulnerabilities.
2.  **Zombie APIs**: Endpoints that are documented and expected (found in OpenAPI specs) but are never accessed (missing in logs). These often represent deprecated code, forgotten features, or technical debt that increases the attack surface.

## Features & Capabilities

*   **OpenAPI Spec Parsing:** Supports ingestion of YAML or JSON OpenAPI specifications to build a baseline of expected API behavior.
*   **Access Log Analysis:** Parses standard web server access logs (e.g., Nginx, Apache) to determine actual API usage.
*   **Intelligent Path Matching:** Converts OpenAPI path templates (e.g., `/api/users/{id}`) into regular expressions for accurate matching against raw log paths (e.g., `/api/users/123`).
*   **Interactive SOC Dashboard:** A lightweight, Tailwind CSS-powered FastAPI dashboard for uploading data and visualizing Shadow and Zombie APIs with severity badges.
*   **Structured Logging:** Emits JSON-formatted logs suitable for aggregation into SIEMs (e.g., Splunk, ELK).

## Architecture

1.  **User/Analyst** uploads an OpenAPI Spec and Access Logs via the Web Dashboard or API.
2.  **Analyzer Engine** parses both inputs.
3.  **Path Matching Logic** correlates actual traffic against expected endpoints.
4.  **Results** are categorized and presented in the Web Dashboard.

## Setup & Installation

### Native Python Execution

1.  Navigate to the project directory:
    ```bash
    cd api_shadow_hunter
    ```
2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3.  Run the FastAPI application:
    ```bash
    uvicorn app.main:app --host 127.0.0.1 --port 8000
    ```
4.  Access the dashboard at `http://127.0.0.1:8000/dashboard`.

### Docker Deployment (Recommended)

1.  Ensure Docker and docker-compose are installed.
2.  Navigate to the project directory:
    ```bash
    cd api_shadow_hunter
    ```
3.  Build and start the container:
    ```bash
    docker-compose up --build -d
    ```
4.  Access the dashboard at `http://127.0.0.1:8000/dashboard`.

## Usage Example

1.  Prepare an OpenAPI spec (`spec.yaml`).
2.  Prepare an access log (`access.log`).
3.  Open the web dashboard, upload `spec.yaml` using the first form, and upload `access.log` using the second form.
4.  Review the detected Shadow and Zombie APIs on the dashboard.

## Security Considerations & Limitations

*   **Threat Model:** This tool is designed for offline or out-of-band analysis of logs and specs. It assumes the uploaded files are trustworthy.
*   **In-Memory Storage:** For demonstration purposes, this tool stores state in memory. In a production environment, results should be stored in a persistent database or cache (e.g., PostgreSQL, Redis).
*   **Log Parsing Complexity:** The current log parser uses a generalized regex. Highly customized or unusual log formats may require adjustments to the parsing logic in `app/analyzer.py`.
*   **REST Focus:** The tool is optimized for RESTful APIs and OpenAPI specifications. It may not fully support GraphQL or gRPC analysis without modification.

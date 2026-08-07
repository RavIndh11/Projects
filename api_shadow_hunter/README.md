# API Shadow Hunter

**API Shadow Hunter** is a defensive security tool designed to detect undocumented (Shadow) and unused (Zombie) APIs. It compares OpenAPI specifications against actual access logs to identify critical visibility gaps that attackers might exploit.

## Overview & Problem Statement

Organizations often struggle with API sprawl. Documented APIs might not match what is actually deployed and consumed. This leads to two significant security risks:
1.  **Shadow APIs**: Endpoints that are deployed and active, but undocumented. They often lack security reviews, authentication, or rate limiting (e.g., forgotten debug endpoints, hidden administrative functions).
2.  **Zombie APIs**: Endpoints that are documented but no longer actively used by valid clients. They expand the attack surface unnecessarily and should be deprecated and removed.

API Shadow Hunter automates the discovery of these endpoints by analyzing access logs and comparing them to expected OpenAPI specifications.

## Architecture

The tool consists of three main components:
1.  **Parsers**:
    *   `SpecParser`: Parses OpenAPI specifications (YAML or JSON) and extracts all defined endpoints and HTTP methods.
    *   `LogParser`: Parses access logs (JSON structured or combined text formats) to extract accessed endpoints, normalizing IDs or UUIDs in paths.
2.  **Analyzer**: Compares the two sets to identify differences, outputting Shadow and Zombie endpoints.
3.  **FastAPI Web Interface**: A modern, lightweight Web UI (Tailwind CSS) to upload files and visualize the results with severity badges.

## Features & Capabilities

*   **OpenAPI Support**: Parses standard OpenAPI/Swagger files in YAML or JSON format.
*   **Flexible Log Parsing**: Understands structured JSON logs and standard web server access logs.
*   **Heuristic Normalization**: Automatically normalizes dynamic paths in logs (e.g., `/users/123` -> `/users/{param}`).
*   **Web Dashboard**: Intuitive interface for SOC analysts to quickly identify critical gaps.
*   **Secure by Default**: Containerized running as a non-root user.

## Installation & Setup

### Native Execution

1.  Navigate to the project directory: `cd api_shadow_hunter`
2.  Install dependencies: `pip install -r requirements.txt`
3.  Run the server: `uvicorn main:app --host 127.0.0.1 --port 8000`
4.  Open `http://127.0.0.1:8000` in your browser.

### Docker (Recommended)

1.  Copy `.env.example` to `.env`: `cp .env.example .env`
2.  Build and run using Docker Compose: `docker-compose up --build`
3.  Access the web interface at `http://localhost:8000`.

## Security Considerations & Limitations

*   **Log Completeness**: The tool is only as good as the access logs provided. If traffic bypasses the logging mechanism, Shadow APIs will not be detected.
*   **Path Normalization Limits**: The heuristic path normalization handles standard UUIDs and integers. Highly custom or complex path parameters might not be normalized perfectly and could produce false positives.
*   **No Active Scanning**: This is a passive analysis tool; it does not actively scan or fuzz the target infrastructure.

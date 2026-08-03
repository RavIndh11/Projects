# CloudTrail Hunter

**CloudTrail Hunter** is a lightweight, FastAPI-based web application designed for Security Operations Center (SOC) analysts to quickly parse, analyze, and visualize AWS CloudTrail logs for malicious activity.

## Overview & Problem Statement

AWS CloudTrail logs are critical for investigating security incidents in cloud environments, but analyzing raw JSON files manually is tedious and error-prone. While SIEMs provide comprehensive capabilities, they can be slow to query or complex to set up for ad-hoc analysis during an active incident.

CloudTrail Hunter solves this by providing a local, fast, and easy-to-use web interface to identify high-risk behaviors such as Defense Evasion (e.g., stopping logging) and Privilege Escalation (e.g., unauthorized policy modifications).

## Architecture

1. **Frontend**: A simple, responsive web interface built with HTML and Tailwind CSS.
2. **Backend**: A FastAPI application that handles file uploads and coordinates analysis.
3. **Data Validation**: Pydantic models strictly validate the uploaded JSON structure to prevent malformed data from causing errors.
4. **Analysis Engine**: A core Python module (`analyzer.py`) that applies deterministic rules to detect known malicious AWS API calls.
5. **Logging**: Findings are printed to `stdout` in structured JSON format, making it easy to forward logs to a central collector if deployed in a larger pipeline.

## Features

- **Fast Log Parsing**: Quickly ingest standard AWS CloudTrail JSON files.
- **Threat Detection**: Pre-configured rules for detecting:
  - Defense Evasion (`StopLogging`, `DeleteTrail`, etc.)
  - Privilege Escalation (`PutUserPolicy`, `CreateAccessKey`, etc.)
  - Risky Root Account Usage
- **SOC Dashboard**: Visual severity badges (Critical, High, Medium, Low) for immediate triage.
- **Secure File Handling**: Validates inputs using Pydantic before processing.
- **Containerized**: Production-ready Docker setup running as a non-root user.

## Installation & Setup

### Option 1: Native Execution (Python 3.11+)

1. Clone the repository and navigate to the directory:
   ```bash
   cd cloudtrail_hunter
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the application:
   ```bash
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```
5. Access the UI at `http://localhost:8000`.

### Option 2: Docker Deployment

1. Build and run using Docker Compose:
   ```bash
   cd cloudtrail_hunter
   docker compose up --build
   ```
2. Access the UI at `http://localhost:8000`.

## Usage Examples

1. Open your browser to `http://localhost:8000`.
2. Click "Choose File" and select an AWS CloudTrail `.json` file.
3. Click "Analyze Logs".
4. Review the generated threat report on the dashboard.

## Security Considerations & Limitations

- **Log Tampering**: The tool assumes the integrity of the uploaded CloudTrail logs. If an attacker has tampered with the logs prior to analysis, the results may be inaccurate.
- **False Positives**: The rule set is deterministic. Legitimate administrative actions (like an authorized admin deleting a test trail) will be flagged and require human context.
- **File Size Limitations**: The current implementation reads the entire file into memory. Extremely large CloudTrail files may cause out-of-memory errors.

## Future Improvements

- Streaming JSON parsing for handling multi-gigabyte log files.
- Support for uploading `.json.gz` files directly (common in S3 buckets).
- Integration with AWS Athena for direct querying rather than manual upload.
- Expanding the detection logic to include IAM persistence and data exfiltration patterns.

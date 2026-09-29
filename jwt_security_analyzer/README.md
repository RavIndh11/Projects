# JWT Security Analyzer

## Overview
JWT Security Analyzer is a Defensive Security tool designed for SOC analysts, security engineers, and developers. It statically analyzes JSON Web Tokens (JWT) to identify common vulnerabilities, misconfigurations, and sensitive data leaks without requiring the backend server's validation logic.

## Problem Statement
Many applications misconfigure JWTs, leading to critical vulnerabilities such as the `alg: none` bypass, using symmetric algorithms with weak shared secrets, missing expiration dates, or leaking PII within the Base64-encoded payload. This tool automates the detection of these flaws.

## Architecture
- **Backend**: FastAPI (Python 3.11) delivering a REST API.
- **Analysis Engine**: A modular engine parsing headers/payloads, and actively attempting brute-force attacks against symmetric signatures using common weak secrets.
- **Frontend**: A lightweight, responsive web interface built with HTML/Tailwind CSS.

## Features
- **Algorithm Analysis**: Detects `alg: none` bypasses and flags the usage of symmetric algorithms (e.g., HS256).
- **Brute-Force Engine**: Automatically attempts to brute-force symmetric signatures using a dictionary of weak secrets.
- **Payload Inspection**: Flags tokens missing expiration (`exp`) or containing potentially sensitive keys (e.g., `password`, `ssn`).
- **Structured Logging**: Outputs findings in a JSON format suitable for SIEM ingestion.
- **Containerized**: Hardened Docker implementation running as a non-root user.

## Installation & Setup

### Using Docker (Recommended)
1. Clone the repository and navigate to `jwt_security_analyzer`:
   ```bash
   cd jwt_security_analyzer
   ```
2. Build and run the container:
   ```bash
   docker compose up --build
   ```
3. Access the dashboard at [http://localhost:8000](http://localhost:8000).

### Local Development
1. Create a virtual environment and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
2. Start the FastAPI server:
   ```bash
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

## Security Considerations
- **Offline Tool**: This tool does not interact with the application that generated the JWT. It performs static analysis.
- **Dictionary Size**: The built-in dictionary for brute-forcing is minimal for demonstration purposes. In a production scenario, it should be supplemented with robust lists (e.g., rockyou.txt).
- **Sensitive Data**: Ensure you are not submitting highly sensitive production JWTs to unauthorized hosted instances of this tool. Run it locally or on a trusted internal network.

# Docker Socket Guard

## Project Overview

Docker Socket Guard is a FastAPI-based security proxy for the Docker Unix socket (`/var/run/docker.sock`). It provides granular access control and payload inspection to prevent common container-escape and privilege-escalation attacks when the Docker socket needs to be exposed to CI/CD pipelines, monitoring agents, or other services.

## Problem Statement

Exposing the Docker socket natively provides the client with `root`-equivalent privileges on the host system. A malicious actor with access to the socket can easily escalate privileges by creating a privileged container or mounting the host filesystem. Docker Socket Guard acts as a secure intermediary, inspecting traffic and enforcing restrictive rules on container creation.

## Features

- **Payload Inspection:** Inspects POST requests to `/containers/create` and blocks:
  - Privileged containers (`Privileged: true`).
  - Dangerous host mounts (e.g., `/`, `/etc`, `/var/run/docker.sock`).
  - Host namespace sharing (`PidMode`, `NetworkMode`, etc.).
  - Adding dangerous Linux capabilities (`CapAdd`).
- **Read-Only Mode:** Can be configured to strictly deny any state-modifying requests (`POST`, `DELETE`, etc.), allowing only read-only monitoring.
- **SIEM-Ready Logging:** Outputs strictly structured JSON logs detailing allowed/blocked actions, perfect for ingestion into SOC logging pipelines.
- **Asynchronous Proxying:** Supports long-lived streaming connections (like `docker logs -f` and `docker events`) via asynchronous `httpx` and `FastAPI StreamingResponse`.

## Architecture

```text
[ Docker Client / CI Agent ]
          │ (HTTP over TCP/Socket)
          ▼
┌──────────────────────────┐
│   Docker Socket Guard    │
│  (FastAPI + Uvicorn)     │
│                          │
│ 1. Request Interception  │
│ 2. Read-Only check       │
│ 3. Payload validation    │
│ 4. JSON Logging          │
└─────────┬────────────────┘
          │ (HTTP over UNIX Socket)
          ▼
 [ /var/run/docker.sock ]
```

## Installation & Setup

### Requirements
- Docker and Docker Compose
- Python 3.11+ (if running natively)

### Docker Deployment (Recommended)

1. **Clone the repository and configure environment variables:**
   ```bash
   cp .env.example .env
   ```

2. **Start the proxy using Docker Compose:**
   ```bash
   docker compose up -d --build
   ```
   The proxy will be exposed on port `8000`.

*(Note: The `docker-compose.yml` runs the container as root by default simply to ensure access to `/var/run/docker.sock`. In production, you should adjust the socket group permissions and run the container as the non-root `appuser`).*

### Native Installation

1. **Install dependencies:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Run the application:**
   ```bash
   uvicorn src.main:app --host 127.0.0.1 --port 8000
   ```

## Usage Examples

Configure your Docker client to connect through the proxy instead of the local socket:

```bash
export DOCKER_HOST=tcp://127.0.0.1:8000
```

**1. Normal operation (Allowed)**
```bash
docker run -d nginx:latest
```

**2. Blocked: Privileged Container**
```bash
docker run --privileged -d ubuntu
# Expected Response:
# Error response from daemon: Creating privileged containers is forbidden.
```

**3. Blocked: Dangerous Volume Mount**
```bash
docker run -v /:/host_root -d ubuntu
# Expected Response:
# Error response from daemon: Mounting dangerous host paths (/) is forbidden.
```

## Security Considerations & Limitations

- **Bypass Risk:** The current implementation strictly intercepts `/containers/create`. Advanced API misuse via other undocumented or novel endpoints might bypass these checks. It is highly recommended to combine this with `READ_ONLY_MODE=true` if only monitoring is required.
- **Performance:** As a Layer 7 HTTP proxy, it introduces minor latency. Large image pulls or extensive log streaming are proxied in chunks but still pass through the FastAPI application layer.
- **Threat Model Assumption:** It assumes the host Docker daemon is secure. The proxy protects against a malicious or compromised *client* using the socket.

## Future Improvements
- Implement rate limiting to prevent DoS attacks against the Docker API.
- Support TLS client certificate authentication (mTLS) on the proxy listener.
- Expand payload validation to include inspection of image registries (e.g., blocking images not from trusted registries).

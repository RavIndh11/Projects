## 2026-08-09 - Docker Healthcheck Dependency Missing

**Vulnerability:** A Dockerfile configured a `HEALTHCHECK` using `curl` but used a base image (`python:3.11-slim`) that does not include the `curl` binary by default.

**Learning:** This results in a consistently failing health check in orchestration environments, marking the container as unhealthy despite the application running correctly.

**Prevention:** When defining a `HEALTHCHECK` that relies on external binaries like `curl` or `wget`, ensure they are explicitly installed via the package manager (e.g., `apt-get install -y curl`) or use a native alternative (like a Python `urllib` one-liner).

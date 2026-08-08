## 2024-05-24 - Weak Hashing in YARA Generator
**Vulnerability:** Weak MD5 and SHA1 hashes used without indicating they were not used for security purposes.
**Learning:** Tools like Bandit will flag `hashlib.md5()` and `hashlib.sha1()` by default as insecure crypto, breaking automated security pipelines or FIPS compliance.
**Prevention:** Always use `usedforsecurity=False` when using weak hashes for non-cryptographic purposes (like file identification/checksums).
## 2024-05-24 - Hardcoded API Key Fallback in docker-compose.yml
**Vulnerability:** A hardcoded default API key (`default-dev-key`) was present in both `app/main.py` and `docker-compose.yml`, allowing unauthenticated access if the user forgot to set the `API_KEY` environment variable in production.
**Learning:** Default values in `docker-compose.yml` (like `${VAR:-default}`) and fallback values in code can lead to fail-open scenarios where a system silently boots in an insecure state.
**Prevention:** Always use fail-secure mechanisms. In `docker-compose.yml`, require variables using `${VAR:?error message}` and in application code, explicitly raise an error if critical secrets are missing rather than providing a default.

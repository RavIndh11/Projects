## 2024-05-24 - Weak Hashing in YARA Generator
**Vulnerability:** Weak MD5 and SHA1 hashes used without indicating they were not used for security purposes.
**Learning:** Tools like Bandit will flag `hashlib.md5()` and `hashlib.sha1()` by default as insecure crypto, breaking automated security pipelines or FIPS compliance.
**Prevention:** Always use `usedforsecurity=False` when using weak hashes for non-cryptographic purposes (like file identification/checksums).

## 2024-05-24 - Hardcoded API Key Fallback in c2_beacon_hunter
**Vulnerability:** A hardcoded default API key ("default-dev-key") was used as a fallback if the API_KEY environment variable was not set, even after an exception was supposed to be raised in production, allowing potential unauthorized access if the exception was somehow bypassed or if it simply fell through in development environments.
**Learning:** Developers sometimes add fallback default credentials for easier local development or testing, but this poses a critical risk if it ends up in a production environment or if the check logic is flawed.
**Prevention:** Never use default hardcoded credentials as fallbacks. In development/testing, inject credentials explicitly via environment variables or use a `.env` file (never committed). If testing requires a mock key, conditionally apply it strictly within the test environment context (e.g., checking `PYTEST_CURRENT_TEST`).

## 2024-05-24 - Hardcoded API Key Fallback in ai_agent_policy_guard
**Vulnerability:** A hardcoded default API key ("dev_api_key") was used as a fallback if the API_KEY environment variable was not set, allowing potential unauthorized access.
**Learning:** Developers sometimes add fallback default credentials for easier local development or testing, but this poses a critical risk if it ends up in a production environment.
**Prevention:** Never use default hardcoded credentials as fallbacks. In development/testing, inject credentials explicitly via environment variables or use a `.env` file (never committed). If testing requires a mock key, conditionally apply it strictly within the test environment context (e.g., checking `PYTEST_CURRENT_TEST`).

## 2024-10-11 - SSRF Bypass via IPv4-mapped IPv6 Address
**Vulnerability:** The application was vulnerable to Server-Side Request Forgery (SSRF) because it failed to properly sanitize IPv4-mapped IPv6 addresses (e.g., `::ffff:127.0.0.1`), allowing attackers to bypass IPv4 blocklists and access restricted local or internal network resources.
**Learning:** Python's `ipaddress` module treats IPv6 addresses and IPv4 addresses distinctly. `ipaddress.ip_address('::ffff:127.0.0.1')` creates an IPv6 object. Checking if this IPv6 object is in an IPv4 network (like `127.0.0.0/8`) always evaluates to `False`, allowing the malicious payload to bypass blocklist checks meant for IPv4 addresses while potentially still routing as an IPv4 connection at the system level.
**Prevention:** When validating IP addresses for SSRF prevention, explicitly extract the IPv4 address from any potential IPv4-mapped IPv6 address by checking the `.ipv4_mapped` property. Example: `if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped: ip = ip.ipv4_mapped`.

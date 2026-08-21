## 2024-05-24 - Weak Hashing in YARA Generator
**Vulnerability:** Weak MD5 and SHA1 hashes used without indicating they were not used for security purposes.
**Learning:** Tools like Bandit will flag `hashlib.md5()` and `hashlib.sha1()` by default as insecure crypto, breaking automated security pipelines or FIPS compliance.
**Prevention:** Always use `usedforsecurity=False` when using weak hashes for non-cryptographic purposes (like file identification/checksums).

## 2024-05-24 - Hardcoded API Key Fallback in c2_beacon_hunter
**Vulnerability:** A hardcoded default API key ("default-dev-key") was used as a fallback if the API_KEY environment variable was not set, even after an exception was supposed to be raised in production, allowing potential unauthorized access if the exception was somehow bypassed or if it simply fell through in development environments.
**Learning:** Developers sometimes add fallback default credentials for easier local development or testing, but this poses a critical risk if it ends up in a production environment or if the check logic is flawed.
**Prevention:** Never use default hardcoded credentials as fallbacks. In development/testing, inject credentials explicitly via environment variables or use a `.env` file (never committed). If testing requires a mock key, conditionally apply it strictly within the test environment context (e.g., checking `PYTEST_CURRENT_TEST`).
## 2025-02-27 - [Bypassing SSRF using IPv4-mapped IPv6]
**Vulnerability:** The SSRF Sentinel failed to block IPv4 addresses passed in the IPv4-mapped IPv6 notation like `::ffff:127.0.0.1`.
**Learning:** `ipaddress.ip_address` correctly interprets these as IPv6 addresses, bypassing any checks relying strictly on IPv4 network ranges.
**Prevention:** Always verify if an IPv6 object is an IPv4-mapped address (`ip.ipv4_mapped`) and evaluate the underlying IPv4 address.

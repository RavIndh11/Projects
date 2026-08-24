## 2024-05-24 - Weak Hashing in YARA Generator
**Vulnerability:** Weak MD5 and SHA1 hashes used without indicating they were not used for security purposes.
**Learning:** Tools like Bandit will flag `hashlib.md5()` and `hashlib.sha1()` by default as insecure crypto, breaking automated security pipelines or FIPS compliance.
**Prevention:** Always use `usedforsecurity=False` when using weak hashes for non-cryptographic purposes (like file identification/checksums).

## 2024-05-24 - Hardcoded API Key Fallback in c2_beacon_hunter
**Vulnerability:** A hardcoded default API key ("default-dev-key") was used as a fallback if the API_KEY environment variable was not set, even after an exception was supposed to be raised in production, allowing potential unauthorized access if the exception was somehow bypassed or if it simply fell through in development environments.
**Learning:** Developers sometimes add fallback default credentials for easier local development or testing, but this poses a critical risk if it ends up in a production environment or if the check logic is flawed.
**Prevention:** Never use default hardcoded credentials as fallbacks. In development/testing, inject credentials explicitly via environment variables or use a `.env` file (never committed). If testing requires a mock key, conditionally apply it strictly within the test environment context (e.g., checking `PYTEST_CURRENT_TEST`).

## 2024-08-24 - Timing Attack via Standard String Equality
**Vulnerability:** API key verification in c2_beacon_hunter used standard string equality (`==`) which is vulnerable to timing attacks.
**Learning:** Standard string equality checks return early on the first mismatched character, allowing an attacker to guess the secret character by character based on response times.
**Prevention:** Always use `secrets.compare_digest` for verifying passwords, tokens, API keys, or any other sensitive secrets to ensure constant-time comparison. Additionally, ensure the input is not None before attempting to compare, as it can result in TypeErrors.

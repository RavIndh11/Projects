## 2024-05-24 - Weak Hashing in YARA Generator
**Vulnerability:** Weak MD5 and SHA1 hashes used without indicating they were not used for security purposes.
**Learning:** Tools like Bandit will flag `hashlib.md5()` and `hashlib.sha1()` by default as insecure crypto, breaking automated security pipelines or FIPS compliance.
**Prevention:** Always use `usedforsecurity=False` when using weak hashes for non-cryptographic purposes (like file identification/checksums).

## 2024-05-24 - Hardcoded API Key Fallback in c2_beacon_hunter
**Vulnerability:** A hardcoded default API key ("default-dev-key") was used as a fallback if the API_KEY environment variable was not set, even after an exception was supposed to be raised in production, allowing potential unauthorized access if the exception was somehow bypassed or if it simply fell through in development environments.
**Learning:** Developers sometimes add fallback default credentials for easier local development or testing, but this poses a critical risk if it ends up in a production environment or if the check logic is flawed.
**Prevention:** Never use default hardcoded credentials as fallbacks. In development/testing, inject credentials explicitly via environment variables or use a `.env` file (never committed). If testing requires a mock key, conditionally apply it strictly within the test environment context (e.g., checking `PYTEST_CURRENT_TEST`).

## 2024-05-24 - Timing Attack Vulnerability in API Key Verification
**Vulnerability:** API key verification was performed using standard string equality (`==`), which allows attackers to perform timing attacks to guess the key.
**Learning:** Standard string comparison operators in Python (and many other languages) short-circuit, meaning they return `False` as soon as a character mismatch is found. This makes the comparison time proportional to the number of matching prefix characters, leaking information.
**Prevention:** Always use constant-time string comparison functions like `secrets.compare_digest()` when validating sensitive credentials such as API keys, passwords, or cryptographic signatures. Ensure the input is not `None` before passing it to `compare_digest` to avoid `TypeError`.

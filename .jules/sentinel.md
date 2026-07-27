## 2024-05-24 - Weak Hashing in YARA Generator
**Vulnerability:** Weak MD5 and SHA1 hashes used without indicating they were not used for security purposes.
**Learning:** Tools like Bandit will flag `hashlib.md5()` and `hashlib.sha1()` by default as insecure crypto, breaking automated security pipelines or FIPS compliance.
**Prevention:** Always use `usedforsecurity=False` when using weak hashes for non-cryptographic purposes (like file identification/checksums).

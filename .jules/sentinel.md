## 2024-05-24 - Weak Hashing in YARA Generator
**Vulnerability:** Weak MD5 and SHA1 hashes used without indicating they were not used for security purposes.
**Learning:** Tools like Bandit will flag `hashlib.md5()` and `hashlib.sha1()` by default as insecure crypto, breaking automated security pipelines or FIPS compliance.
**Prevention:** Always use `usedforsecurity=False` when using weak hashes for non-cryptographic purposes (like file identification/checksums).
## 2024-05-18 - Prevent IPv4-Mapped IPv6 Bypasses in IP Validation

**Vulnerability:** A standard blocklist checking for RFC 1918 IPv4 addresses using `ipaddress` can be bypassed by an attacker submitting an IPv4-mapped IPv6 address (e.g., `::ffff:127.0.0.1`). The library evaluates this as an IPv6 object, which avoids the IPv4 CIDR blocks, but underlying OS networking stacks will often translate and route it as a local IPv4 request, causing SSRF.

**Learning:** Always normalize IP objects. When validating IP addresses using Python's `ipaddress` module, explicitly check for and unpack IPv4-mapped addresses.

**Prevention:** Include logic like `if ip.version == 6 and ip.ipv4_mapped: ip = ip.ipv4_mapped` before evaluating against standard blocklists. Also include the IPv6 Unspecified Address (`::/128`) in your blocklists as it often resolves to localhost on Linux.

## 2026-07-27 - HTTP Connection Reuse (TCP Handshake Overhead)
**Learning:** Sending multiple sequential HTTP requests to the same origin without using a connection pool (like `requests.Session()`) incurs significant overhead due to repeated TCP handshakes and SSL negotiation. In security scanning tools like `cors_scanner`, where multiple payloads are tested against a single URL, this bottleneck is substantial.
**Action:** Always utilize `requests.Session()` (or equivalent connection pooling mechanisms) when making multiple requests to the same target domain to reuse the underlying TCP connections, drastically improving performance.## 2026-07-28 - DNS NXDOMAIN Early Return
**Learning:** When resolving DNS records, if an 'A' record lookup raises `dns.resolver.NXDOMAIN`, it means the domain itself does not exist. Subsequent queries for other record types (like 'MX') on that same domain are guaranteed to also raise `NXDOMAIN`.
**Action:** Always return early or skip subsequent DNS queries if an initial query raises `NXDOMAIN` to eliminate unnecessary network requests and significantly improve performance.
## 2024-05-24 - [Python Regex Caching]
**Learning:** Using `functools.lru_cache` to memoize repetitive, expensive regex pattern matching against frequently recurring strings (like log paths and user agents) drastically speeds up parsing.
**Action:** When iterating over repetitive inputs where evaluation is pure but costly (like compiling or executing multiple regexes), pull the loop into a separate cached function.

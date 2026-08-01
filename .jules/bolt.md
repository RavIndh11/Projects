## 2026-08-01 - [Reusing TCP connections with requests.Session]
**Learning:** Making repeated network requests to the same host using `requests.get` incurs heavy overhead from establishing TCP connections and TLS handshakes each time. Using a `requests.Session` object creates an underlying `urllib3` connection pool to reuse these connections.
**Action:** When creating tools that make multiple queries to the same remote API/host, instantiate a global or instance-level `requests.Session()` object instead of using individual `requests.get` calls.

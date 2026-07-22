import requests
from urllib.parse import urlparse
from typing import List, Dict, Optional
import urllib3

# Suppress insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CORSScanner:
    """
    A scanner to detect Cross-Origin Resource Sharing (CORS) misconfigurations.
    """

    def __init__(self, timeout: int = 10, user_agent: str = "Mozilla/5.0 CORS-Scanner"):
        self.timeout = timeout
        self.headers = {"User-Agent": user_agent}

    def _generate_payloads(self, url: str) -> List[str]:
        """
        Generate a list of malicious origin payloads based on the target URL.
        """
        parsed_url = urlparse(url)
        netloc = parsed_url.netloc
        # Extract host without port for payload generation if port exists
        host = netloc.split(':')[0] if ':' in netloc else netloc

        payloads = [
            "https://evil.com",
            "http://evil.com",
            "null",
            f"https://{host}.evil.com", # Prefix bypass
            f"https://evil{host}",       # Suffix bypass (e.g., evil.com if host is .com, or evilexample.com)
            f"http://{host}.evil.com"
        ]
        return payloads

    def scan_url(self, url: str) -> List[Dict[str, str]]:
        """
        Scan a single URL for CORS misconfigurations.
        Returns a list of findings.
        """
        findings = []
        payloads = self._generate_payloads(url)

        for origin in payloads:
            headers = self.headers.copy()
            headers["Origin"] = origin

            try:
                # Use GET request for checking CORS headers.
                # In a real scenario, OPTIONS is also useful, but GET is often enough
                # if the server reflects on GET requests.
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False
                )

                acao = response.headers.get("Access-Control-Allow-Origin")
                acac = response.headers.get("Access-Control-Allow-Credentials")

                if acao:
                    # Check if the reflected ACAO matches our malicious payload
                    # Sometimes servers return * which is also interesting but only exploitable if ACAC is true (which is against spec but happens) or if we want to bypass network restrictions
                    if acao == origin or acao == "*":
                        severity = "High" if acao == origin and acac == "true" else "Medium"
                        if acao == "*" and acac == "true":
                            # Browsers should block this, but it's a severe misconfiguration attempt
                            severity = "Low"

                        finding = {
                            "url": url,
                            "payload": origin,
                            "acao_header": acao,
                            "acac_header": acac if acac else "false",
                            "severity": severity,
                            "description": f"Reflected Origin: {acao} with Allow-Credentials: {acac}"
                        }
                        findings.append(finding)
            except requests.RequestException as e:
                import logging
                logging.debug(f"Request error for {url} with payload {origin}: {e}")
                pass

        return findings

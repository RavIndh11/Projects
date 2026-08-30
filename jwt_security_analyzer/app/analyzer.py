import base64
import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from app.schemas import AnalysisResult, Vulnerability

logger = logging.getLogger(__name__)

class JWTAnalyzer:
    def __init__(self):
        # A small list of common weak secrets for demonstration.
        # In a real tool this would be a much larger wordlist or loaded from a file.
        self.common_weak_secrets = [
            "secret", "123456", "password", "admin", "test", "jwtsecret",
            "changeme", "qwerty", "letmein", "default"
        ]

    def _decode_base64_url(self, data: str) -> dict:
        """Decode a base64url encoded string to a dictionary."""
        # Add padding if necessary
        padding = "=" * (4 - (len(data) % 4))
        decoded_bytes = base64.urlsafe_b64decode(data + padding)
        return json.loads(decoded_bytes.decode('utf-8'))

    def parse_token(self, token: str) -> Tuple[Optional[Dict], Optional[Dict], Optional[str], Optional[str]]:
        """Parses the JWT into header, payload, and signature without verifying."""
        parts = token.split('.')
        if len(parts) != 3:
            return None, None, None, "Invalid JWT format. Must contain 3 parts."

        try:
            header = self._decode_base64_url(parts[0])
            payload = self._decode_base64_url(parts[1])
            signature = parts[2]
            return header, payload, signature, None
        except Exception as e:
            logger.error(f"Error parsing token: {e}")
            return None, None, None, f"Failed to parse token components: {str(e)}"

    def check_alg_none(self, header: Dict) -> Optional[Vulnerability]:
        alg = str(header.get('alg', '')).lower()
        if alg == 'none':
            return Vulnerability(
                id="JWT-001",
                name="Algorithm 'none' Accepted",
                severity="Critical",
                description="The JWT header specifies 'alg: none'. If the backend accepts this, it will bypass signature validation entirely.",
                remediation="Ensure the backend library strictly enforces the expected algorithm (e.g., HS256, RS256) and rejects 'alg: none'."
            )
        return None

    def check_weak_symmetric_alg(self, header: Dict) -> Optional[Vulnerability]:
        alg = str(header.get('alg', '')).upper()
        if alg in ['HS256', 'HS384', 'HS512']:
            return Vulnerability(
                id="JWT-002",
                name="Symmetric Algorithm Used",
                severity="Low",
                description=f"The token uses a symmetric algorithm ({alg}). This is not inherently insecure, but it is vulnerable to offline brute-forcing if the secret key is weak.",
                remediation="Ensure the secret key is strong (e.g., >= 256 bits). Consider switching to asymmetric algorithms (RS256, ES256) if the key needs to be shared."
            )
        return None

    def check_missing_expiration(self, payload: Dict) -> Optional[Vulnerability]:
        if 'exp' not in payload:
            return Vulnerability(
                id="JWT-003",
                name="Missing Expiration Claim (exp)",
                severity="Medium",
                description="The token does not have an 'exp' claim. It will be valid indefinitely unless revoked manually.",
                remediation="Add a short-lived 'exp' claim to limit the window of opportunity if the token is compromised."
            )
        return None

    def check_sensitive_data_in_payload(self, payload: Dict) -> Optional[Vulnerability]:
        sensitive_keys = ['password', 'pwd', 'secret', 'ssn', 'credit_card', 'pin']
        found_keys = [k for k in payload.keys() if any(sk in k.lower() for sk in sensitive_keys)]

        if found_keys:
            return Vulnerability(
                id="JWT-004",
                name="Sensitive Data in Payload",
                severity="High",
                description=f"Potential sensitive data found in payload keys: {', '.join(found_keys)}. JWT payloads are merely base64 encoded, not encrypted.",
                remediation="Do not store sensitive data like passwords or PII in JWT payloads. Store a reference (e.g., user ID) instead."
            )
        return None

    def check_weak_secret_bruteforce(self, token: str, header: Dict) -> Optional[Vulnerability]:
        """Attempt to brute force the token signature with common weak secrets."""
        import jwt # local import to avoid loading unless needed

        alg = str(header.get('alg', '')).upper()
        if alg not in ['HS256', 'HS384', 'HS512']:
            return None # Brute force only applies to symmetric algs here

        for secret in self.common_weak_secrets:
            try:
                # If decode succeeds, we found the secret
                jwt.decode(token, secret, algorithms=[alg])
                return Vulnerability(
                    id="JWT-005",
                    name="Weak Secret Key (Brute-forced)",
                    severity="Critical",
                    description=f"The token's signature was successfully verified using a known weak secret ('{secret}'). An attacker can forge arbitrary tokens.",
                    remediation="Immediately change the secret key to a strong, cryptographically random value (at least 256 bits) and invalidate all existing tokens."
                )
            except jwt.InvalidSignatureError:
                continue
            except Exception as e:
                # Other decoding errors (expired, etc) mean the signature might actually be valid but payload invalid.
                # Since pyjwt validates signature first, if it fails validation we get InvalidSignatureError.
                # If we get another error (like ExpiredSignatureError), the signature *was* valid.
                if isinstance(e, jwt.ExpiredSignatureError):
                   return Vulnerability(
                        id="JWT-005",
                        name="Weak Secret Key (Brute-forced)",
                        severity="Critical",
                        description=f"The token's signature was successfully verified using a known weak secret ('{secret}'). (Token is expired).",
                        remediation="Immediately change the secret key to a strong, cryptographically random value (at least 256 bits) and invalidate all existing tokens."
                    )
                continue

        return None

    def analyze(self, token: str) -> AnalysisResult:
        header, payload, signature, error = self.parse_token(token)

        if error:
            logger.warning(f"Analysis failed: {error}")
            return AnalysisResult(
                is_valid_format=False,
                error=error
            )

        vulnerabilities = []

        # 1. Check alg: none
        if header:
            vuln = self.check_alg_none(header)
            if vuln: vulnerabilities.append(vuln)

            vuln = self.check_weak_symmetric_alg(header)
            if vuln: vulnerabilities.append(vuln)

            # Brute force (symmetric only)
            vuln = self.check_weak_secret_bruteforce(token, header)
            if vuln: vulnerabilities.append(vuln)

        # 2. Check payload
        if payload:
            vuln = self.check_missing_expiration(payload)
            if vuln: vulnerabilities.append(vuln)

            vuln = self.check_sensitive_data_in_payload(payload)
            if vuln: vulnerabilities.append(vuln)

        return AnalysisResult(
            is_valid_format=True,
            header=header,
            payload=payload,
            signature=signature,
            vulnerabilities=vulnerabilities
        )

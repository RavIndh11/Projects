import base64
import json
import hmac
import hashlib
import time

class JWTInspectorError(Exception):
    """Base exception for JWT Inspector errors."""
    pass

class InvalidTokenError(JWTInspectorError):
    """Raised when the token format is invalid."""
    pass

def base64url_decode(input_string):
    """Decodes a base64url encoded string."""
    rem = len(input_string) % 4
    if rem > 0:
        input_string += '=' * (4 - rem)
    try:
        return base64.urlsafe_b64decode(input_string)
    except Exception as e:
        raise InvalidTokenError(f"Failed to decode base64url: {e}")

def parse_jwt(token):
    """Parses a JWT and returns the decoded header, payload, and raw signature."""
    parts = token.split('.')
    if len(parts) != 3:
        raise InvalidTokenError("Invalid JWT format. Expected 3 parts separated by dots.")

    try:
        header_json = base64url_decode(parts[0]).decode('utf-8')
        payload_json = base64url_decode(parts[1]).decode('utf-8')

        header = json.loads(header_json)
        payload = json.loads(payload_json)
    except Exception as e:
        raise InvalidTokenError(f"Failed to parse JWT header or payload as JSON: {e}")

    return {
        "header": header,
        "payload": payload,
        "signature_raw": parts[2],
        "signing_input": f"{parts[0]}.{parts[1]}"
    }

def analyze_token(parsed_token):
    """Analyzes the parsed token for security issues and interesting claims."""
    analysis = {
        "is_none_algorithm": False,
        "is_expired": False,
        "expires_in_seconds": None,
        "issues": []
    }

    header = parsed_token.get("header", {})
    payload = parsed_token.get("payload", {})

    # Check for 'none' algorithm
    alg = header.get("alg", "").lower()
    if alg == "none":
        analysis["is_none_algorithm"] = True
        analysis["issues"].append("CRITICAL: Token uses the 'none' algorithm, which bypasses signature verification.")

    # Check expiration
    exp = payload.get("exp")
    if exp:
        try:
            exp_time = int(exp)
            current_time = int(time.time())
            analysis["expires_in_seconds"] = exp_time - current_time
            if analysis["expires_in_seconds"] < 0:
                analysis["is_expired"] = True
                analysis["issues"].append("WARNING: Token is expired.")
        except ValueError:
            analysis["issues"].append("ERROR: 'exp' claim is not a valid integer.")
    else:
        analysis["issues"].append("INFO: Token does not have an 'exp' (expiration) claim.")

    return analysis

def brute_force_hmac_sha256(signing_input, target_signature_b64, wordlist_path):
    """Attempts to brute force an HMAC-SHA256 signature using a wordlist."""
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                secret = line.strip()
                if not secret:
                    continue

                # Compute HMAC-SHA256
                signature = hmac.new(
                    secret.encode('utf-8'),
                    signing_input.encode('utf-8'),
                    hashlib.sha256
                ).digest()

                # Base64url encode the computed signature (remove padding)
                computed_signature_b64 = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')

                if computed_signature_b64 == target_signature_b64:
                    return secret
    except FileNotFoundError:
        raise JWTInspectorError(f"Wordlist file not found: {wordlist_path}")
    except Exception as e:
        raise JWTInspectorError(f"Error reading wordlist: {e}")

    return None

# JWT Inspector

## Project Overview
JWT Inspector is a lightweight, zero-dependency Python command-line tool designed for static analysis and offline brute-forcing of JSON Web Tokens (JWTs). It is built for security engineers, penetration testers, and developers who need a quick, safe, and local way to inspect JWTs without relying on external online decoders that might log sensitive data.

## Problem Statement
When auditing web applications, security practitioners frequently encounter JWTs used for session management and authorization. A common requirement is to decode these tokens to inspect claims (like user IDs or roles) and to check for common misconfigurations (such as the `alg: none` vulnerability or weak HMAC secrets). While online tools (like jwt.io) exist, pasting potentially sensitive production tokens into third-party websites is a significant security risk. There is a need for a local, fast, and easy-to-use tool for JWT inspection.

## Features
- **Local Decoding**: Decodes Base64URL-encoded headers and payloads completely offline.
- **Static Analysis**: Detects critical security misconfigurations like the `alg: "none"` bypass vulnerability.
- **Expiration Checking**: Validates the `exp` (expiration) claim to see if the token is currently valid.
- **HMAC Brute-forcing**: Performs offline dictionary attacks against HS256 signed tokens to identify weak signing secrets.
- **Zero Dependencies (Core)**: The core functionality relies entirely on the Python standard library, making it highly portable. Testing relies on `pytest`.

## Architecture or Workflow
The project is structured into modular components:
- `core.py`: Contains the logic for base64url decoding, JSON parsing, static analysis rules, and cryptographic operations (HMAC-SHA256 generation for brute-forcing).
- `cli.py`: The entry point that utilizes `argparse` to provide a user-friendly command-line interface, formatting the output from `core.py` for readability.
- `tests/`: A comprehensive suite of `pytest` unit tests ensuring the reliability of parsing, analysis, and brute-forcing logic.

## Installation Instructions

### Prerequisites
- Python 3.6 or higher.

### Setup
Clone the repository and navigate to the project directory:

```bash
cd jwt_inspector
```

*(Optional)* Create a virtual environment for testing:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage Examples

### 1. Basic Inspection and Analysis
Simply pass the JWT string to the script.

```bash
python3 -m jwt_inspector.cli "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
```

**Output:**
```
[*] Parsing JWT...

--- Header ---
{
  "alg": "HS256",
  "typ": "JWT"
}

--- Payload ---
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}

[*] Analyzing Token...

Findings:
  - INFO: Token does not have an 'exp' (expiration) claim.
```

### 2. Brute-forcing an HS256 Secret
Use the `-w` or `--wordlist` flag to provide a list of potential secrets.

```bash
python3 -m jwt_inspector.cli "your.jwt.here" -w /path/to/wordlist.txt
```

## Security Considerations
- **Offline Only**: This tool is designed to run entirely locally. It never transmits tokens over the network, ensuring that sensitive data contained within the JWTs remains on your machine.
- **Brute-force Speed**: The brute-force mechanism is implemented in pure Python. While sufficient for small to medium wordlists or basic CTF challenges, it is not highly optimized (e.g., using GPU acceleration like Hashcat) for massive dictionary attacks.

## Limitations
- **Algorithm Support for Cracking**: Currently, the brute-force cracking feature only supports the HMAC-SHA256 (`HS256`) algorithm. Asymmetric algorithms (like RS256) cannot be brute-forced in this manner, and other symmetric algorithms (HS384, HS512) are not yet implemented.
- **Standard Library Performance**: Performance during brute-forcing is limited by standard CPython execution speeds.

## Future Improvements
- **Add HS384 and HS512 Support**: Extend the brute-forcing capabilities to other HMAC algorithms.
- **Public Key Extraction Check**: Add analysis rules to detect confusion attacks (e.g., changing RS256 to HS256 and signing with the public key).
- **JWE Support**: Add support for parsing and analyzing JSON Web Encryption (JWE) tokens.

import argparse
import sys
import json
from .core import parse_jwt, analyze_token, brute_force_hmac_sha256, JWTInspectorError

def main():
    parser = argparse.ArgumentParser(description="JWT Inspector: A tool for analyzing and cracking JSON Web Tokens.")
    parser.add_argument("token", help="The JSON Web Token to inspect.")
    parser.add_argument("-w", "--wordlist", help="Path to a wordlist file for HMAC secret brute-forcing.")

    args = parser.parse_args()

    try:
        print("[*] Parsing JWT...")
        parsed = parse_jwt(args.token)

        print("\n--- Header ---")
        print(json.dumps(parsed["header"], indent=2))

        print("\n--- Payload ---")
        print(json.dumps(parsed["payload"], indent=2))

        print("\n[*] Analyzing Token...")
        analysis = analyze_token(parsed)

        if analysis["issues"]:
            print("\nFindings:")
            for issue in analysis["issues"]:
                print(f"  - {issue}")
        else:
            print("\nNo obvious security issues found during static analysis.")

        if args.wordlist:
            alg = parsed["header"].get("alg", "").upper()
            if alg in ["HS256", "HS384", "HS512"]:
                # Currently only implemented HS256 in core, but check for HS* family
                if alg == "HS256":
                    print(f"\n[*] Starting HMAC-SHA256 brute-force attack using wordlist: {args.wordlist}")
                    secret = brute_force_hmac_sha256(parsed["signing_input"], parsed["signature_raw"], args.wordlist)
                    if secret:
                        print(f"[+] SUCCESS! Secret found: {secret}")
                    else:
                        print("[-] Secret not found in wordlist.")
                else:
                    print(f"\n[-] Algorithm {alg} brute-forcing is not yet supported. Only HS256 is supported.")
            elif alg == "NONE":
                 print("\n[*] Algorithm is 'none'. No signature to crack.")
            else:
                print(f"\n[-] Token uses {alg}. Brute-forcing is only applicable to symmetric HMAC algorithms (e.g., HS256).")

    except JWTInspectorError as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

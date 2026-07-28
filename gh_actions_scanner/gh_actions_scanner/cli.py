import argparse
import sys
import json
from .scanner import scan_directory

def main():
    parser = argparse.ArgumentParser(description="Scan GitHub Actions workflows for security vulnerabilities.")
    parser.add_argument("directory", help="Directory containing .github/workflows to scan.")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format.")

    args = parser.parse_args()

    results = scan_directory(args.directory)

    if args.format == "json":
        print(json.dumps(results, indent=2))
    else:
        if not results:
            print("No vulnerabilities found.")
        else:
            for finding in results:
                print(f"[{finding['severity']}] {finding['rule']} in {finding['file']}:")
                print(f"  -> {finding['message']}\n")

    if any(r['severity'] in ['HIGH', 'CRITICAL'] for r in results):
        sys.exit(1)

if __name__ == "__main__":
    main()

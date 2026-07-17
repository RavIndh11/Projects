import argparse
import os
import sys
import json
import logging
from core import scan_policy_file

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

def scan_directory(directory_path):
    """Scan a directory for JSON policy files and evaluate them."""
    all_findings = {}
    for filename in os.listdir(directory_path):
        if filename.endswith(".json"):
            filepath = os.path.join(directory_path, filename)
            findings = scan_policy_file(filepath)
            if findings is not None:
                all_findings[filepath] = findings
    return all_findings

def print_findings(findings, output_format="text"):
    """Print findings in the specified format."""
    if output_format == "json":
        print(json.dumps(findings, indent=4))
        return

    # Text output
    total_findings = 0
    for filepath, vectors in findings.items():
        print(f"\n[+] Scanning {filepath}")
        if vectors:
            print(f"    WARNING: Potential privilege escalation vectors detected!")
            for vector in vectors:
                print(f"    - {vector}")
            total_findings += len(vectors)
        else:
            print(f"    Secure: No known privesc vectors detected.")

    print(f"\nScan complete. Total potential vectors found: {total_findings}")

def main():
    parser = argparse.ArgumentParser(description="AWS IAM Privilege Escalation Scanner")
    parser.add_argument("-f", "--file", type=str, help="Path to a single IAM policy JSON file.")
    parser.add_argument("-d", "--directory", type=str, help="Path to a directory containing IAM policy JSON files.")
    parser.add_argument("-o", "--output", type=str, choices=["text", "json"], default="text", help="Output format (default: text).")

    args = parser.parse_args()

    if not args.file and not args.directory:
        parser.error("Must provide either a file (-f) or a directory (-d) to scan.")

    all_findings = {}

    if args.file:
        if not os.path.exists(args.file):
            logger.error(f"File not found: {args.file}")
            sys.exit(1)
        findings = scan_policy_file(args.file)
        if findings is not None:
            all_findings[args.file] = findings

    if args.directory:
        if not os.path.isdir(args.directory):
            logger.error(f"Directory not found: {args.directory}")
            sys.exit(1)
        dir_findings = scan_directory(args.directory)
        all_findings.update(dir_findings)

    print_findings(all_findings, args.output)

if __name__ == "__main__":
    main()

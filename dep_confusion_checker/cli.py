import argparse
import sys
import json
import os
from .checker import DependencyChecker

def main():
    parser = argparse.ArgumentParser(
        description="Dependency Confusion Checker: Detect potentially vulnerable packages in dependency files."
    )

    parser.add_argument(
        "filepath",
        help="Path to the dependency file (package.json or requirements.txt)"
    )

    parser.add_argument(
        "-t", "--type",
        choices=['npm', 'pypi'],
        help="Force the dependency type (npm for package.json, pypi for requirements.txt). Auto-detected by default."
    )

    parser.add_argument(
        "-i", "--ignore-scopes",
        nargs="+",
        default=[],
        help="NPM scopes to ignore (e.g., -i @mycompany @internal)"
    )

    parser.add_argument(
        "-j", "--json",
        action="store_true",
        help="Output results in JSON format"
    )

    args = parser.parse_args()

    if not os.path.exists(args.filepath):
        print(f"Error: File '{args.filepath}' does not exist.", file=sys.stderr)
        sys.exit(1)

    file_type = args.type
    if not file_type:
        filename = os.path.basename(args.filepath).lower()
        if "package.json" in filename:
            file_type = "npm"
        elif "requirements.txt" in filename:
            file_type = "pypi"
        else:
            print("Error: Could not auto-detect file type from filename. Please use -t/--type to specify 'npm' or 'pypi'.", file=sys.stderr)
            sys.exit(1)

    checker = DependencyChecker(ignore_scopes=args.ignore_scopes)

    try:
        results = checker.check_file(args.filepath, file_type)
    except Exception as e:
        print(f"Error checking file: {e}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"--- Dependency Confusion Check Report ---")
        print(f"File: {args.filepath} ({file_type.upper()})")
        print(f"Total packages checked: {len(results['safe']) + len(results['vulnerable']) + len(results['ignored'])}")

        if results['ignored']:
             print(f"\nIgnored packages ({len(results['ignored'])}):")
             for pkg in results['ignored']:
                 print(f"  - {pkg}")

        if results['safe']:
            print(f"\nSafe packages found on public registry ({len(results['safe'])}):")
            for pkg in results['safe']:
                print(f"  - {pkg}")

        if results['vulnerable']:
            print(f"\n[!] POTENTIALLY VULNERABLE PACKAGES ({len(results['vulnerable'])}) [!]")
            print("These packages were not found on the public registry.")
            print("An attacker could potentially claim them and serve malicious code.")
            for pkg in results['vulnerable']:
                print(f"  [X] {pkg}")

            # Exit with code 1 if vulnerabilities are found
            sys.exit(1)
        else:
            print("\n[+] No vulnerable packages detected.")
            sys.exit(0)

if __name__ == "__main__":
    main()

import argparse
import sys
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from .scanner import CORSScanner

def print_finding(finding):
    severity_color = {
        "High": "\033[91m",   # Red
        "Medium": "\033[93m", # Yellow
        "Low": "\033[94m"     # Blue
    }
    reset_color = "\033[0m"
    color = severity_color.get(finding["severity"], reset_color)

    print(f"{color}[{finding['severity']}] {finding['url']} - Payload: {finding['payload']}{reset_color}")
    print(f"    ACAO: {finding['acao_header']}")
    print(f"    ACAC: {finding['acac_header']}")

def main():
    parser = argparse.ArgumentParser(description="CORS Misconfiguration Scanner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Target URL to scan")
    group.add_argument("-l", "--list", help="File containing list of URLs to scan")

    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")
    parser.add_argument("-o", "--output", help="Output file to save findings (JSON format)")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP request timeout in seconds (default: 10)")

    args = parser.parse_args()

    scanner = CORSScanner(timeout=args.timeout)
    urls_to_scan = []

    if args.url:
        urls_to_scan.append(args.url)
    elif args.list:
        try:
            with open(args.list, 'r') as f:
                urls_to_scan = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Error: File not found: {args.list}")
            sys.exit(1)

    print(f"Starting scan of {len(urls_to_scan)} URLs with {args.threads} threads...\n")

    all_findings = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_url = {executor.submit(scanner.scan_url, url): url for url in urls_to_scan}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                findings = future.result()
                if findings:
                    for finding in findings:
                        print_finding(finding)
                        all_findings.append(finding)
            except Exception as exc:
                print(f"Error scanning {url}: {exc}")

    if all_findings:
        print(f"\nScan complete. Found {len(all_findings)} potential misconfigurations.")
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(all_findings, f, indent=4)
            print(f"Findings saved to {args.output}")
    else:
        print("\nScan complete. No misconfigurations found.")

if __name__ == "__main__":
    main()

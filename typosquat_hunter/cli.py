import argparse
import json
from typosquat_hunter.permutations import get_all_permutations
from typosquat_hunter.scanner import Scanner

def main():
    parser = argparse.ArgumentParser(description="Typosquat Hunter - A tool to identify registered typosquatted domains.")
    parser.add_argument("domain", help="The target domain to check (e.g., example.com)")
    parser.add_argument("-c", "--concurrency", type=int, default=10, help="Number of concurrent DNS queries (default: 10)")
    parser.add_argument("-o", "--output", choices=["text", "json"], default="text", help="Output format (text or json)")

    args = parser.parse_args()

    domain_parts = args.domain.split('.')
    if len(domain_parts) < 2:
        print("Error: Invalid domain format. Please provide a domain with a TLD (e.g., example.com)")
        return

    base_domain = domain_parts[0]
    tld = '.'.join(domain_parts[1:])

    print(f"[*] Generating permutations for {base_domain}...")
    permutations = get_all_permutations(base_domain)

    domains_to_scan = [f"{p}.{tld}" for p in permutations]
    print(f"[*] Generated {len(domains_to_scan)} domains to scan.")

    print(f"[*] Scanning domains (concurrency: {args.concurrency})...")
    scanner = Scanner(concurrency=args.concurrency)
    results = scanner.scan_domains(domains_to_scan)

    if args.output == "json":
        print(json.dumps(results, indent=4))
    else:
        print("\n[*] Scan Results:")
        if not results:
            print("No resolvable typosquatted domains found.")
        for r in results:
            print(f"\n[+] {r['domain']}")
            if r['a_records']:
                print(f"    A Records: {', '.join(r['a_records'])}")
            if r['mx_records']:
                print(f"    MX Records: {', '.join(r['mx_records'])}")

if __name__ == "__main__":
    main()

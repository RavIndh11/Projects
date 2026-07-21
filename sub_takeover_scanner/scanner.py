import argparse
import json
import logging
import sys
import dns.resolver
import requests
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

def load_signatures(filepath):
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error(f"Signatures file not found: {filepath}")
        sys.exit(1)
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON format in {filepath}")
        sys.exit(1)

def resolve_cname(domain):
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        # Follow CNAME chain and return all unique CNAMEs
        cnames = []
        for rdata in answers:
            cname = str(rdata.target).rstrip('.')
            cnames.append(cname)
        return cnames
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []
    except Exception as e:
        logging.debug(f"DNS resolution error for {domain}: {e}")
        return []

def check_vulnerability(domain, signatures):
    cnames = resolve_cname(domain)
    if not cnames:
        return None

    for cname in cnames:
        for sig in signatures:
            for sig_cname in sig.get("cname", []):
                if sig_cname in cname:
                    logging.info(f"[{domain}] CNAME {cname} matches provider {sig['provider']}")

                    try:
                        # Make HTTP request
                        response = requests.get(f"http://{domain}", timeout=5, allow_redirects=True)
                        if sig["fingerprint"] in response.text:
                            logging.warning(f"[{domain}] VULNERABLE to subdomain takeover via {sig['provider']}!")
                            return {
                                "domain": domain,
                                "cname": cname,
                                "provider": sig["provider"],
                                "vulnerable": True
                            }
                    except requests.exceptions.RequestException as e:
                        logging.debug(f"HTTP request failed for {domain}: {e}")

    return None

def main():
    parser = argparse.ArgumentParser(description="Subdomain Takeover Scanner")
    parser.add_argument("-l", "--list", help="File containing list of subdomains to scan", required=False)
    parser.add_argument("-d", "--domain", help="Single subdomain to scan", required=False)
    parser.add_argument("-o", "--output", help="Output JSON file for results", required=False)
    parser.add_argument("-s", "--signatures", help="Path to signatures.json", default="signatures.json")

    args = parser.parse_args()

    if not args.list and not args.domain:
        parser.print_help()
        sys.exit(1)

    sig_path = args.signatures
    # Attempt to load from script directory if not found in current directory
    if not os.path.exists(sig_path):
        script_dir = os.path.dirname(os.path.realpath(__file__))
        sig_path = os.path.join(script_dir, "signatures.json")

    signatures = load_signatures(sig_path)

    targets = []
    if args.domain:
        targets.append(args.domain)
    if args.list:
        try:
            with open(args.list, 'r') as f:
                targets.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            logging.error(f"Target list file not found: {args.list}")
            sys.exit(1)

    results = []
    for target in targets:
        result = check_vulnerability(target, signatures)
        if result:
            results.append(result)

    if args.output and results:
        try:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=4)
            logging.info(f"Results saved to {args.output}")
        except IOError as e:
            logging.error(f"Failed to write results to {args.output}: {e}")

if __name__ == "__main__":
    main()

import whois
import socket
import requests
import subprocess
import shutil
import ssl
import re
import argparse
import json
import sys
import datetime

# Check if target is an IP address (IPv4 or basic IPv6 check)
def is_ip(address):
    ipv4_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    if ipv4_pattern.match(address):
        return all(0 <= int(part) <= 255 for part in address.split("."))
    if ":" in address:
        return True
    return False

# WHOIS Lookup
def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        # Convert WHOIS entry to dict gracefully
        if isinstance(w, dict):
            return w
        try:
            return dict(w)
        except Exception:
            return str(w)
    except Exception as e:
        return f"WHOIS lookup failed: {e}"

# DNS Enumeration using dig (A, NS, MX) with socket fallback
def dns_enum(domain):
    records = {}
    has_dig = shutil.which("dig") is not None

    for record_type in ["A", "NS", "MX"]:
        if has_dig:
            try:
                result = subprocess.check_output(["dig", domain, record_type, "+short"], timeout=10)
                records[record_type] = result.decode("utf-8").strip()
            except Exception as e:
                records[record_type] = f"DNS query failed: {e}"
        else:
            # Fallback for A record resolution using socket
            if record_type == "A":
                try:
                    ips = socket.gethostbyname_ex(domain)[2]
                    records["A"] = "\n".join(ips)
                except Exception as e:
                    records["A"] = f"Fallback resolution failed: {e}"
            else:
                records[record_type] = f"Skipped (dig command not available)"
    return records

# IP Geolocation using ipinfo.io
def ip_geolocation(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        if response.status_code == 200:
            return response.json()
        return f"Geolocation failed: HTTP status {response.status_code}"
    except Exception as e:
        return f"Geolocation failed: {e}"

# Reverse DNS Lookup
def reverse_dns_lookup(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror as e:
        return f"Reverse DNS lookup failed: {e}"
    except Exception as e:
        return f"Reverse DNS lookup failed: {e}"

# Passive Subdomain Enumeration via crt.sh
def passive_subdomains(domain):
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=15)
        if response.status_code != 200:
            return f"Failed to fetch subdomains: HTTP {response.status_code}"

        data = response.json()
        subdomains = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name and not name.startswith("*") and name.endswith(domain):
                    subdomains.add(name)

        return sorted(list(subdomains))
    except Exception as e:
        return f"Passive subdomain enum failed: {e}"

# HTTP Security Headers Analysis
def analyze_security_headers(target):
    protocols = ["https://", "http://"]
    response = None
    url_used = ""
    for proto in protocols:
        try:
            url = f"{proto}{target}"
            response = requests.get(url, timeout=5, allow_redirects=True)
            url_used = response.url
            break
        except Exception:
            continue

    if not response:
        return f"Could not connect to {target} over HTTP/HTTPS for header analysis."

    headers = response.headers
    security_headers = {
        "Strict-Transport-Security": "HSTS enforces secure connections. Prevents MITM attacks.",
        "Content-Security-Policy": "CSP mitigates XSS and data injection attacks.",
        "X-Frame-Options": "Prevents Clickjacking by controlling page framing.",
        "X-Content-Type-Options": "Prevents MIME-type sniffing.",
        "X-XSS-Protection": "Older protection against cross-site scripting (XSS).",
        "Referrer-Policy": "Controls how much referrer info is passed on links."
    }

    results = {
        "url": url_used,
        "present": {},
        "missing": {}
    }

    for header, desc in security_headers.items():
        # Case insensitive header lookup
        header_val = headers.get(header)
        if header_val:
            results["present"][header] = {
                "value": header_val,
                "description": desc
            }
        else:
            results["missing"][header] = desc

    return results

# SSL/TLS Certificate Checker
def check_ssl_cert(domain, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        return f"SSL Certificate check failed: {e}"

# Helper to decode raw SSL/TLS dictionary values
def parse_ssl_cert(cert):
    if not isinstance(cert, dict):
        return cert

    def decode_tuple(tup):
        res = []
        for rdns in tup:
            for rdn in rdns:
                res.append(f"{rdn[0]}={rdn[1]}")
        return ", ".join(res)

    parsed = {
        "subject": decode_tuple(cert.get("subject", ())),
        "issuer": decode_tuple(cert.get("issuer", ())),
        "version": cert.get("version"),
        "serialNumber": cert.get("serialNumber"),
        "notBefore": cert.get("notBefore"),
        "notAfter": cert.get("notAfter"),
        "subjectAltName": [item[1] for item in cert.get("subjectAltName", ()) if len(item) > 1]
    }
    return parsed

# Fallback lightweight socket TCP connect scan
def socket_port_scan(target, ports=[21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080]):
    print(f"\n[+] Nmap not found. Running basic Python socket port scan on {target}...")
    open_ports = []
    try:
        ip = socket.gethostbyname(target)
    except Exception as e:
        return f"Failed to resolve target '{target}' for fallback scan: {e}"

    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        result = s.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        s.close()

    if open_ports:
        return f"Fallback Port Scan Results for {target} ({ip}):\n" + "\n".join([f"Port {p}: OPEN" for p in open_ports])
    else:
        return f"Fallback Port Scan Results for {target} ({ip}):\nNo open ports found among the tested common ports."

# Nmap Scan with Fallback
def nmap_scan(target):
    if shutil.which("nmap"):
        try:
            print(f"\n[+] Running Nmap scan on {target}...\n")
            result = subprocess.check_output(["nmap", "-T4", "-F", target], timeout=60)
            return result.decode("utf-8")
        except subprocess.CalledProcessError as e:
            return f"Nmap scan failed: {e}"
        except subprocess.TimeoutExpired:
            return "Nmap scan timed out"
    else:
        return socket_port_scan(target)

# Convert outputs to styled txt format
def format_results_as_text(results):
    lines = []
    lines.append("=" * 60)
    lines.append("                 RECON TOOL RESULTS")
    lines.append("=" * 60)

    # Target Info
    info = results.get("target_info", {})
    if info.get("type") == "Domain":
        lines.append(f"Target: {info.get('domain')} (Domain)")
        if info.get("resolved_ip"):
            lines.append(f"Resolved IP: {info.get('resolved_ip')}")
    else:
        lines.append(f"Target: {info.get('ip')} (IP)")
    lines.append("-" * 60)

    # WHOIS
    if "whois" in results:
        lines.append("\n=== WHOIS Lookup ===")
        whois_data = results["whois"]
        if isinstance(whois_data, dict):
            for k, v in whois_data.items():
                if v and k not in ["raw", "raw_text"]:
                    lines.append(f"{k}: {v}")
        else:
            lines.append(str(whois_data))

    # DNS
    if "dns" in results:
        lines.append("\n=== DNS Enumeration ===")
        dns_data = results["dns"]
        if isinstance(dns_data, dict):
            for rtype, output in dns_data.items():
                lines.append(f"\n{rtype} Records:")
                lines.append(output if output else "No data")
        else:
            lines.append(str(dns_data))

    # Subdomains
    if "subdomains" in results:
        lines.append("\n=== Passive Subdomains ===")
        sub_data = results["subdomains"]
        if isinstance(sub_data, list):
            if sub_data:
                lines.append(f"Found {len(sub_data)} subdomain(s):")
                for sub in sub_data:
                    lines.append(f"  - {sub}")
            else:
                lines.append("No subdomains found.")
        else:
            lines.append(str(sub_data))

    # Geolocation
    if "geo" in results:
        lines.append("\n=== IP Geolocation ===")
        geo_data = results["geo"]
        if isinstance(geo_data, dict):
            for k, v in geo_data.items():
                lines.append(f"{k}: {v}")
        else:
            lines.append(str(geo_data))

    # Reverse DNS
    if "rdns" in results:
        lines.append("\n=== Reverse DNS Lookup ===")
        lines.append(str(results["rdns"]))

    # SSL Cert
    if "ssl" in results:
        lines.append("\n=== SSL Certificate Checker ===")
        ssl_data = results["ssl"]
        if isinstance(ssl_data, dict):
            for k, v in ssl_data.items():
                lines.append(f"{k}: {v}")
        else:
            lines.append(str(ssl_data))

    # HTTP Headers
    if "headers" in results:
        lines.append("\n=== HTTP Security Headers Analysis ===")
        header_data = results["headers"]
        if isinstance(header_data, dict):
            lines.append(f"Target URL Analyzed: {header_data.get('url')}\n")
            lines.append("Present Security Headers:")
            present = header_data.get("present", {})
            if present:
                for h, detail in present.items():
                    lines.append(f"  [✓] {h}: {detail.get('value')}")
            else:
                lines.append("  (None found)")

            lines.append("\nMissing Security Headers (Recommendations):")
            missing = header_data.get("missing", {})
            if missing:
                for h, desc in missing.items():
                    lines.append(f"  [✗] {h} - {desc}")
            else:
                lines.append("  (None! Great security posture.)")
        else:
            lines.append(str(header_data))

    # Nmap
    if "nmap" in results:
        lines.append("\n=== Nmap Scan ===")
        lines.append(str(results["nmap"]))

    return "\n".join(lines)

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Recon Tool - A lightweight information gathering utility for domain & IP analysis."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Target domain or IP address (e.g., example.com or 8.8.8.8)."
    )
    parser.add_argument(
        "-d", "--domain",
        help="Domain to analyze (overrides positional target)."
    )
    parser.add_argument(
        "-i", "--ip",
        help="IP address to analyze (overrides domain resolution if provided alone)."
    )
    parser.add_argument(
        "-o", "--output",
        help="Path to save output results."
    )
    parser.add_argument(
        "-f", "--format",
        choices=["txt", "json"],
        default="txt",
        help="Output file format (default: txt)."
    )
    parser.add_argument(
        "--modules",
        nargs="+",
        choices=["whois", "dns", "geo", "rdns", "nmap", "subdomains", "headers", "ssl"],
        help="Specific modules to run. If not specified, all applicable modules run."
    )
    return parser.parse_args()

# Main function
def main():
    args = parse_arguments()

    # Extract target
    target = args.domain or args.ip or args.target
    if not target:
        print("=== Welcome to Recon Tool ===")
        target = input("Enter target domain or IP address (example.com): ").strip()
        if not target:
            print("Error: No target specified. Exiting.")
            sys.exit(1)

    results = {}

    # Determine type of target
    if is_ip(target):
        ip = target
        domain = args.domain or None
        results["target_info"] = {"type": "IP", "ip": ip}
        if domain:
            results["target_info"]["domain"] = domain
            print(f"[+] Target recognized as IP: {ip} with associated domain: {domain}")
        else:
            print(f"[+] Target recognized as IP: {ip}")
    else:
        domain = target
        results["target_info"] = {"type": "Domain", "domain": domain}
        print(f"[+] Target recognized as Domain: {domain}")
        try:
            ip = socket.gethostbyname(domain)
            results["target_info"]["resolved_ip"] = ip
            print(f"[+] Resolved domain {domain} to IP: {ip}")
        except Exception as e:
            print(f"[-] Failed to resolve domain '{domain}': {e}")
            ip = None

    selected_modules = args.modules or ["whois", "dns", "geo", "rdns", "nmap", "subdomains", "headers", "ssl"]

    def should_run(mod_name, req_domain=False, req_ip=False):
        if mod_name not in selected_modules:
            return False
        if req_domain and not domain:
            return False
        if req_ip and not ip:
            return False
        return True

    # 1. WHOIS Lookup
    if should_run("whois", req_domain=True):
        print("\n=== WHOIS Lookup ===")
        w_res = whois_lookup(domain)
        results["whois"] = w_res
        if isinstance(w_res, dict):
            clean_w = {k: v for k, v in w_res.items() if v and k not in ["raw", "raw_text"]}
            for k, v in clean_w.items():
                print(f"{k}: {v}")
        else:
            print(w_res)

    # 2. DNS Enumeration
    if should_run("dns", req_domain=True):
        print("\n=== DNS Enumeration ===")
        dns_res = dns_enum(domain)
        results["dns"] = dns_res
        if isinstance(dns_res, dict):
            for rtype, output in dns_res.items():
                print(f"\n{rtype} Records:\n{output if output else 'No data'}")
        else:
            print(dns_res)

    # 3. Passive Subdomains
    if should_run("subdomains", req_domain=True):
        print("\n=== Passive Subdomains (crt.sh) ===")
        sub_res = passive_subdomains(domain)
        results["subdomains"] = sub_res
        if isinstance(sub_res, list):
            if sub_res:
                print(f"Found {len(sub_res)} subdomain(s):")
                for sub in sub_res[:20]:
                    print(f"  - {sub}")
                if len(sub_res) > 20:
                    print(f"  ... and {len(sub_res) - 20} more (view full list in output file)")
            else:
                print("No subdomains found.")
        else:
            print(sub_res)

    # 4. IP Geolocation
    if should_run("geo", req_ip=True):
        print("\n=== IP Geolocation ===")
        geo_res = ip_geolocation(ip)
        results["geo"] = geo_res
        if isinstance(geo_res, dict):
            for k, v in geo_res.items():
                print(f"{k}: {v}")
        else:
            print(geo_res)

    # 5. Reverse DNS Lookup
    if should_run("rdns", req_ip=True):
        print("\n=== Reverse DNS Lookup ===")
        rdns_res = reverse_dns_lookup(ip)
        results["rdns"] = rdns_res
        print(rdns_res)

    # 6. SSL Certificate Checker
    if should_run("ssl", req_domain=True):
        print("\n=== SSL Certificate Checker ===")
        ssl_res = check_ssl_cert(domain)
        parsed_ssl = parse_ssl_cert(ssl_res)
        results["ssl"] = parsed_ssl
        if isinstance(parsed_ssl, dict):
            for k, v in parsed_ssl.items():
                print(f"{k}: {v}")
        else:
            print(parsed_ssl)

    # 7. HTTP Security Headers
    if should_run("headers", req_domain=True):
        print("\n=== HTTP Security Headers Analysis ===")
        headers_res = analyze_security_headers(domain)
        results["headers"] = headers_res
        if isinstance(headers_res, dict):
            print(f"Target URL Analyzed: {headers_res.get('url')}\n")
            print("Present Security Headers:")
            present = headers_res.get("present", {})
            if present:
                for h, detail in present.items():
                    print(f"  [✓] {h}: {detail.get('value')}")
            else:
                print("  (None found)")

            print("\nMissing Security Headers (Recommendations):")
            missing = headers_res.get("missing", {})
            if missing:
                for h, desc in missing.items():
                    print(f"  [✗] {h} - {desc}")
            else:
                print("  (None! Great security posture.)")
        else:
            print(headers_res)

    # 8. Nmap Scan
    if should_run("nmap", req_ip=True):
        scan_target = domain if domain else ip
        print("\n=== Nmap Scan ===")
        nmap_res = nmap_scan(scan_target)
        results["nmap"] = nmap_res
        print(nmap_res)

    # File Output
    if args.output:
        try:
            if args.format == "json":
                def json_serializer(obj):
                    if isinstance(obj, (datetime.datetime, datetime.date)):
                        return obj.isoformat()
                    if hasattr(obj, '__dict__'):
                        return dict(obj)
                    return str(obj)

                with open(args.output, "w") as f:
                    json.dump(results, f, indent=4, default=json_serializer)
            else:
                txt_output = format_results_as_text(results)
                with open(args.output, "w") as f:
                    f.write(txt_output)
            print(f"\n[+] Results successfully saved to {args.output} ({args.format.upper()} format)")
        except Exception as e:
            print(f"\n[-] Failed to save output file: {e}")

if __name__ == "__main__":
    main()

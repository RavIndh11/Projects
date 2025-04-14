import whois
import socket
import requests
import subprocess

# WHOIS Lookup
def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        return f"WHOIS lookup failed: {e}"

# DNS Enumeration using dig (A, NS, MX)
def dns_enum(domain):
    try:
        records = {}
        for record_type in ["A", "NS", "MX"]:
            result = subprocess.check_output(["dig", domain, record_type, "+short"])
            records[record_type] = result.decode("utf-8").strip()
        return records
    except subprocess.CalledProcessError as e:
        return f"DNS enumeration failed: {e}"

# IP Geolocation using ipinfo.io
def ip_geolocation(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        return response.json()
    except Exception as e:
        return f"Geolocation failed: {e}"

# Reverse DNS Lookup
def reverse_dns_lookup(ip):
    try:
        return socket.gethostbyaddr(ip)
    except socket.herror as e:
        return f"Reverse DNS lookup failed: {e}"

# Nmap Scan
def nmap_scan(target):
    try:
        print(f"\n[+] Running Nmap scan on {target}...\n")
        result = subprocess.check_output(["nmap", "-T4", "-F", target])
        return result.decode("utf-8")
    except subprocess.CalledProcessError as e:
        return f"Nmap scan failed: {e}"

# Main function to call all
def main():
    domain = input("Enter domain (example.com): ")
    try:
        ip = socket.gethostbyname(domain)
    except Exception as e:
        print(f"Failed to resolve domain: {e}")
        return

    print("\n=== WHOIS Lookup ===")
    print(whois_lookup(domain))

    print("\n=== DNS Enumeration ===")
    dns_records = dns_enum(domain)
    if isinstance(dns_records, dict):
        for rtype, output in dns_records.items():
            print(f"\n{rtype} Records:\n{output if output else 'No data'}")
    else:
        print(dns_records)

    print("\n=== IP Geolocation ===")
    geo = ip_geolocation(ip)
    if isinstance(geo, dict):
        for k, v in geo.items():
            print(f"{k}: {v}")
    else:
        print(geo)

    print("\n=== Reverse DNS Lookup ===")
    print(reverse_dns_lookup(ip))

    print("\n=== Nmap Scan ===")
    print(nmap_scan(domain))

if __name__ == "__main__":
    main()

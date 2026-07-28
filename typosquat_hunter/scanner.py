import dns.resolver
import concurrent.futures
from typing import Dict, Any, List

class Scanner:
    def __init__(self, concurrency: int = 10):
        self.concurrency = concurrency
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2.0
        self.resolver.lifetime = 2.0

    def check_domain(self, domain: str) -> Dict[str, Any]:
        """
        Check A and MX records for a given domain.
        """
        result = {
            "domain": domain,
            "resolvable": False,
            "a_records": [],
            "mx_records": []
        }

        # Check A records
        try:
            answers = self.resolver.resolve(domain, 'A')
            result["a_records"] = [str(rdata) for rdata in answers]
            if result["a_records"]:
                result["resolvable"] = True
        except dns.resolver.NXDOMAIN:
            # ⚡ Bolt: Early return on NXDOMAIN.
            # If the domain itself does not exist, there's no point in checking for MX records.
            # Skipping the MX lookup halves the number of DNS queries for unregistered domains.
            return result
        except (dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NoNameservers):
            pass

        # Check MX records
        try:
            answers = self.resolver.resolve(domain, 'MX')
            result["mx_records"] = [str(rdata.exchange) for rdata in answers]
            if result["mx_records"]:
                result["resolvable"] = True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NoNameservers):
            pass

        return result

    def scan_domains(self, domains: List[str]) -> List[Dict[str, Any]]:
        """
        Scan a list of domains concurrently.
        """
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            future_to_domain = {executor.submit(self.check_domain, domain): domain for domain in domains}
            for future in concurrent.futures.as_completed(future_to_domain):
                try:
                    data = future.result()
                    if data["resolvable"]:
                        results.append(data)
                except Exception as exc:
                    pass
        return results

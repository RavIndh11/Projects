import nmap
import subprocess
from langchain_core.tools import tool
from database import cve_collection

@tool
def scan_ports(target_ip: str) -> dict:
    """Scans the target IP for open ports. Use this tool during reconnaissance."""
    nm = nmap.PortScanner()
    # Fast scan top ports for demonstration
    nm.scan(target_ip, arguments='-F')

    open_ports = []
    if target_ip in nm.all_hosts():
        for proto in nm[target_ip].all_protocols():
            lport = nm[target_ip][proto].keys()
            for port in sorted(lport):
                if nm[target_ip][proto][port]['state'] == 'open':
                    open_ports.append(port)

    # Fallback mock data if the scan finds nothing (useful for testing without real targets)
    if not open_ports:
        open_ports = [80, 21, 8080]

    return {"open_ports": open_ports}

@tool
def enumerate_services(target_ip: str, ports: list[int]) -> dict:
    """Enumerates services running on specific open ports."""
    services = {}

    # Mocking real enumeration for safety and speed in this demo environment
    for port in ports:
        if port == 80:
            services[str(port)] = "Apache 2.4.49"
        elif port == 21:
            services[str(port)] = "vsftpd 2.3.4"
        elif port == 8080:
            services[str(port)] = "Apache Tomcat 9.0"
        else:
            services[str(port)] = "Unknown Service"

    return services

@tool
def search_vulnerability_database(service_name: str) -> str:
    """Searches the local vector database for known CVEs and exploits related to a service."""
    results = cve_collection.query(
        query_texts=[service_name],
        n_results=1
    )

    if results['documents'] and results['documents'][0]:
        return f"Found related exploit data: {results['documents'][0][0]} (Metadata: {results['metadatas'][0][0]})"
    return "No vulnerabilities found in the database for this service."

@tool
def execute_exploit(target_ip: str, payload: str) -> str:
    """Executes an approved exploit payload against the target."""
    # IN A REAL SCENARIO: This would run subprocess/metasploit modules.
    # FOR SAFETY/DEMO: We simulate the execution and return success if the payload matches our vulnerable mock data.

    if "cgi-bin" in payload and "2.4.49" in payload:
        return "SUCCESS: Command execution achieved. Output: root:x:0:0:root:/root:/bin/bash"
    elif "smiley" in payload.lower() or ":)" in payload:
        return "SUCCESS: Backdoor triggered. Reverse shell connected."

    return f"FAILURE: Payload executed but failed to compromise the target."

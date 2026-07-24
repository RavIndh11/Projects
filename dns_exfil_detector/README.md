# DNS Exfiltration Detector

## Overview
DNS Exfiltration Detector is a lightweight Python-based cybersecurity tool designed to detect potential data exfiltration and tunneling over the DNS protocol. It analyzes DNS queries for suspicious patterns, such as high Shannon entropy, abnormal domain lengths, or unusual query types (e.g., TXT records).

## Problem Statement
Attackers often use DNS to exfiltrate sensitive data or establish covert command and control (C2) channels. Since DNS traffic is rarely blocked by firewalls, it provides an attractive avenue for stealthy communication. Detecting these covert channels is critical for defensive security and threat hunting.

## Features
*   **Live Traffic Analysis:** Monitor network interfaces in real-time for suspicious DNS queries.
*   **PCAP Analysis:** Analyze existing packet capture (PCAP) files for historical forensic investigations.
*   **Entropy Calculation:** Uses Shannon entropy to identify randomly generated domains or encoded data (e.g., Base64) within queries.
*   **Length Checking:** Flags domain queries that exceed normal length thresholds, a common indicator of tunneling.
*   **Query Type Detection:** Identifies abnormal DNS query types often used in exfiltration, such as `TXT` queries.
*   **Customizable Thresholds:** Users can adjust entropy and length thresholds via command-line arguments.

## Architecture
The tool relies on the `scapy` library to parse network packets.
1.  **Packet Ingestion:** Reads packets from a live interface or a PCAP file.
2.  **DNS Layer Extraction:** Filters for UDP port 53 traffic and extracts the `DNSQR` (DNS Query Record) layer.
3.  **Analysis Engine:**
    *   Extracts the queried domain name.
    *   Calculates the Shannon entropy of the query string.
    *   Measures the length of the query string.
    *   Checks the query type (e.g., type 16 for TXT).
4.  **Logging:** If the query violates the configured thresholds, an alert is logged to the console with the reason.

## Installation
It is recommended to run this tool within a Python virtual environment.

```bash
# Clone the repository
git clone <repository_url>
cd dns_exfil_detector

# Install dependencies
pip install -r requirements.txt
```

## Usage
Run the script using Python. You may need root privileges (e.g., `sudo`) to capture live traffic.

### Analyze a PCAP file:
```bash
python3 detector.py -f traffic.pcap
```

### Live Capture (default interface):
```bash
sudo python3 detector.py
```

### Live Capture (specific interface):
```bash
sudo python3 detector.py -i eth0
```

### Custom Thresholds:
```bash
# Set custom entropy threshold to 4.0 and length threshold to 60
python3 detector.py -f traffic.pcap -e 4.0 -l 60
```

## Security Considerations
*   **Privilege Escalation:** Running live captures requires elevated privileges (root/Administrator). Ensure the script is executed in a trusted environment to minimize risk.
*   **Denial of Service (DoS):** Analyzing high-volume live DNS traffic may consume significant CPU resources. The tool currently processes packets sequentially, which might lead to packet drops under heavy load.

## Limitations
*   **False Positives:** Legitimate services, such as Content Delivery Networks (CDNs) or anti-spam blocklists (DNSBL), may generate high-entropy or long domain queries, leading to false positives.
*   **Evasion:** Attackers can evade detection by using low-entropy encoding schemes, querying short segments over an extended period, or using DoH (DNS over HTTPS), which encrypts the queries.

## Future Improvements
*   Implement baseline profiling to learn "normal" DNS behavior for a specific environment and reduce false positives.
*   Add multi-threading or multiprocessing to handle high-throughput network traffic more efficiently.
*   Integrate output formatting (e.g., JSON) to feed alerts into a SIEM (Security Information and Event Management) system.
*   Support for analyzing DoH (DNS over HTTPS) traffic by integrating with a TLS decryption proxy.

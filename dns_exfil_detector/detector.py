import math
import argparse
from scapy.all import sniff, rdpcap, DNS, DNSQR, IP
from collections import Counter
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def calculate_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = Counter(data)
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy

class DNSExfilDetector:
    def __init__(self, entropy_threshold: float = 4.5, length_threshold: int = 50):
        self.entropy_threshold = entropy_threshold
        self.length_threshold = length_threshold

    def analyze_packet(self, packet) -> bool:
        """Analyze a single packet for DNS exfiltration patterns.
        Returns True if suspicious, False otherwise.
        """
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            # Extract queried domain name
            try:
                query = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
            except Exception:
                return False

            qtype = packet[DNSQR].qtype

            # Analyze query string
            entropy = calculate_entropy(query)
            length = len(query)

            is_suspicious = False
            reasons = []

            if entropy > self.entropy_threshold:
                is_suspicious = True
                reasons.append(f"High entropy ({entropy:.2f})")

            if length > self.length_threshold:
                is_suspicious = True
                reasons.append(f"Abnormal length ({length})")

            # qtype 16 is TXT
            if qtype == 16:
                is_suspicious = True
                reasons.append(f"TXT Query")

            if is_suspicious:
                src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
                logging.warning(f"Suspicious DNS Query from {src_ip}: '{query}' | Reasons: {', '.join(reasons)}")
                return True

        return False

    def analyze_pcap(self, pcap_file: str):
        """Analyze an existing PCAP file for DNS exfiltration."""
        logging.info(f"Analyzing PCAP file: {pcap_file}")
        try:
            packets = rdpcap(pcap_file)
            count = 0
            for pkt in packets:
                if self.analyze_packet(pkt):
                    count += 1
            logging.info(f"Analysis complete. Found {count} suspicious packets.")
        except FileNotFoundError:
            logging.error(f"File not found: {pcap_file}")
        except Exception as e:
            logging.error(f"Error analyzing PCAP: {e}")

    def start_live_capture(self, interface: str = None):
        """Start capturing live DNS traffic."""
        logging.info(f"Starting live capture on interface: {interface if interface else 'default'}... (Press Ctrl+C to stop)")
        try:
            sniff(filter="udp port 53", prn=self.analyze_packet, store=False, iface=interface)
        except KeyboardInterrupt:
            logging.info("Live capture stopped by user.")
        except Exception as e:
            logging.error(f"Error capturing live traffic: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS Exfiltration Detector - Detects suspicious DNS queries")
    parser.add_argument("-f", "--file", help="Path to PCAP file to analyze")
    parser.add_argument("-i", "--interface", help="Interface for live capture (e.g., eth0)")
    parser.add_argument("-e", "--entropy", type=float, default=4.5, help="Entropy threshold (default 4.5)")
    parser.add_argument("-l", "--length", type=int, default=50, help="Query length threshold (default 50)")

    args = parser.parse_args()

    detector = DNSExfilDetector(entropy_threshold=args.entropy, length_threshold=args.length)

    if args.file:
        detector.analyze_pcap(args.file)
    else:
        # Default to live capture if no file is provided
        detector.start_live_capture(args.interface)

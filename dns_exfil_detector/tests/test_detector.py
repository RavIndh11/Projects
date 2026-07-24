import pytest
from scapy.all import IP, UDP, DNS, DNSQR
from dns_exfil_detector.detector import calculate_entropy, DNSExfilDetector

def test_calculate_entropy_empty():
    assert calculate_entropy("") == 0.0

def test_calculate_entropy_low():
    # 'google.com' should have low entropy
    entropy = calculate_entropy("google.com")
    assert entropy < 3.5

def test_calculate_entropy_high():
    # A random base64 looking string should have high entropy
    entropy = calculate_entropy("cGFzc3dvcmQxMjM0NTY3ODkwLmV4YW1wbGUuY29t")
    assert entropy > 4.0

@pytest.fixture
def detector():
    return DNSExfilDetector(entropy_threshold=4.0, length_threshold=30)

def create_dns_packet(qname, qtype=1):
    """Helper function to create a mock DNS query packet."""
    return IP(src="192.168.1.100", dst="8.8.8.8") / \
           UDP(sport=12345, dport=53) / \
           DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype))

def test_analyze_packet_normal(detector):
    packet = create_dns_packet("example.com")
    assert detector.analyze_packet(packet) == False

def test_analyze_packet_high_entropy(detector):
    packet = create_dns_packet("cGFzc3dvcmQxMjM0NTY3ODkw.attacker.com")
    assert detector.analyze_packet(packet) == True

def test_analyze_packet_abnormal_length(detector):
    # Length > 30 (threshold is 30)
    packet = create_dns_packet("thisisareallylongdomainnamethatexceeds.thethreshold.com")
    assert detector.analyze_packet(packet) == True

def test_analyze_packet_txt_query(detector):
    # TXT query (qtype 16) is flagged regardless of entropy/length
    packet = create_dns_packet("example.com", qtype=16)
    assert detector.analyze_packet(packet) == True

def test_analyze_packet_not_dns(detector):
    # Packet without DNS layer
    packet = IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=12345, dport=80)
    assert detector.analyze_packet(packet) == False

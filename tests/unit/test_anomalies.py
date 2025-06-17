# tests/unit/test_anomalies.py
from packetbuddy import anomalies, parser

def test_no_anomalies_in_clean_traffic(simple_http_pcap):
    """UNIT: Ensure no anomalies are detected in benign traffic."""
    packets = parser.parse_pcap(simple_http_pcap) # Using the real parser
    detected = anomalies.detect_ssh_bruteforce(packets)
    assert len(detected) == 0

def test_detects_ssh_bruteforce(anomaly_pcap):
    """UNIT: Ensure a known SSH bruteforce is correctly identified."""
    packets = parser.parse_pcap(anomaly_pcap)
    detected = anomalies.detect_ssh_bruteforce(packets)
    assert len(detected) > 0
    # Assert on the structure of the anomaly report
    anomaly = detected[0]
    assert "description" in anomaly
    assert "source_ip" in anomaly
    assert "severity" in anomaly
    assert anomaly["severity"] == "High"

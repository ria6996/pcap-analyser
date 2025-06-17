# tests/unit/test_parser.py
from packetbuddy import parser

def test_parse_simple_pcap(simple_http_pcap):
    """UNIT: Ensure a standard pcap file is parsed correctly."""
    packets = parser.parse_pcap(simple_http_pcap)
    assert len(packets) > 0
    # Assert that a known packet type is present
    assert any("TCP" in pkt for pkt in packets)
    assert any("HTTP" in pkt for pkt in packets)

def test_parse_empty_pcap(empty_pcap):
    """EDGE CASE: Ensure an empty file results in an empty list."""
    packets = parser.parse_pcap(empty_pcap)
    assert isinstance(packets, list)
    assert len(packets) == 0

# (Additional tests for pcapng, malformed packets, etc.)

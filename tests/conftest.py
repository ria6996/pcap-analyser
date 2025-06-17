# tests/conftest.py
import pytest
from pathlib import Path

@pytest.fixture
def test_data_dir() -> Path:
    """Returns the path to the test data directory."""
    return Path(__file__).parent / "test_data"

@pytest.fixture
def simple_http_pcap(test_data_dir) -> Path:
    """Path to a simple PCAP with HTTP traffic."""
    return test_data_dir / "simple_http.pcap"

@pytest.fixture
def empty_pcap(test_data_dir) -> Path:
    """Path to an empty PCAP file."""
    return test_data_dir / "empty.pcap"

@pytest.fixture
def anomaly_pcap(test_data_dir) -> Path:
    """Path to a PCAP with a known SSH bruteforce attempt."""
    return test_data_dir / "known_anomaly_ssh_bruteforce.pcap"

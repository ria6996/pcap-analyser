# tests/integration/test_main_api.py
from fastapi.testclient import TestClient
from packetbuddy.main import app # Import the FastAPI app object

client = TestClient(app)

def test_full_upload_and_analyze_pipeline(simple_http_pcap):
    """
    INTEGRATION: Simulate a file upload and analysis via the API.
    This test covers main.py, parser.py, summarizer.py, and anomalies.py.
    """
    with open(simple_http_pcap, "rb") as f:
        response = client.post(
            "/api/v1/analyze",
            files={"capture_file": ("simple_http.pcap", f, "application/vnd.tcpdump.pcap")}
        )

    # Assert successful API call
    assert response.status_code == 200
    data = response.json()

    # Assert on the structure of the final, integrated output
    assert "summary" in data
    assert "anomalies" in data
    assert "chatbot_suggestion" in data

    # Assert on content correctness
    assert data["summary"]["protocol_distribution"]["TCP"] > 0
    assert len(data["anomalies"]) == 0 # No anomalies in this file

def test_upload_invalid_file_type():
    """INTEGRATION: Ensure the API rejects non-pcap files."""
    response = client.post(
        "/api/v1/analyze",
        files={"capture_file": ("test.txt", b"this is not a pcap", "text/plain")}
    )
    assert response.status_code == 400
    assert "Invalid file type" in response.json()["detail"]

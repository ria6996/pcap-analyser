# tests/unit/test_chatbot.py
from unittest.mock import patch
from packetbuddy import chatbot

# Mocked data that would come from the parser and summarizer
MOCK_SUMMARY = {
    "protocol_distribution": {"TCP": 50, "UDP": 50},
    "top_conversations": [("1.1.1.1", "8.8.8.8")]
}
MOCK_ANOMALIES = [{"description": "Potential SSH bruteforce detected."}]

@patch('packetbuddy.chatbot.query_llm_backend') # Mock the function that makes the internet call
def test_chatbot_response_structure(mock_query_llm):
    """UNIT: Ensure the chatbot formats the LLM response correctly."""
    # Configure the mock to return a predictable response
    mock_query_llm.return_value = "This is a test answer from the mocked LLM."

    question = "What happened in this capture?"
    response = chatbot.get_response(question, MOCK_SUMMARY, MOCK_ANOMALIES)

    # 1. Assert that our code called the LLM with a well-formed prompt
    mock_query_llm.assert_called_once()
    call_args, _ = mock_query_llm.call_args
    prompt = call_args[0]
    assert "Context from PCAP Summary:" in prompt
    assert "Potential SSH bruteforce" in prompt
    assert "User Question: What happened in this capture?" in prompt

    # 2. Assert that our code structured the final response correctly
    assert "answer" in response
    assert "sources" in response
    assert response["answer"] == "This is a test answer from the mocked LLM."
    assert "Summary" in response["sources"]
    assert "Anomalies" in response["sources"]

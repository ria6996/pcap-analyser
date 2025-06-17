# pcap-analyser
we are making an AI that can parse and analyse network packets,  detect anomalies and integrate it with a chatbot that can answer queries related to the network in human-readable language.

# OGPW (Open Graph Packet Watcher)

## Features
- Upload and analyze `.pcap` files
- Streamlit UI for visualization
- FastAPI backend for processing

## Setup
1. Clone the repo
2. `pip install -r requirements.txt`
3. Run backend: `uvicorn backend.main:app --reload`
4. Run frontend: `streamlit run frontend/app.py`

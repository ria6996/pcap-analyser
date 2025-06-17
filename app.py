import streamlit as st
import pandas as pd
import plotly.express as px
import time
from pathlib import Path

# --- Page Configuration ---
# This should be the first Streamlit command in your script.
st.set_page_config(
    page_title="Packet Buddy",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Mock Backend Functions ---
# In a real application, these functions would make API calls to your FastAPI backend.
# e.g., requests.post("http://127.0.0.1:8000/analyze", files=...)

def mock_analyze_pcap(uploaded_file):
    """
    Simulates the backend analysis pipeline (summarizer.py + anomalies.py).
    Returns a dictionary with structured results.
    """
    # Simulate processing time
    time.sleep(3) 
    
    # Simulate results
    analysis_results = {
        "metadata": {
            "file_name": uploaded_file.name,
            "file_size_mb": round(uploaded_file.size / (1024 * 1024), 2),
            "packet_count": 15721,
            "duration_sec": 225,
        },
        "summary": {
            "kpis": {
                "ue_registrations_success": 12,
                "ue_registrations_fail": 2,
                "pdu_sessions_established": 25,
            },
            "protocol_mix": {"TCP": 45, "UDP": 30, "NGAP": 15, "Other": 10},
            "top_talkers": [
                {"ip": "10.1.1.5", "bytes": 5242880},
                {"ip": "8.8.8.8", "bytes": 3145728},
                {"ip": "192.168.1.100", "bytes": 2097152},
            ]
        },
        "anomalies": [
            {
                "id": "ANOM-001",
                "title": "Potential DNS Exfiltration",
                "severity": "High",
                "explanation": "This traffic pattern matches a known DNS Exfiltration signature. The model detected unusually long query names with high entropy, which is a common tactic for tunneling data.",
                "features": {"Source IP": "10.1.1.5", "Query Length": 85, "Query Entropy": 4.5},
                "recommendation": "Isolate the source host '10.1.1.5' and perform a forensic analysis. Block the suspicious DNS domains at the firewall."
            },
            {
                "id": "ANOM-002",
                "title": "Port Scan Detected",
                "severity": "Medium",
                "explanation": "A single source IP was observed connecting to an abnormally high number of unique destination ports in a short time frame. This is characteristic of a port scanning tool like Nmap.",
                "features": {"Source IP": "192.168.1.201", "Unique Ports / 60s": 150, "SYN Ratio": 0.98},
                "recommendation": "Temporarily block the source IP '192.168.1.201' and review firewall logs for other suspicious activity from this address."
            },
            {
                "id": "ANOM-003",
                "title": "Uncommon Encrypted Traffic",
                "severity": "Low",
                "explanation": "An encrypted (TLS) flow was detected with unusual size and duration characteristics compared to the baseline of normal traffic. This could be a non-standard application or a new type of C2 traffic.",
                "features": {"Source IP": "10.1.1.5", "Destination IP": "104.22.15.89", "Flow Duration (ms)": 120000},
                "recommendation": "Monitor the destination IP. If this alert repeats, consider a deeper inspection of the traffic from the source host."
            }
        ]
    }
    return analysis_results

def mock_chat_query(query: str, context: dict):
    """Simulates the backend chat AI, which has access to the analysis results."""
    time.sleep(1)
    query = query.lower()
    anomalies = context.get("anomalies", [])
    
    if "high severity" in query:
        high_sev = [a for a in anomalies if a['severity'] == 'High']
        if high_sev:
            return f"Found {len(high_sev)} high-severity anomaly: **{high_sev[0]['title']}** from source IP `{high_sev[0]['features']['Source IP']}`. I recommend you investigate this immediately."
        else:
            return "No high-severity anomalies were detected in this capture."
    elif "top talker" in query:
        top_talker_ip = context.get("summary", {}).get("top_talkers", [{}])[0].get("ip", "N/A")
        return f"The top talker in this capture is the IP address: `{top_talker_ip}`."
    elif "recommend" in query for a in anomalies:
        if "10.1.1.5" in query:
            return "For IP `10.1.1.5`, I recommend you **isolate the host** and perform forensic analysis due to the potential DNS exfiltration."
        else:
            return "Which anomaly or IP are you asking about? For example, 'What do you recommend for 10.1.1.5?'"
    else:
        return "I can answer questions about anomalies, top talkers, and recommendations. For example, try asking: 'Show me high severity anomalies'."

# --- Helper Functions for UI ---

def highlight_severity(row):
    """Applies color to the anomaly table based on severity."""
    severity = row['Severity']
    color = ''
    if severity == 'High':
        color = 'background-color: #660000;'
    elif severity == 'Medium':
        color = 'background-color: #994c00;'
    elif severity == 'Low':
        color = 'background-color: #003366;'
    return [color] * len(row)

# --- Main Application UI ---

# Initialize session state variables
if "analysis_results" not in st.session_state:
    st.session_state.analysis_results = None
if "uploaded_file_name" not in st.session_state:
    st.session_state.uploaded_file_name = None
if "messages" not in st.session_state:
    st.session_state.messages = []

# --- Sidebar ---
with st.sidebar:
    st.title("🤖 Packet Buddy")
    st.markdown("Upload a `.pcap` or `.pcapng` file to start the analysis.")

    uploaded_file = st.file_uploader(
        "Choose a file", 
        type=["pcap", "pcapng"],
        help="Upload your network capture file for AI-powered analysis."
    )

    if uploaded_file is not None:
        # If a new file is uploaded, reset everything
        if uploaded_file.name != st.session_state.uploaded_file_name:
            st.session_state.analysis_results = None
            st.session_state.messages = []
            st.session_state.uploaded_file_name = uploaded_file.name
            
            with st.spinner(f"Analyzing `{uploaded_file.name}`... this may take a moment."):
                # This is where you would call the real backend
                st.session_state.analysis_results = mock_analyze_pcap(uploaded_file)
        
        # Display metadata preview in the sidebar
        if st.session_state.analysis_results:
            meta = st.session_state.analysis_results["metadata"]
            st.success("Analysis Complete!")
            st.subheader("Capture Metadata")
            st.info(f"""
                **File:** `{meta['file_name']}`\n
                **Size:** `{meta['file_size_mb']} MB`\n
                **Packets:** `{meta['packet_count']}`\n
                **Duration:** `{meta['duration_sec']} seconds`
            """)

# --- Main Content Area ---

st.header("Packet Analysis Dashboard")

if st.session_state.analysis_results is None:
    st.info("Welcome to Packet Buddy! Please upload a PCAP file using the sidebar to begin.")
    st.image("https://i.imgur.com/v4R3n5G.png", caption="Your personal network analysis assistant.") # A placeholder image
else:
    results = st.session_state.analysis_results
    
    # --- Dashboard Views (Tabs) ---
    summary_tab, anomaly_tab = st.tabs(["📈 Summary & KPIs", "⚠️ Anomaly Report"])

    with summary_tab:
        st.subheader("High-Level Summary")
        
        # KPIs
        kpis = results["summary"]["kpis"]
        col1, col2, col3 = st.columns(3)
        col1.metric("UE Registrations", f"{kpis['ue_registrations_success']} Success", f"-{kpis['ue_registrations_fail']} Failed", delta_color="inverse")
        col2.metric("PDU Sessions", f"{kpis['pdu_sessions_established']} Established")
        
        # Charts
        st.subheader("Visual Breakdowns")
        col1, col2 = st.columns(2)
        
        with col1:
            protocol_df = pd.DataFrame(results["summary"]["protocol_mix"].items(), columns=['Protocol', 'Percentage'])
            fig_proto = px.pie(protocol_df, names='Protocol', values='Percentage', title='Protocol Mix', hole=0.4)
            st.plotly_chart(fig_proto, use_container_width=True)

        with col2:
            talkers_df = pd.DataFrame(results["summary"]["top_talkers"])
            fig_talkers = px.bar(talkers_df, x='ip', y='bytes', title='Top 10 Talkers by Volume', labels={'ip': 'Source IP', 'bytes': 'Bytes Transferred'})
            st.plotly_chart(fig_talkers, use_container_width=True)

    with anomaly_tab:
        st.subheader("AI-Detected Anomalies")
        anomalies = results["anomalies"]
        
        if not anomalies:
            st.success("✅ No anomalies detected in this capture.")
        else:
            # Display anomalies in a styled DataFrame
            anomalies_df = pd.DataFrame(anomalies)[['title', 'severity', 'explanation']]
            anomalies_df.rename(columns={'title': 'Title', 'severity': 'Severity', 'explanation': 'Description'}, inplace=True)
            st.dataframe(
                anomalies_df.style.apply(highlight_severity, axis=1),
                use_container_width=True,
                hide_index=True
            )
            
            st.markdown("---")
            st.subheader("Anomaly Details")
            
            # Show expandable details for each anomaly
            for anom in anomalies:
                with st.expander(f"**{anom['severity']}**: {anom['title']}"):
                    st.markdown(f"**Explanation:** {anom['explanation']}")
                    st.markdown("**Contributing Features:**")
                    st.json(anom['features'])
                    st.warning(f"**Recommendation:** {anom['recommendation']}")

    # --- Chat Interface ---
    st.markdown("---")
    st.subheader("💬 Chat with Packet Pal")

    # Display chat messages from history
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # Accept user input
    if prompt := st.chat_input("Ask about this PCAP..."):
        # Add user message to chat history
        st.session_state.messages.append({"role": "user", "content": prompt})
        # Display user message in chat message container
        with st.chat_message("user"):
            st.markdown(prompt)

        # Display assistant response in chat message container
        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                response = mock_chat_query(prompt, st.session_state.analysis_results)
                st.markdown(response)
        
        # Add assistant response to chat history
        st.session_state.messages.append({"role": "assistant", "content": response})

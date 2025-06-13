from collections import defaultdict
from datetime import datetime

class Summarizer:
    """
    The Packet Buddy summarization engine. Analyzes a list of parsed packets
    and generates narrative and structured summaries of network behavior.
    """

    def __init__(self, parsed_packets: list, metadata: dict = None):
        """
        Initializes the summarizer with packet data and optional metadata.

        Args:
            parsed_packets (list): A list of dictionaries, where each dict
                                   represents a single parsed packet.
            metadata (dict, optional): Context like filename, capture tool, etc.
        """
        if not parsed_packets:
            raise ValueError("Parsed packet list cannot be empty.")

        self.packets = parsed_packets
        self.metadata = metadata or {}
        self.summary_data = {}

        # Core analysis is triggered on initialization
        self._analyze()

    def _analyze(self):
        """
        Main analysis orchestrator. Populates the internal state by
        iterating through packets and identifying flows, sessions, and events.
        """
        # Initialize containers
        self.stats = {
            'packet_count': len(self.packets),
            'start_time': self.packets[0]['timestamp'],
            'end_time': self.packets[-1]['timestamp'],
            'protocol_counts': defaultdict(int),
            'ip_pair_counts': defaultdict(int)
        }
        self.tcp_flows = defaultdict(lambda: {
            'packets': [], 'flags': set(), 'start_time': None, 'end_time': None
        })
        self.udp_sessions = defaultdict(list)
        self.dns_queries = {}
        self.ngap_procedures = defaultdict(lambda: {
            'messages': [], 'ue_id': None, 'start_time': None
        })

        # Process each packet
        for packet in self.packets:
            self._process_packet(packet)

        # Post-process collected data into final summary structures
        self._compile_summaries()

    def _process_packet(self, packet: dict):
        """Processes a single packet to update analysis state."""
        layers = packet.get('layers', {})
        timestamp = packet['timestamp']

        # General Stats
        if 'ip' in layers:
            src, dst = layers['ip']['src'], layers['ip']['dst']
            # Canonicalize IP pair to count both directions as one conversation
            pair = tuple(sorted((src, dst)))
            self.stats['ip_pair_counts'][pair] += 1

        # Per-Protocol Processing
        if 'tcp' in layers:
            self._process_tcp(packet)
        elif 'udp' in layers:
            self._process_udp(packet)
        elif 'ngap' in layers:
            self._process_ngap(packet)
        # ... other protocols like SCTP, GTP-U can be added here

    def _process_tcp(self, packet: dict):
        """Analyzes TCP-specific data."""
        self.stats['protocol_counts']['TCP'] += 1
        ip_layer = packet['layers']['ip']
        tcp_layer = packet['layers']['tcp']

        # Define flow identifier
        flow_id = tuple(sorted(((ip_layer['src'], tcp_layer['src_port']),
                                (ip_layer['dst'], tcp_layer['dst_port']))))

        flow = self.tcp_flows[flow_id]
        if not flow['start_time']:
            flow['start_time'] = packet['timestamp']
        flow['end_time'] = packet['timestamp']
        flow['packets'].append(packet)

        # Track flags for handshake/close analysis
        for flag, present in tcp_layer.get('flags', {}).items():
            if present:
                flow['flags'].add(flag.upper())
        
        # Track retransmissions (simplified logic)
        if packet.get('analysis', {}).get('is_retransmission'):
            flow['retransmissions'] = flow.get('retransmissions', 0) + 1


    def _process_udp(self, packet: dict):
        """Analyzes UDP-specific data."""
        self.stats['protocol_counts']['UDP'] += 1
        ip_layer = packet['layers']['ip']
        udp_layer = packet['layers']['udp']

        session_id = tuple(sorted(((ip_layer['src'], udp_layer['src_port']),
                                   (ip_layer['dst'], udp_layer['dst_port']))))
        self.udp_sessions[session_id].append(packet)

        if 'dns' in packet['layers']:
            self.stats['protocol_counts']['DNS'] += 1
            self._process_dns(packet)

    def _process_dns(self, packet: dict):
        """Tracks DNS queries and responses."""
        dns_layer = packet['layers']['dns']
        if 'query_name' in dns_layer: # It's a query
            self.dns_queries[dns_layer['transaction_id']] = {
                'query_name': dns_layer['query_name'],
                'query_type': dns_layer['query_type'],
                'response': 'No response found'
            }
        elif 'answers' in dns_layer: # It's a response
            if dns_layer['transaction_id'] in self.dns_queries:
                self.dns_queries[dns_layer['transaction_id']]['response'] = \
                    [a['data'] for a in dns_layer['answers']]

    def _process_ngap(self, packet: dict):
        """Analyzes 5G NGAP-specific procedures."""
        self.stats['protocol_counts']['NGAP'] += 1
        ngap_layer = packet['layers']['ngap']
        
        # Use AMF UE NGAP ID as the primary key for a UE's procedures
        ue_id = ngap_layer.get('amf_ue_ngap_id')
        if not ue_id: return # Skip messages without a UE context

        # Group by procedure code for a specific UE
        proc_code = ngap_layer['procedure_code']
        procedure_id = f"UE-{ue_id}_Proc-{proc_code}"
        
        proc = self.ngap_procedures[procedure_id]
        if not proc['start_time']:
            proc['start_time'] = packet['timestamp']
        proc['ue_id'] = ue_id
        proc['messages'].append(packet)

    def _compile_summaries(self):
        """
        Converts the analyzed state into the final structured dictionary.
        This dictionary is the single source of truth for all outputs.
        """
        # --- Metadata and Overview ---
        start_dt = datetime.fromtimestamp(self.stats['start_time'])
        end_dt = datetime.fromtimestamp(self.stats['end_time'])
        duration = self.stats['end_time'] - self.stats['start_time']

        self.summary_data['metadata'] = {
            **self.metadata,
            'capture_start_utc': start_dt.strftime('%Y-%m-%d %H:%M:%S.%f'),
            'capture_end_utc': end_dt.strftime('%Y-%m-%d %H:%M:%S.%f'),
            'duration_seconds': round(duration, 3)
        }

        top_ip_pairs = sorted(self.stats['ip_pair_counts'].items(), key=lambda x: x[1], reverse=True)
        self.summary_data['overview'] = {
            'total_packets': self.stats['packet_count'],
            'protocol_mix': dict(self.stats['protocol_counts']),
            'top_ip_pairs': [
                {'pair': f"{p[0]} <-> {p[1]}", 'count': c} for p, c in top_ip_pairs[:3]
            ]
        }
        
        # --- TCP Summary ---
        tcp_summary = {
            'total_packets': self.stats['protocol_counts'].get('TCP', 0),
            'total_flows': len(self.tcp_flows),
            'events': {'complete_handshakes': 0, 'resets': 0, 'incomplete_handshakes': 0},
            'flows': []
        }
        for flow_id, data in self.tcp_flows.items():
            flags = data['flags']
            status = "Incomplete"
            if 'SYN' in flags and 'SYN' in flags and 'ACK' in flags:
                if 'FIN' in flags or 'RST' in flags:
                    status = "Complete (Closed)"
                else:
                    status = "Established (Active)"
                tcp_summary['events']['complete_handshakes'] += 1
            else:
                tcp_summary['events']['incomplete_handshakes'] += 1

            if 'RST' in flags:
                status += " with Reset"
                tcp_summary['events']['resets'] += 1
            
            retrans = data.get('retransmissions', 0)
            
            flow_desc = f"{flow_id[0][0]}:{flow_id[0][1]} <-> {flow_id[1][0]}:{flow_id[1][1]}"
            tcp_summary['flows'].append({
                'flow_id': flow_desc,
                'status': status,
                'packet_count': len(data['packets']),
                'retransmissions': retrans,
                'summary': f"Status: {status}. Packets: {len(data['packets'])}. Retransmissions: {retrans}."
            })
        self.summary_data['tcp_analysis'] = tcp_summary

        # --- UDP Summary ---
        self.summary_data['udp_analysis'] = {
            'total_packets': self.stats['protocol_counts'].get('UDP', 0),
            'total_sessions': len(self.udp_sessions),
            'dns_summary': {
                'query_count': len(self.dns_queries),
                'queries': list(self.dns_queries.values())
            }
        }
        
        # --- NGAP Summary ---
        ngap_summary = {
            'total_messages': self.stats['protocol_counts'].get('NGAP', 0),
            'total_procedures': len(self.ngap_procedures),
            'procedures': []
        }
        for proc_id, data in self.ngap_procedures.items():
            # A simple narrative for the procedure
            first_msg_type = data['messages'][0]['layers']['ngap'].get('message_type', 'unknown')
            proc_name = data['messages'][0]['layers']['ngap'].get('procedure_name', 'Unknown Procedure')
            status = "Initiated"
            if len(data['messages']) > 1:
                last_msg_type = data['messages'][-1]['layers']['ngap'].get('message_type', 'unknown')
                if 'successfulOutcome' in last_msg_type:
                    status = "Successful"
                elif 'unsuccessfulOutcome' in last_msg_type:
                    status = "Failed"

            ngap_summary['procedures'].append({
                'procedure_id': proc_id,
                'procedure_name': proc_name,
                'ue_id': data['ue_id'],
                'message_count': len(data['messages']),
                'status': status,
                'summary': f"UE ID {data['ue_id']}: {proc_name} procedure was {status} with {len(data['messages'])} messages."
            })
        self.summary_data['ngap_analysis'] = ngap_summary


    def get_structured_summary(self) -> dict:
        """
        Returns the full analysis results as a structured dictionary.
        Ideal for consumption by other tools, UIs, or LLMs.
        """
        return self.summary_data

    def get_narrative_summary(self, verbosity: str = 'high') -> str:
        """
        Generates a human-readable, technical report in Markdown format.

        Args:
            verbosity (str): 'high' for a brief overview, 'detailed' for flow-by-flow breakdowns.
        """
        s = self.summary_data # a shortcut
        md = []

        # --- Header ---
        filename = self.metadata.get('filename', 'capture.pcap')
        md.append(f"# Packet Capture Summary: `{filename}`")
        md.append(f"**Capture Time:** {s['metadata']['capture_start_utc']} to {s['metadata']['capture_end_utc']} UTC ({s['metadata']['duration_seconds']}s)")
        
        # --- General Overview ---
        md.append("\n## General Traffic Overview")
        md.append(f"This capture contains **{s['overview']['total_packets']}** packets across **{s['tcp_analysis']['total_flows'] + s['udp_analysis']['total_sessions']}** identified TCP/UDP flows.")
        
        proto_mix_str = ", ".join([f"{p} ({c})" for p, c in s['overview']['protocol_mix'].items()])
        md.append(f"- **Protocol Mix:** {proto_mix_str}")
        
        md.append("- **Most Frequent Conversations:**")
        for pair in s['overview']['top_ip_pairs']:
            md.append(f"  - `{pair['pair']}` ({pair['count']} packets)")
        
        # --- TCP Analysis ---
        if s['tcp_analysis']['total_packets'] > 0:
            md.append("\n## TCP Analysis")
            tcp_events = s['tcp_analysis']['events']
            md.append(f"A total of **{s['tcp_analysis']['total_packets']}** TCP packets were observed across **{s['tcp_analysis']['total_flows']}** distinct flows.")
            md.append(f"- **Key Events:** {tcp_events['complete_handshakes']} complete handshakes, {tcp_events['resets']} connection resets (RST), and {tcp_events['incomplete_handshakes']} incomplete handshakes.")
            if verbosity == 'detailed':
                md.append("\n### TCP Flow Breakdown:")
                for flow in s['tcp_analysis']['flows']:
                    md.append(f"- **Flow:** `{flow['flow_id']}`\n  - {flow['summary']}")

        # --- UDP & DNS Analysis ---
        if s['udp_analysis']['total_packets'] > 0:
            md.append("\n## UDP Analysis")
            md.append(f"A total of **{s['udp_analysis']['total_packets']}** UDP packets were observed across **{s['udp_analysis']['total_sessions']}** sessions.")
            dns_summary = s['udp_analysis']['dns_summary']
            if dns_summary['query_count'] > 0:
                md.append(f"- **DNS Activity:** {dns_summary['query_count']} queries were identified.")
                if verbosity == 'detailed':
                     for q in dns_summary['queries'][:3]: # Show top 3
                         md.append(f"  - Query for `{q['query_name']}` ({q['query_type']}) -> Response: `{q['response']}`")

        # --- 5G NGAP Analysis ---
        if s['ngap_analysis']['total_messages'] > 0:
            md.append("\n## 5G Core Network Analysis (NGAP)")
            ngap = s['ngap_analysis']
            md.append(f"**{ngap['total_messages']}** NGAP messages were identified, corresponding to **{ngap['total_procedures']}** distinct procedures.")
            if verbosity == 'detailed':
                md.append("\n### NGAP Procedure Breakdown:")
                for proc in ngap['procedures']:
                    md.append(f"- {proc['summary']}")
        
        return "\n".join(md)
Use code with caution.
Python
Example Usage and Output
Here is how "Packet Buddy" would use my engine and the resulting summaries I would generate from a mock packet list.
# --- Mock Data representing output from a parser ---
mock_parsed_packets = [
    # TCP Handshake and Data Transfer
    {'timestamp': 1677615000.1, 'layers': {'ip': {'src': '10.1.1.5', 'dst': '192.168.1.100'}, 'tcp': {'src_port': 54321, 'dst_port': 443, 'flags': {'syn': True}}}},
    {'timestamp': 1677615000.2, 'layers': {'ip': {'src': '192.168.1.100', 'dst': '10.1.1.5'}, 'tcp': {'src_port': 443, 'dst_port': 54321, 'flags': {'syn': True, 'ack': True}}}},
    {'timestamp': 1677615000.3, 'layers': {'ip': {'src': '10.1.1.5', 'dst': '192.168.1.100'}, 'tcp': {'src_port': 54321, 'dst_port': 443, 'flags': {'ack': True}}}},
    {'timestamp': 1677615001.0, 'layers': {'ip': {'src': '10.1.1.5', 'dst': '192.168.1.100'}, 'tcp': {'src_port': 54321, 'dst_port': 443, 'flags': {'ack': True, 'psh': True}}}},
    {'timestamp': 1677615002.5, 'layers': {'ip': {'src': '10.1.1.5', 'dst': '192.168.1.100'}, 'tcp': {'src_port': 54321, 'dst_port': 443, 'flags': {'fin': True, 'ack': True}}}},

    # DNS Query/Response
    {'timestamp': 1677615003.0, 'layers': {'ip': {'src': '10.1.1.5', 'dst': '8.8.8.8'}, 'udp': {'src_port': 12345, 'dst_port': 53}, 'dns': {'transaction_id': '0x1234', 'query_name': 'api.packetbuddy.dev', 'query_type': 'A'}}},
    {'timestamp': 1677615003.2, 'layers': {'ip': {'src': '8.8.8.8', 'dst': '10.1.1.5'}, 'udp': {'src_port': 53, 'dst_port': 12345}, 'dns': {'transaction_id': '0x1234', 'answers': [{'name': 'api.packetbuddy.dev', 'type': 'A', 'data': '192.0.2.55'}]}}},
    
    # 5G NGAP UE Context Setup
    {'timestamp': 1677615005.1, 'layers': {'ip': {'src': '10.20.0.1', 'dst': '10.20.0.2'}, 'sctp': {}, 'ngap': {'procedure_code': 48, 'procedure_name': 'UEContextSetup', 'message_type': 'initiatingMessage', 'amf_ue_ngap_id': 101}}},
    {'timestamp': 1677615005.3, 'layers': {'ip': {'src': '10.20.0.2', 'dst': '10.20.0.1'}, 'sctp': {}, 'ngap': {'procedure_code': 48, 'procedure_name': 'UEContextSetup', 'message_type': 'successfulOutcome', 'amf_ue_ngap_id': 101}}},
]
mock_metadata = {
    'filename': '5g_traffic_sample.pcapng',
    'capture_tool': 'Wireshark 4.0.1'
}

# --- System Execution ---
if __name__ == '__main__':
    # 1. Initialize the summarizer engine
    engine = Summarizer(mock_parsed_packets, mock_metadata)
    
    # 2. Get the structured dictionary output (for a chatbot or UI)
    structured_output = engine.get_structured_summary()
    
    # 3. Get the human-readable Markdown report
    narrative_output = engine.get_narrative_summary(verbosity='detailed')

    # --- Engine Outputs ---
    
    print("--- STRUCTURED DICTIONARY (for machine consumption) ---")
    import json
    print(json.dumps(structured_output, indent=2))
    
    print("\n\n--- NARRATIVE MARKDOWN REPORT (for human consumption) ---")
    print(narrative_output)

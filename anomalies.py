import json
from collections import defaultdict
from typing import List, Dict, Any

# In a real implementation, ML models would be loaded like this:
# from joblib import load
# isolation_forest_model = load('models/isolation_forest_v1.joblib')

class AnomalyDetector:
    """
    The Packet Buddy anomaly detection engine. Analyzes structured packet data
    to find network problems, security risks, and performance bottlenecks.
    """

    def __init__(self, parsed_packets: List[Dict], config: Dict = None):
        """
        Initializes the detector with packet data and configuration.

        Args:
            parsed_packets (List[Dict]): A list of dictionaries from the parser.
            config (Dict, optional): Configuration for thresholds, model paths,
                                     and reputation lists.
        """
        if not parsed_packets:
            raise ValueError("Parsed packet list cannot be empty.")

        self.packets = parsed_packets
        self.config = config or self._get_default_config()
        self.anomalies = []
        
        # Pre-process packets into flows for efficient, stateful analysis
        self.flows = self._group_packets_into_flows()

    def _get_default_config(self) -> Dict:
        """Provides default thresholds and settings."""
        return {
            "latency_threshold_ms": 250,
            "retransmission_threshold_pct": 5,
            "suspicious_ips": {"1.2.3.4", "100.200.10.20"}, # Example reputation list
            "tcp_incomplete_handshake_timeout_s": 5.0
        }

    def _group_packets_into_flows(self) -> Dict:
        """
        Groups individual packets into TCP/UDP flows for stateful analysis.
        This is a critical pre-processing step.
        """
        flows = defaultdict(lambda: {
            'packets': [], 'protocol': None, 'start_time': float('inf'), 'end_time': 0
        })
        for packet in self.packets:
            layers = packet.get('layers', {})
            flow_id = None
            protocol = None

            if 'tcp' in layers:
                protocol = 'TCP'
                ip_l, tcp_l = layers['ip'], layers['tcp']
                flow_id = tuple(sorted(((ip_l['src'], tcp_l['src_port']),
                                        (ip_l['dst'], tcp_l['dst_port']))))
            elif 'udp' in layers:
                protocol = 'UDP'
                ip_l, udp_l = layers['ip'], layers['udp']
                flow_id = tuple(sorted(((ip_l['src'], udp_l['src_port']),
                                        (ip_l['dst'], udp_l['dst_port']))))
            
            if flow_id:
                flow = flows[flow_id]
                flow['protocol'] = protocol
                flow['packets'].append(packet)
                flow['start_time'] = min(flow['start_time'], packet['timestamp'])
                flow['end_time'] = max(flow['end_time'], packet['timestamp'])
        
        return dict(flows)

    def run_detection(self) -> List[Dict]:
        """
        Orchestrates the execution of all anomaly detection modules.
        
        Returns:
            List[Dict]: A list of found anomalies.
        """
        # 1. Rule-based / Heuristic Detectors
        self._detect_tcp_handshake_failures()
        self._detect_excessive_retransmissions()
        self._detect_latency_spikes()
        self._detect_protocol_violations()
        self._detect_suspicious_endpoints()

        # 2. ML-based Detectors (optional, based on model availability)
        # self._run_statistical_outlier_detection()
        
        return self.anomalies

    def _add_anomaly(self, type: str, severity: str, explanation: str,
                     affected_packets: List[int], affected_flow: Any = None,
                     suggestion: str = None):
        """A structured helper to add anomalies to the results list."""
        anomaly = {
            "type": type,
            "severity": severity, # e.g., "Low", "Medium", "High", "Critical"
            "explanation": explanation,
            "context": {
                "affected_packet_indices": affected_packets,
                "affected_flow_id": str(affected_flow) if affected_flow else "N/A"
            }
        }
        if suggestion:
            anomaly["suggestion"] = suggestion
        self.anomalies.append(anomaly)

    # --- Detection Modules ---

    def _detect_tcp_handshake_failures(self):
        """Finds incomplete TCP three-way handshakes."""
        for flow_id, flow_data in self.flows.items():
            if flow_data['protocol'] != 'TCP':
                continue

            flags = set()
            syn_packet_idx = -1
            syn_time = 0
            for p in flow_data['packets']:
                if p['layers']['tcp']['flags'].get('syn'):
                    flags.add('SYN')
                    if syn_packet_idx == -1: # First SYN
                        syn_packet_idx = p['frame_number']
                        syn_time = p['timestamp']
                if p['layers']['tcp']['flags'].get('ack'):
                    flags.add('ACK')
                if p['layers']['tcp']['flags'].get('rst'):
                    flags.add('RST')

            # Check for SYN with no SYN-ACK
            if 'SYN' in flags and 'ACK' not in flags:
                duration = flow_data['end_time'] - syn_time
                if duration > self.config['tcp_incomplete_handshake_timeout_s']:
                    self._add_anomaly(
                        type="TCP Handshake Failure",
                        severity="Medium",
                        explanation="A TCP connection was initiated (SYN sent) but never completed. The server did not respond with a SYN-ACK.",
                        affected_packets=[syn_packet_idx],
                        affected_flow=flow_id,
                        suggestion="Check for firewall rules blocking the destination port or if the server application is running."
                    )

    def _detect_excessive_retransmissions(self):
        """Identifies flows with a high percentage of retransmitted packets."""
        for flow_id, flow_data in self.flows.items():
            if flow_data['protocol'] != 'TCP':
                continue
            
            retrans_count = 0
            retrans_indices = []
            for p in flow_data['packets']:
                if p.get('analysis', {}).get('is_retransmission'):
                    retrans_count += 1
                    retrans_indices.append(p['frame_number'])
            
            total_packets = len(flow_data['packets'])
            if total_packets > 0:
                retrans_pct = (retrans_count / total_packets) * 100
                if retrans_pct > self.config['retransmission_threshold_pct']:
                    self._add_anomaly(
                        type="Excessive TCP Retransmissions",
                        severity="Medium",
                        explanation=f"Flow has a high rate of retransmissions ({retrans_pct:.1f}%), indicating significant packet loss or network congestion.",
                        affected_packets=retrans_indices,
                        affected_flow=flow_id,
                        suggestion="Investigate network path for congestion, faulty hardware, or misconfigured QoS."
                    )

    def _detect_latency_spikes(self):
        """Finds high RTT between request/response pairs (e.g., DNS)."""
        # Simplified example for DNS
        dns_queries = {}
        for packet in self.packets:
            if 'dns' in packet['layers']:
                dns_layer = packet['layers']['dns']
                tx_id = dns_layer['transaction_id']
                if 'query_name' in dns_layer: # Is a query
                    dns_queries[tx_id] = packet
                elif 'answers' in dns_layer and tx_id in dns_queries: # Is a response
                    query_packet = dns_queries[tx_id]
                    rtt = (packet['timestamp'] - query_packet['timestamp']) * 1000 # in ms
                    if rtt > self.config['latency_threshold_ms']:
                        self._add_anomaly(
                            type="High Application Latency",
                            severity="Low",
                            explanation=f"Detected high DNS round-trip time of {rtt:.0f}ms for query '{query_packet['layers']['dns']['query_name']}'.",
                            affected_packets=[query_packet['frame_number'], packet['frame_number']],
                            suggestion="High RTT can be caused by server load, network congestion, or long geographic distance to the server."
                        )

    def _detect_protocol_violations(self):
        """Detects packets that violate expected protocol standards."""
        for packet in self.packets:
            layers = packet['layers']
            # Example: NGAP should run over SCTP, not UDP.
            if 'ngap' in layers and 'udp' in layers:
                self._add_anomaly(
                    type="Protocol Violation",
                    severity="High",
                    explanation="An NGAP (5G Core) message was found encapsulated in UDP. NGAP's standard transport is SCTP.",
                    affected_packets=[packet['frame_number']],
                    suggestion="This could indicate a misconfigured network element or a potential malformed packet attack."
                )

    def _detect_suspicious_endpoints(self):
        """Flags communication with IPs on a reputation blacklist."""
        suspicious_ips = self.config['suspicious_ips']
        for packet in self.packets:
            if 'ip' in packet['layers']:
                src_ip, dst_ip = packet['layers']['ip']['src'], packet['layers']['ip']['dst']
                if src_ip in suspicious_ips or dst_ip in suspicious_ips:
                    bad_ip = src_ip if src_ip in suspicious_ips else dst_ip
                    self._add_anomaly(
                        type="Suspicious Endpoint Communication",
                        severity="High",
                        explanation=f"Traffic detected to/from a known suspicious IP address: {bad_ip}.",
                        affected_packets=[packet['frame_number']],
                        suggestion="Investigate the process responsible for this communication. The endpoint may be compromised or connecting to a C2 server."
                    )

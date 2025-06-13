import pyshark
import logging
from typing import List, Dict, Any, Optional, Union
from collections import defaultdict
import json
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PacketParser:
    """
    Packet parsing engine for extracting structured information from PCAP/PCAPNG files.
    Focuses on clean data extraction without analysis or summarization.
    """
    
    def __init__(self, max_packets: Optional[int] = None):
        """
        Initialize the packet parser.
        
        Args:
            max_packets: Maximum number of packets to parse (None for all)
        """
        self.max_packets = max_packets
        
    def _safe_get_attr(self, obj: Any, attr_path: str, default: Any = None) -> Any:
        """
        Safely get attribute from PyShark object, handling nested attributes.
        
        Args:
            obj: PyShark object
            attr_path: Dot-separated attribute path (e.g., 'tcp.flags.syn')
            default: Default value if attribute not found
            
        Returns:
            Attribute value or default
        """
        try:
            attrs = attr_path.split('.')
            current = obj
            for attr in attrs:
                if hasattr(current, attr):
                    current = getattr(current, attr)
                else:
                    return default
            return current
        except (AttributeError, TypeError):
            return default
    
    def _convert_value(self, value: Any) -> Any:
        """
        Convert PyShark values to clean, serializable types.
        
        Args:
            value: Raw value from PyShark
            
        Returns:
            Clean, serializable value
        """
        if value is None:
            return None
            
        # Convert to string first to handle PyShark objects
        str_value = str(value)
        
        # Try to convert numeric strings
        if str_value.isdigit():
            return int(str_value)
        
        try:
            # Try float conversion
            if '.' in str_value and str_value.replace('.', '').replace('-', '').isdigit():
                return float(str_value)
        except ValueError:
            pass
            
        # Handle boolean-like strings
        if str_value.lower() in ('true', '1'):
            return True
        elif str_value.lower() in ('false', '0'):
            return False
            
        return str_value
    
    def _extract_tcp_flags(self, packet: Any) -> Dict[str, bool]:
        """Extract TCP flags if present."""
        if not hasattr(packet, 'tcp'):
            return {}
            
        tcp_flags = {}
        flag_names = ['syn', 'ack', 'fin', 'rst', 'psh', 'urg', 'ece', 'cwr']
        
        for flag in flag_names:
            flag_value = self._safe_get_attr(packet, f'tcp.flags.{flag}', 0)
            tcp_flags[flag] = bool(self._convert_value(flag_value))
            
        return tcp_flags
    
    def _extract_protocol_specific(self, packet: Any) -> Dict[str, Any]:
        """Extract protocol-specific fields for various protocols."""
        protocol_data = {}
        
        # DNS fields
        if hasattr(packet, 'dns'):
            protocol_data['dns'] = {
                'query_name': self._convert_value(self._safe_get_attr(packet, 'dns.qry.name')),
                'query_type': self._convert_value(self._safe_get_attr(packet, 'dns.qry.type')),
                'response_code': self._convert_value(self._safe_get_attr(packet, 'dns.flags.rcode')),
                'is_response': bool(self._convert_value(self._safe_get_attr(packet, 'dns.flags.response', 0))),
                'transaction_id': self._convert_value(self._safe_get_attr(packet, 'dns.id'))
            }
        
        # HTTP fields
        if hasattr(packet, 'http'):
            protocol_data['http'] = {
                'method': self._convert_value(self._safe_get_attr(packet, 'http.request.method')),
                'uri': self._convert_value(self._safe_get_attr(packet, 'http.request.uri')),
                'host': self._convert_value(self._safe_get_attr(packet, 'http.host')),
                'status_code': self._convert_value(self._safe_get_attr(packet, 'http.response.code')),
                'user_agent': self._convert_value(self._safe_get_attr(packet, 'http.user_agent')),
                'content_type': self._convert_value(self._safe_get_attr(packet, 'http.content_type'))
            }
        
        # HTTPS/TLS fields
        if hasattr(packet, 'tls') or hasattr(packet, 'ssl'):
            tls_layer = packet.tls if hasattr(packet, 'tls') else packet.ssl
            protocol_data['tls'] = {
                'version': self._convert_value(self._safe_get_attr(packet, 'tls.version')),
                'cipher_suite': self._convert_value(self._safe_get_attr(packet, 'tls.handshake.ciphersuite')),
                'server_name': self._convert_value(self._safe_get_attr(packet, 'tls.handshake.extensions_server_name')),
                'record_type': self._convert_value(self._safe_get_attr(packet, 'tls.record.content_type'))
            }
        
        # GTP fields (for mobile networks)
        if hasattr(packet, 'gtp'):
            protocol_data['gtp'] = {
                'version': self._convert_value(self._safe_get_attr(packet, 'gtp.version')),
                'message_type': self._convert_value(self._safe_get_attr(packet, 'gtp.message_type')),
                'teid': self._convert_value(self._safe_get_attr(packet, 'gtp.teid')),
                'sequence_number': self._convert_value(self._safe_get_attr(packet, 'gtp.seq'))
            }
        
        # NGAP fields (5G protocol)
        if hasattr(packet, 'ngap'):
            protocol_data['ngap'] = {
                'procedure_code': self._convert_value(self._safe_get_attr(packet, 'ngap.procedureCode')),
                'criticality': self._convert_value(self._safe_get_attr(packet, 'ngap.criticality')),
                'message_type': self._convert_value(self._safe_get_attr(packet, 'ngap.choice'))
            }
        
        # ICMP fields
        if hasattr(packet, 'icmp'):
            protocol_data['icmp'] = {
                'type': self._convert_value(self._safe_get_attr(packet, 'icmp.type')),
                'code': self._convert_value(self._safe_get_attr(packet, 'icmp.code')),
                'checksum': self._convert_value(self._safe_get_attr(packet, 'icmp.checksum'))
            }
        
        return protocol_data
    
    def _extract_packet_data(self, packet: Any, packet_num: int) -> Dict[str, Any]:
        """
        Extract structured data from a single packet.
        
        Args:
            packet: PyShark packet object
            packet_num: Packet number for reference
            
        Returns:
            Dictionary containing packet metadata
        """
        try:
            # Basic packet information
            packet_data = {
                'packet_number': packet_num,
                'timestamp': self._convert_value(packet.sniff_timestamp),
                'length': self._convert_value(packet.length),
                'captured_length': self._convert_value(packet.captured_length),
                'protocols': [layer.layer_name for layer in packet.layers],
                'highest_layer': packet.highest_layer if hasattr(packet, 'highest_layer') else None
            }
            
            # IP layer information
            if hasattr(packet, 'ip'):
                packet_data.update({
                    'src_ip': self._convert_value(packet.ip.src),
                    'dst_ip': self._convert_value(packet.ip.dst),
                    'ip_version': self._convert_value(packet.ip.version),
                    'ttl': self._convert_value(packet.ip.ttl),
                    'ip_protocol': self._convert_value(packet.ip.proto),
                    'ip_flags': self._convert_value(self._safe_get_attr(packet, 'ip.flags')),
                    'fragment_offset': self._convert_value(self._safe_get_attr(packet, 'ip.frag_offset'))
                })
            elif hasattr(packet, 'ipv6'):
                packet_data.update({
                    'src_ip': self._convert_value(packet.ipv6.src),
                    'dst_ip': self._convert_value(packet.ipv6.dst),
                    'ip_version': 6,
                    'hop_limit': self._convert_value(packet.ipv6.hlim),
                    'ip_protocol': self._convert_value(packet.ipv6.nxt),
                    'flow_label': self._convert_value(self._safe_get_attr(packet, 'ipv6.flow'))
                })
            
            # Transport layer information
            if hasattr(packet, 'tcp'):
                packet_data.update({
                    'src_port': self._convert_value(packet.tcp.srcport),
                    'dst_port': self._convert_value(packet.tcp.dstport),
                    'transport_protocol': 'TCP',
                    'tcp_seq': self._convert_value(packet.tcp.seq),
                    'tcp_ack': self._convert_value(packet.tcp.ack),
                    'tcp_window_size': self._convert_value(packet.tcp.window_size_value),
                    'tcp_flags': self._extract_tcp_flags(packet),
                    'tcp_stream': self._convert_value(self._safe_get_attr(packet, 'tcp.stream')),
                    'tcp_retransmission': bool(self._safe_get_attr(packet, 'tcp.analysis.retransmission')),
                    'tcp_duplicate_ack': bool(self._safe_get_attr(packet, 'tcp.analysis.duplicate_ack')),
                    'tcp_fast_retransmission': bool(self._safe_get_attr(packet, 'tcp.analysis.fast_retransmission'))
                })
            elif hasattr(packet, 'udp'):
                packet_data.update({
                    'src_port': self._convert_value(packet.udp.srcport),
                    'dst_port': self._convert_value(packet.udp.dstport),
                    'transport_protocol': 'UDP',
                    'udp_length': self._convert_value(packet.udp.length),
                    'udp_checksum': self._convert_value(packet.udp.checksum),
                    'udp_stream': self._convert_value(self._safe_get_attr(packet, 'udp.stream'))
                })
            
            # Add protocol-specific data
            protocol_specific = self._extract_protocol_specific(packet)
            if protocol_specific:
                packet_data['protocol_data'] = protocol_specific
            
            # Ethernet layer information
            if hasattr(packet, 'eth'):
                packet_data.update({
                    'src_mac': self._convert_value(packet.eth.src),
                    'dst_mac': self._convert_value(packet.eth.dst),
                    'eth_type': self._convert_value(packet.eth.type)
                })
            
            return packet_data
            
        except Exception as e:
            logger.warning(f"Error parsing packet {packet_num}: {str(e)}")
            return {
                'packet_number': packet_num,
                'error': str(e),
                'timestamp': None,
                'length': None,
                'protocols': []
            }
    
    def parse_pcap(self, file_path: str, display_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Parse PCAP/PCAPNG file and extract structured packet data.
        
        Args:
            file_path: Path to PCAP/PCAPNG file
            display_filter: Optional Wireshark display filter
            
        Returns:
            List of dictionaries containing packet metadata
        """
        packets_data = []
        packet_count = 0
        
        try:
            logger.info(f"Starting to parse PCAP file: {file_path}")
            
            # Create capture object with lazy loading
            capture_kwargs = {'input_file': file_path, 'lazy': True}
            if display_filter:
                capture_kwargs['display_filter'] = display_filter
                
            capture = pyshark.FileCapture(**capture_kwargs)
            
            for packet in capture:
                packet_count += 1
                
                # Extract packet data
                packet_data = self._extract_packet_data(packet, packet_count)
                packets_data.append(packet_data)
                
                # Progress logging
                if packet_count % 1000 == 0:
                    logger.info(f"Processed {packet_count} packets...")
                
                # Check max packets limit
                if self.max_packets and packet_count >= self.max_packets:
                    logger.info(f"Reached maximum packet limit: {self.max_packets}")
                    break
            
            capture.close()
            logger.info(f"Successfully parsed {packet_count} packets from {file_path}")
            
        except Exception as e:
            logger.error(f"Error parsing PCAP file {file_path}: {str(e)}")
            raise
        
        return packets_data
    
    def extract_flows(self, packets: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group packets into logical flows/conversations.
        
        Args:
            packets: List of parsed packet dictionaries
            
        Returns:
            Dictionary with flow identifiers as keys and packet lists as values
        """
        flows = defaultdict(list)
        
        for packet in packets:
            # Skip packets with errors or missing IP info
            if 'error' in packet or not packet.get('src_ip') or not packet.get('dst_ip'):
                continue
            
            # Create flow identifier
            src_ip = packet['src_ip']
            dst_ip = packet['dst_ip']
            protocol = packet.get('transport_protocol', 'UNKNOWN')
            src_port = packet.get('src_port', 0)
            dst_port = packet.get('dst_port', 0)
            
            # Normalize flow direction (smaller IP first for consistency)
            if src_ip < dst_ip:
                flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
            else:
                flow_id = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
            
            # For TCP, also group by stream if available
            if protocol == 'TCP' and 'tcp_stream' in packet:
                flow_id = f"TCP_STREAM_{packet['tcp_stream']}"
            elif protocol == 'UDP' and 'udp_stream' in packet:
                flow_id = f"UDP_STREAM_{packet['udp_stream']}"
            
            flows[flow_id].append(packet)
        
        # Convert to regular dict and sort packets in each flow by timestamp
        result_flows = {}
        for flow_id, flow_packets in flows.items():
            # Sort by timestamp, handling None values
            sorted_packets = sorted(
                flow_packets,
                key=lambda x: x.get('timestamp') or 0
            )
            result_flows[flow_id] = sorted_packets
        
        logger.info(f"Extracted {len(result_flows)} flows from {len(packets)} packets")
        return result_flows


# Convenience functions for easy usage
def parse_pcap(file_path: str, max_packets: Optional[int] = None, 
               display_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Convenience function to parse a PCAP file.
    
    Args:
        file_path: Path to PCAP/PCAPNG file
        max_packets: Maximum number of packets to parse
        display_filter: Optional Wireshark display filter
        
    Returns:
        List of parsed packet dictionaries
    """
    parser = PacketParser(max_packets=max_packets)
    return parser.parse_pcap(file_path, display_filter=display_filter)


def extract_flows(packets: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Convenience function to extract flows from parsed packets.
    
    Args:
        packets: List of parsed packet dictionaries
        
    Returns:
        Dictionary of flows
    """
    parser = PacketParser()
    return parser.extract_flows(packets)


# Example usage and testing
if __name__ == "__main__":
    # Example usage
    try:
        # Parse a PCAP file
        packets = parse_pcap("example.pcap", max_packets=100)
        
        # Extract flows
        flows = extract_flows(packets)
        
        # Print summary
        print(f"Parsed {len(packets)} packets")
        print(f"Identified {len(flows)} flows")
        
        # Show first packet structure
        if packets:
            print("\nFirst packet structure:")
            print(json.dumps(packets[0], indent=2, default=str))
        
    except FileNotFoundError:
        print("Example PCAP file not found. Please provide a valid PCAP file path.")
    except Exception as e:
        print(f"Error: {e}")

# packet_buddy_parser.py

import pyshark
import logging
from collections import defaultdict
import json
import datetime

# --- Configuration ---
# Set up a basic logger. In a larger application, this would be configured externally.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class PacketParser:
    """
    The core packet parsing engine for Packet Buddy.

    This class uses PyShark to read PCAP/PCAPNG files and extract structured,
    JSON-serializable data from each packet without performing analysis.
    """

    def __init__(self):
        """Initializes the PacketParser."""
        logging.info("Packet Buddy Parsing Engine initialized.")

    def _get_field_value(self, obj, field_path, default=None):
        """
        Safely retrieves a nested attribute from a PyShark packet object.
        This prevents crashes from missing layers or fields.
        
        Example: _get_field_value(packet, 'tcp.analysis.retransmission')
        """
        try:
            # Iteratively access nested attributes
            value = obj
            for part in field_path.split('.'):
                value = getattr(value, part)
            
            # Convert PyShark Field objects to their native string/int value
            return self._clean_pyshark_field(value)
        except AttributeError:
            return default

    def _clean_pyshark_field(self, field):
        """
        Converts a PyShark Field object to a clean, serializable value.
        """
        # The base_obj is the raw value (str, int, etc.)
        if hasattr(field, 'base_obj'):
             return field.base_obj
        # If it's not a special PyShark object, return it as is
        return field

    def _extract_base_info(self, packet_num, packet):
        """Extracts universal packet metadata."""
        # This base structure ensures schema consistency for every packet.
        data = {
            "packet_num": packet_num,
            "timestamp": None,
            "protocol": None,
            "packet_size": None,
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
        }
        
        # Basic packet metadata
        if hasattr(packet, 'sniff_time'):
            # Convert datetime object to ISO 8601 string format for JSON compatibility
            data["timestamp"] = packet.sniff_time.isoformat()
        data["protocol"] = self._get_field_value(packet, 'highest_layer')
        data["packet_size"] = int(self._get_field_value(packet, 'length', 0))

        # IP Layer
        if 'IP' in packet:
            data["src_ip"] = self._get_field_value(packet, 'ip.src')
            data["dst_ip"] = self._get_field_value(packet, 'ip.dst')
        elif 'IPV6' in packet: # Handle IPv6 as well
            data["src_ip"] = self._get_field_value(packet, 'ipv6.src')
            data["dst_ip"] = self._get_field_value(packet, 'ipv6.dst')

        return data

    def _extract_transport_layer_info(self, packet, data):
        """Extracts TCP or UDP specific information."""
        # TCP Layer
        if 'TCP' in packet:
            data["src_port"] = int(self._get_field_value(packet, 'tcp.srcport', 0))
            data["dst_port"] = int(self._get_field_value(packet, 'tcp.dstport', 0))
            data["tcp_flags"] = self._get_field_value(packet, 'tcp.flags')
            # Use a boolean for retransmissions for cleaner data
            data["tcp_retransmission"] = self._get_field_value(packet, 'tcp.analysis.retransmission') is not None
            
            # Check for handshake packets based on flags
            flags = int(data["tcp_flags"], 16) if data["tcp_flags"] else 0
            is_syn = (flags & 0x02) != 0
            is_ack = (flags & 0x10) != 0
            data["tcp_handshake_type"] = None
            if is_syn and not is_ack:
                data["tcp_handshake_type"] = "SYN"
            elif is_syn and is_ack:
                data["tcp_handshake_type"] = "SYN-ACK"

        # UDP Layer
        elif 'UDP' in packet:
            data["src_port"] = int(self._get_field_value(packet, 'udp.srcport', 0))
            data["dst_port"] = int(self._get_field_value(packet, 'udp.dstport', 0))

    def _extract_application_layer_info(self, packet, data):
        """Extracts data from specific application layer protocols."""
        # DNS
        if 'DNS' in packet:
            data['dns_query_name'] = self._get_field_value(packet, 'dns.qry.name')
            # DNS can have multiple 'A' records, so we collect them all
            if hasattr(packet.dns, 'a'):
                data['dns_response_ips'] = [self._clean_pyshark_field(a) for a in packet.dns.a_all]
            
        # NGAP (5G Core)
        if 'NGAP' in packet:
            data['ngap_procedure_code'] = int(self._get_field_value(packet, 'ngap.procedureCode', -1))
            data['ngap_ran_ue_id'] = self._get_field_value(packet, 'ngap.ran_ue_ngap_id')
        
        # GTP (GPRS Tunneling Protocol)
        if 'GTP' in packet:
            data['gtp_message_type'] = int(self._get_field_value(packet, 'gtp.message_type', -1))
            data['gtp_teid'] = self._get_field_value(packet, 'gtp.teid')
            
        # Add other custom protocol extractors here as needed...
        # Example for HTTP:
        # if 'HTTP' in packet:
        #     data['http_host'] = self._get_field_value(packet, 'http.host')
        #     data['http_request_method'] = self._get_field_value(packet, 'http.request.method')

    def parse_pcap(self, file_path: str, packet_limit: int = None) -> list:
        """
        Reads a PCAP file and returns a list of dictionaries, one for each packet.

        Args:
            file_path (str): The path to the PCAP or PCAPNG file.
            packet_limit (int, optional): The maximum number of packets to parse.
                                          Useful for UI throttling or quick previews.

        Returns:
            list: A list of dictionaries, where each dictionary represents a parsed packet.
        """
        all_packets = []
        logging.info(f"Starting packet capture from file: {file_path}")

        try:
            # FileCapture is a generator, making it memory-efficient for large files.
            # `lazy_init=True` defers tshark startup until the first packet is accessed.
            cap = pyshark.FileCapture(file_path, lazy_init=True)
            
            for i, packet in enumerate(cap):
                if packet_limit and i >= packet_limit:
                    logging.info(f"Reached packet limit of {packet_limit}. Stopping parse.")
                    break
                
                try:
                    # 1. Start with the base, universal information
                    packet_data = self._extract_base_info(i + 1, packet)
                    
                    # 2. Add transport layer details (TCP/UDP)
                    self._extract_transport_layer_info(packet, packet_data)
                    
                    # 3. Add specific application layer details
                    self._extract_application_layer_info(packet, packet_data)
                    
                    all_packets.append(packet_data)
                
                except Exception as e:
                    # This catches unexpected errors during individual packet processing
                    logging.warning(f"Could not parse packet #{i+1}. Error: {e}. Skipping.")
                    continue
            
            cap.close()

        except pyshark.errors.TsharkNotFoundException:
            logging.error("Tshark not found! Please install it and ensure it's in your system's PATH.")
            raise
        except Exception as e:
            logging.error(f"An error occurred during file capture: {e}")
            raise

        logging.info(f"Successfully parsed {len(all_packets)} packets from {file_path}.")
        return all_packets

    def extract_flows(self, packets: list) -> dict:
        """
        Groups a list of parsed packets into logical flows (conversations).

        A flow is defined by a canonical 5-tuple:
        (protocol, smaller_ip, smaller_port, larger_ip, larger_port)

        Args:
            packets (list): A list of parsed packet dictionaries from `parse_pcap`.

        Returns:
            dict: A dictionary where keys are flow identifiers (tuples) and
                  values are lists of packets belonging to that flow.
        """
        flows = defaultdict(list)
        logging.info(f"Extracting flows from {len(packets)} packets.")
        
        for packet in packets:
            # A flow requires IP and Port information to be meaningful
            if not all([packet.get('src_ip'), packet.get('dst_ip'), packet.get('src_port'), packet.get('dst_port')]):
                continue

            # Create a canonical flow key to group bidirectional traffic
            # The key is always (proto, smaller_addr, larger_addr) where addr is (ip, port)
            addr1 = (packet['src_ip'], packet['src_port'])
            addr2 = (packet['dst_ip'], packet['dst_port'])
            
            if addr1 < addr2:
                flow_key = (packet['protocol'],) + addr1 + addr2
            else:
                flow_key = (packet['protocol'],) + addr2 + addr1
            
            flows[flow_key].append(packet)
            
        logging.info(f"Identified {len(flows)} unique flows.")
        return dict(flows) # Convert back to a standard dict for consistency


# --- Example Usage ---
if __name__ == '__main__':
    # This block demonstrates how to use the PacketParser class.
    # You would need a sample PCAP file. For this example, we'll assume
    # a file named 'sample.pcap' exists in the same directory.
    
    # Create a dummy pcap file if you don't have one (requires scapy)
    try:
        from scapy.all import wrpcap, Ether, IP, TCP, DNS, DNSQR
        
        dummy_packets = [
            Ether()/IP(src="192.168.1.10", dst="8.8.8.8")/TCP(sport=12345, dport=53, flags="S"),
            Ether()/IP(src="8.8.8.8", dst="192.168.1.10")/TCP(sport=53, dport=12345, flags="SA"),
            Ether()/IP(src="192.168.1.10", dst="8.8.8.8")/TCP(sport=12345, dport=53, flags="A"),
            Ether()/IP(src="192.168.1.10", dst="8.8.8.8")/TCP(dport=53)/DNS(rd=1, qd=DNSQR(qname="pyshark.com")),
        ]
        wrpcap("sample.pcap", dummy_packets)
        PCAP_FILE_PATH = "sample.pcap"
        
    except ImportError:
        print("Scapy not found. Cannot create a dummy pcap file.")
        print("Please place a 'sample.pcap' file in this directory to run the example.")
        PCAP_FILE_PATH = "sample.pcap" # This will likely fail if the file doesn't exist.
        
    except Exception as e:
        print(f"Error creating dummy pcap: {e}")
        PCAP_FILE_PATH = "sample.pcap"
        

    parser = PacketParser()
    
    # 1. Parse the entire PCAP file
    try:
        parsed_packets = parser.parse_pcap(PCAP_FILE_PATH)
        
        # 2. Print the first 2 parsed packets to inspect the structure
        print("\n--- Sample Parsed Packets (JSON) ---")
        print(json.dumps(parsed_packets[:2], indent=2))

        # 3. Extract and inspect flows from the parsed data
        if parsed_packets:
            packet_flows = parser.extract_flows(parsed_packets)
            
            print(f"\n--- Flow Extraction Summary ---")
            print(f"Total flows found: {len(packet_flows)}")
            
            # Print details of the first flow found
            if packet_flows:
                first_flow_key = list(packet_flows.keys())[0]
                first_flow_packets = packet_flows[first_flow_key]
                print(f"\nDetails for flow: {first_flow_key}")
                print(f"  Number of packets in this flow: {len(first_flow_packets)}")
                print(f"  First packet timestamp: {first_flow_packets[0]['timestamp']}")
                print(f"  Last packet timestamp: {first_flow_packets[-1]['timestamp']}")

    except FileNotFoundError:
        logging.error(f"ERROR: The file '{PCAP_FILE_PATH}' was not found. Please provide a valid PCAP file.")
    except pyshark.errors.TsharkNotFoundException:
        logging.error("CRITICAL: Tshark is required by PyShark but was not found.")
        logging.error("Please install Tshark (part of the Wireshark suite) and ensure it is in your system's PATH.")
    except Exception as e:
        logging.error(f"An unexpected error occurred during the demonstration: {e}")

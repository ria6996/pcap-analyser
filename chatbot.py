import re
from typing import Dict, List, Any

class ConversationalEngine:
    """
    The Packet Buddy conversational AI. Translates structured network analysis
    into natural language explanations for users.
    """

    def __init__(self, parsed_packets: List[Dict], summary: Dict, anomalies: List[Dict], system_prompt: str = None):
        """
        Initializes the engine with the full context of a capture analysis.

        Args:
            parsed_packets (List[Dict]): The raw parsed packet data.
            summary (Dict): The structured summary from the Summarizer engine.
            anomalies (List[Dict]): The list of anomalies from the AnomalyDetector.
            system_prompt (str, optional): An override for the default persona.
        """
        self.context = {
            "packets": {p['frame_number']: p for p in parsed_packets},
            "summary": summary,
            "anomalies": anomalies
        }
        self.system_prompt = system_prompt or self._get_default_prompt()

    def _get_default_prompt(self) -> str:
        """The default persona for the AI engine."""
        return (
            "You are Packet Buddy's AI assistant. Your role is to be a helpful and "
            "knowledgeable network analyst. Explain network concepts clearly and "
            "concisely, like a teacher. Always base your answers strictly on the "
            "provided context of the packet capture. If the information isn't in "
            "the context, state that you cannot answer. Use markdown to format "
            "your responses for clarity. Cite specific packet numbers as evidence."
        )

    def answer_query(self, query: str) -> str:
        """
        Processes a user's natural language query and generates a response.
        This is the main entry point for the conversational interface.
        """
        # In a real LLM implementation, the context and query would be formatted
        # and sent to the model API. Here, we simulate that with rule-based intent detection.
        intent, entities = self._determine_intent(query)

        # Route to the appropriate handler based on intent
        if intent == "summarize_capture":
            return self._handle_summary_request()
        elif intent == "list_anomalies":
            return self._handle_anomaly_request()
        elif intent == "explain_packet":
            return self._handle_packet_request(entities.get("packet_number"))
        elif intent == "explain_flow":
            return self._handle_flow_request(entities.get("ip_pair"))
        else:
            return self._handle_generic_request()

    def _determine_intent(self, query: str) -> (str, Dict):
        """
        A simplified intent recognizer. In a real system, this would be a
        more sophisticated NLU model.
        """
        query = query.lower()
        # Explain packet intent
        match = re.search(r"(explain|what is|what's in) packet (\d+)", query)
        if match:
            return "explain_packet", {"packet_number": int(match.group(2))}
        
        # Explain flow/conversation intent
        match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", query)
        if match:
            return "explain_flow", {"ip_pair": tuple(sorted((match.group(1), match.group(2))))}

        # Anomaly intent
        if any(word in query for word in ["suspicious", "wrong", "error", "problem", "anomaly", "anomalies"]):
            return "list_anomalies", {}

        # Summary intent
        if any(word in query for word in ["summary", "overview", "what happened", "summarize"]):
            return "summarize_capture", {}
            
        return "generic", {}

    # --- Response Handlers ---

    def _handle_summary_request(self) -> str:
        """Generates a high-level summary of the capture."""
        s = self.context['summary']
        total_packets = s['overview']['total_packets']
        duration = s['metadata']['duration_seconds']
        
        response = f"Of course! Here is a high-level overview of the capture:\n\n"
        response += f"- **Total Traffic:** The capture contains **{total_packets} packets** recorded over **{duration} seconds**.\n"
        
        # Combine TCP and UDP flows for a simpler count
        total_flows = s.get('tcp_analysis', {}).get('total_flows', 0) + s.get('udp_analysis', {}).get('total_sessions', 0)
        response += f"- **Conversations:** I've identified **{total_flows}** distinct conversations (or flows).\n"
        
        top_pair = s['overview']['top_ip_pairs'][0]
        response += f"- **Top Talkers:** The most active conversation was between `{top_pair['pair']}` with {top_pair['count']} packets.\n"
        
        if self.context['anomalies']:
            response += f"- **Issues Found:** I detected **{len(self.context['anomalies'])}** potential issue(s). You can ask me 'what was wrong?' to learn more."
        else:
            response += f"- **Issues Found:** I didn't detect any major anomalies in this capture."
            
        return response

    def _handle_anomaly_request(self) -> str:
        """Explains any detected anomalies."""
        anomalies = self.context['anomalies']
        if not anomalies:
            return "I've analyzed the capture and did not find any significant anomalies or suspicious activity. The traffic appears to be behaving as expected."

        response = f"Yes, I found **{len(anomalies)}** potential issue(s). Here's a breakdown:\n"
        for i, anomaly in enumerate(anomalies):
            response += f"\n**{i+1}. {anomaly['type']} (Severity: {anomaly['severity']})**\n"
            response += f"   - **What it means:** {anomaly['explanation']}\n"
            if "suggestion" in anomaly:
                response += f"   - **Possible Cause:** {anomaly['suggestion']}\n"
            response += f"   - **Evidence:** This was observed in packet(s) {anomaly['context']['affected_packet_indices']}."
        
        return response

    def _handle_packet_request(self, packet_number: int) -> str:
        """Explains the contents of a single packet."""
        if not packet_number or packet_number not in self.context['packets']:
            return f"I'm sorry, I can't find a packet with the number {packet_number} in this capture."

        packet = self.context['packets'][packet_number]
        layers = packet['layers']
        
        response = f"Certainly! Let's break down **packet {packet_number}**. This packet is part of a conversation using the **{packet.get('protocol', 'N/A')}** protocol.\n\n"
        response += "Here are the layers of the packet, from the outside in:\n"
        
        if 'ip' in layers:
            ip = layers['ip']
            response += f"- **IP Layer (The Envelope):** This is like the mailing envelope. It's addressed from source IP `{ip['src']}` to destination IP `{ip['dst']}`.\n"
        
        if 'tcp' in layers:
            tcp = layers['tcp']
            flags = [k.upper() for k, v in tcp.get('flags', {}).items() if v]
            response += f"- **TCP Layer (The Conversation Rules):** This layer manages the connection. \n"
            response += f"  - It uses port `{tcp['src_port']}` on the sending side and port `{tcp['dst_port']}` on the receiving side.\n"
            if flags:
                response += f"  - It has the `{', '.join(flags)}` flag(s) set. For example, a `SYN` flag is used to start a new connection, like knocking on a door.\n"
        
        if 'dns' in layers:
            dns = layers['dns']
            response += f"- **DNS Layer (The Address Book):** This is a Domain Name System message.\n"
            if 'query_name' in dns:
                response += f"  - It's a **query** asking for the IP address of `{dns['query_name']}`."
            elif 'answers' in dns:
                response += f"  - It's a **response**, stating that the IP address is `{dns['answers'][0]['data']}`."

        return response
    
    def _handle_flow_request(self, ip_pair: tuple) -> str:
        # This is a more advanced query that requires synthesizing information.
        # A full implementation would filter packets and re-run parts of the summary/anomaly logic.
        return f"I see you're asking about the conversation between `{ip_pair[0]}` and `{ip_pair[1]}`. I'm still learning how to summarize specific flows, but you can ask me to explain individual packets from that conversation!"

    def _handle_generic_request(self) -> str:
        """A fallback for when the intent is not understood."""
        return (
            "I'm not sure how to answer that. I can help you with questions like:\n\n"
            "- 'Give me a summary of the capture.'\n"
            "- 'Was there anything suspicious?'\n"
            "- 'Explain packet 42.'\n\n"
            "How can I help you analyze this capture?"
        )

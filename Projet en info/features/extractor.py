from scapy.all import IP, TCP, UDP, ICMP

def extract_info(packet):
    info = {
        "summary": packet.summary(),
        "src": None, "dst": None,
        "sport": None, "dport": None,
        "proto": None
    }
    if IP in packet:
        info["src"] = packet[IP].src
        info["dst"] = packet[IP].dst
    if TCP in packet:
        info["sport"] = packet[TCP].sport
        info["dport"] = packet[TCP].dport
        info["proto"] = "TCP"
    elif UDP in packet:
        info["proto"] = "UDP"
    elif ICMP in packet:
        info["proto"] = "ICMP"
    else:
        info["proto"] = "OTHER"
    return info

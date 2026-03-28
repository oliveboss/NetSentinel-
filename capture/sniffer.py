# capture/sniffer.py

from scapy.all import sniff, IP, TCP, UDP
import state.runtime_state as state

def process_packet(packet):
    if not state.packet_callback:
        return

    pkt = {
        "src": packet[IP].src if IP in packet else "-",
        "dst": packet[IP].dst if IP in packet else "-",
        "proto": "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER",
        "sport": packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else "-",
        "dport": packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else "-",
        "size": len(packet)
    }

    state.packet_callback(pkt)

def start_sniffing(iface=None):
    state.capturing = True
    sniff(
        iface=iface,
        prn=process_packet,
        store=False,
        stop_filter=lambda p: not state.capturing
    )

def stop_sniffing():
    state.capturing = False

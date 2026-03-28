import pytest
from scapy.all import IP, TCP, UDP, ICMP, Raw

from features.extractor import extract_info


# ---------------------------------------------------------
# TCP packet
# ---------------------------------------------------------
def test_extract_tcp_info():
    pkt = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1234, dport=80)

    info = extract_info(pkt)

    assert info["src"] == "1.1.1.1"
    assert info["dst"] == "2.2.2.2"
    assert info["sport"] == 1234
    assert info["dport"] == 80
    assert info["proto"] == "TCP"
    assert "TCP" in info["summary"]


# ---------------------------------------------------------
# UDP packet
# ---------------------------------------------------------
def test_extract_udp_info():
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=53)

    info = extract_info(pkt)

    assert info["src"] == "10.0.0.1"
    assert info["dst"] == "10.0.0.2"
    assert info["proto"] == "UDP"
    assert info["sport"] is None  # UDP sport non extrait dans ton code
    assert info["dport"] is None  # idem
    assert "UDP" in info["summary"]


# ---------------------------------------------------------
# ICMP packet
# ---------------------------------------------------------
def test_extract_icmp_info():
    pkt = IP(src="8.8.8.8", dst="1.1.1.1") / ICMP()

    info = extract_info(pkt)

    assert info["src"] == "8.8.8.8"
    assert info["dst"] == "1.1.1.1"
    assert info["proto"] == "ICMP"
    assert info["sport"] is None
    assert info["dport"] is None
    assert "ICMP" in info["summary"]


# ---------------------------------------------------------
# Packet without IP layer
# ---------------------------------------------------------
def test_extract_other_protocol():
    pkt = Raw(b"hello world")  # aucun IP/TCP/UDP/ICMP

    info = extract_info(pkt)

    assert info["src"] is None
    assert info["dst"] is None
    assert info["proto"] == "OTHER"
    assert "Raw" in info["summary"]
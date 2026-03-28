import pytest
from unittest.mock import patch, MagicMock

from scapy.all import IP, TCP, UDP
import capture.sniffer as sniffer
import state.runtime_state as state


# -------------------------------------------------------------------
# Fake Scapy-like packet
# -------------------------------------------------------------------
class FakeLayer:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class FakePacket:
    def __init__(self, layers, length):
        self.layers = layers
        self.length = length

    def __contains__(self, layer):
        return layer in self.layers

    def __getitem__(self, layer):
        return self.layers[layer]

    def __len__(self):
        return self.length


# -------------------------------------------------------------------
# process_packet()
# -------------------------------------------------------------------
def test_process_packet_no_callback():
    state.packet_callback = None
    packet = FakePacket({}, 100)
    sniffer.process_packet(packet)  # Should not crash


def test_process_packet_tcp():
    callback = MagicMock()
    state.packet_callback = callback

    packet = FakePacket(
        layers={
            IP: FakeLayer(src="1.1.1.1", dst="2.2.2.2"),
            TCP: FakeLayer(sport=1234, dport=80)
        },
        length=150
    )

    sniffer.process_packet(packet)

    callback.assert_called_once_with({
        "src": "1.1.1.1",
        "dst": "2.2.2.2",
        "proto": "TCP",
        "sport": 1234,
        "dport": 80,
        "size": 150
    })


def test_process_packet_udp():
    callback = MagicMock()
    state.packet_callback = callback

    packet = FakePacket(
        layers={
            IP: FakeLayer(src="10.0.0.1", dst="10.0.0.2"),
            UDP: FakeLayer(sport=5000, dport=53)
        },
        length=99
    )

    sniffer.process_packet(packet)

    callback.assert_called_once_with({
        "src": "10.0.0.1",
        "dst": "10.0.0.2",
        "proto": "UDP",
        "sport": 5000,
        "dport": 53,
        "size": 99
    })


def test_process_packet_other_protocol():
    callback = MagicMock()
    state.packet_callback = callback

    packet = FakePacket(layers={}, length=42)

    sniffer.process_packet(packet)

    callback.assert_called_once_with({
        "src": "-",
        "dst": "-",
        "proto": "OTHER",
        "sport": "-",
        "dport": "-",
        "size": 42
    })


# -------------------------------------------------------------------
# start_sniffing()
# -------------------------------------------------------------------
@patch("capture.sniffer.sniff")
def test_start_sniffing(mock_sniff):
    state.capturing = False

    sniffer.start_sniffing(iface="eth0")

    assert state.capturing is True
    mock_sniff.assert_called_once()
    kwargs = mock_sniff.call_args.kwargs

    assert kwargs["iface"] == "eth0"
    assert kwargs["prn"] == sniffer.process_packet
    assert kwargs["store"] is False
    assert callable(kwargs["stop_filter"])


# -------------------------------------------------------------------
# stop_sniffing()
# -------------------------------------------------------------------
def test_stop_sniffing():
    state.capturing = True
    sniffer.stop_sniffing()
    assert state.capturing is False
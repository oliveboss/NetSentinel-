import pytest
from unittest.mock import patch, MagicMock
import socket

from utils.interfaces import list_interfaces


# ---------------------------------------------------------
# Interface active avec IPv4 (Wi-Fi)
# ---------------------------------------------------------
@patch("utils.interfaces.psutil.net_if_stats")
@patch("utils.interfaces.psutil.net_if_addrs")
def test_list_interfaces_wifi(mock_addrs, mock_stats):
    mock_stats.return_value = {
        "Wi-Fi": MagicMock(isup=True)
    }

    mock_addrs.return_value = {
        "Wi-Fi": [
            MagicMock(family=socket.AF_INET, address="192.168.1.10")
        ]
    }

    interfaces = list_interfaces()

    assert interfaces == [("Wi-Fi (192.168.1.10)", "Wi-Fi")]


# ---------------------------------------------------------
# Interface Ethernet
# ---------------------------------------------------------
@patch("utils.interfaces.psutil.net_if_stats")
@patch("utils.interfaces.psutil.net_if_addrs")
def test_list_interfaces_ethernet(mock_addrs, mock_stats):
    mock_stats.return_value = {
        "Ethernet0": MagicMock(isup=True)
    }

    mock_addrs.return_value = {
        "Ethernet0": [
            MagicMock(family=socket.AF_INET, address="10.0.0.5")
        ]
    }

    interfaces = list_interfaces()

    assert interfaces == [("Ethernet (10.0.0.5)", "Ethernet0")]


# ---------------------------------------------------------
# Interface active mais sans IPv4 → ignorée
# ---------------------------------------------------------
@patch("utils.interfaces.psutil.net_if_stats")
@patch("utils.interfaces.psutil.net_if_addrs")
def test_interface_without_ipv4_is_ignored(mock_addrs, mock_stats):
    mock_stats.return_value = {
        "Wi-Fi": MagicMock(isup=True)
    }

    mock_addrs.return_value = {
        "Wi-Fi": [
            MagicMock(family=socket.AF_INET6, address="fe80::1")
        ]
    }

    interfaces = list_interfaces()

    assert interfaces == []


# ---------------------------------------------------------
# Interface inactive → ignorée
# ---------------------------------------------------------
@patch("utils.interfaces.psutil.net_if_stats")
@patch("utils.interfaces.psutil.net_if_addrs")
def test_interface_inactive_is_ignored(mock_addrs, mock_stats):
    mock_stats.return_value = {
        "Wi-Fi": MagicMock(isup=False)
    }

    mock_addrs.return_value = {}

    interfaces = list_interfaces()

    assert interfaces == []


# ---------------------------------------------------------
# Interface loopback / virtuelle → ignorée
# ---------------------------------------------------------
@patch("utils.interfaces.psutil.net_if_stats")
@patch("utils.interfaces.psutil.net_if_addrs")
def test_loopback_and_virtual_are_ignored(mock_addrs, mock_stats):
    mock_stats.return_value = {
        "Loopback Pseudo-Interface": MagicMock(isup=True),
        "VMware Virtual Adapter": MagicMock(isup=True),
    }

    mock_addrs.return_value = {
        "Loopback Pseudo-Interface": [
            MagicMock(family=socket.AF_INET, address="127.0.0.1")
        ],
        "VMware Virtual Adapter": [
            MagicMock(family=socket.AF_INET, address="192.168.200.1")
        ]
    }

    interfaces = list_interfaces()

    assert interfaces == []
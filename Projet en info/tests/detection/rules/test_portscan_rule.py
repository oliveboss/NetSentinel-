import pytest
from unittest.mock import patch

from detection.rules.portscan_rule import PortScanRule


# ---------------------------------------------------------
# Initialisation
# ---------------------------------------------------------
@patch("detection.rules.portscan_rule.PORTSCAN_PORT_THRESHOLD", new=3)
@patch("detection.rules.portscan_rule.PORTSCAN_TIME_WINDOW", new=10)
def test_init_loads_config():
    rule = PortScanRule()
    assert rule.time_window == 10
    assert rule.port_threshold == 3
    assert isinstance(rule.ip_ports, dict)


# ---------------------------------------------------------
# Paquet non TCP/UDP → aucun alert
# ---------------------------------------------------------
@patch("detection.rules.portscan_rule.PORTSCAN_PORT_THRESHOLD", new=3)
@patch("detection.rules.portscan_rule.PORTSCAN_TIME_WINDOW", new=10)
def test_check_non_tcp_udp_returns_none():
    rule = PortScanRule()

    pkt = {"proto": "ICMP", "src": "1.1.1.1", "dport": 80}
    assert rule.check(pkt) is None


# ---------------------------------------------------------
# Détection port scan après seuil
# ---------------------------------------------------------
@patch("detection.rules.portscan_rule.PORTSCAN_PORT_THRESHOLD", new=3)
@patch("detection.rules.portscan_rule.PORTSCAN_TIME_WINDOW", new=10)
def test_portscan_detected():
    rule = PortScanRule()

    pkt_base = {"proto": "TCP", "src": "10.0.0.1"}

    with patch("detection.rules.portscan_rule.time.time") as mock_time:
        mock_time.return_value = 1000
        assert rule.check({**pkt_base, "dport": 1000}) is None

        mock_time.return_value = 1001
        assert rule.check({**pkt_base, "dport": 1001}) is None

        mock_time.return_value = 1002
        alert = rule.check({**pkt_base, "dport": 1002})

        assert alert == "⚠ Possible Port Scan (TCP/UDP) détecté depuis 10.0.0.1"
        assert rule.ip_ports["10.0.0.1"] == {}


# ---------------------------------------------------------
# Fenêtre temporelle : ports expirés
# ---------------------------------------------------------
@patch("detection.rules.portscan_rule.PORTSCAN_PORT_THRESHOLD", new=3)
@patch("detection.rules.portscan_rule.PORTSCAN_TIME_WINDOW", new=2)
def test_old_ports_are_removed():
    rule = PortScanRule()

    pkt_base = {"proto": "UDP", "src": "8.8.8.8"}

    with patch("detection.rules.portscan_rule.time.time") as mock_time:
        mock_time.return_value = 1000
        rule.check({**pkt_base, "dport": 2000})

        mock_time.return_value = 1001
        rule.check({**pkt_base, "dport": 2001})

        mock_time.return_value = 1004
        alert = rule.check({**pkt_base, "dport": 2002})

        assert alert is None
        assert list(rule.ip_ports["8.8.8.8"].keys()) == [2002]
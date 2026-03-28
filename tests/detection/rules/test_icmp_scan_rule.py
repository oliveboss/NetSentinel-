import pytest
from unittest.mock import patch

from detection.rules.icmp_scan_rule import IcmpScanRule


# ---------------------------------------------------------
# Initialisation
# ---------------------------------------------------------
@patch("detection.rules.icmp_scan_rule.ICMP_THRESHOLD", new=3)
@patch("detection.rules.icmp_scan_rule.ICMP_TIME_WINDOW", new=10)
def test_init_loads_config():
    rule = IcmpScanRule()
    assert rule.time_window == 10
    assert rule.icmp_threshold == 3
    assert isinstance(rule.ip_icmp_times, dict)


# ---------------------------------------------------------
# Paquet non-ICMP → aucun alert
# ---------------------------------------------------------
@patch("detection.rules.icmp_scan_rule.ICMP_THRESHOLD", new=3)
@patch("detection.rules.icmp_scan_rule.ICMP_TIME_WINDOW", new=10)
def test_check_non_icmp_returns_none():
    rule = IcmpScanRule()

    pkt = {"proto": "TCP", "src": "1.1.1.1"}
    assert rule.check(pkt) is None


# ---------------------------------------------------------
# Détection ICMP après seuil
# ---------------------------------------------------------
@patch("detection.rules.icmp_scan_rule.ICMP_THRESHOLD", new=3)
@patch("detection.rules.icmp_scan_rule.ICMP_TIME_WINDOW", new=10)
def test_icmp_scan_detected():
    rule = IcmpScanRule()

    pkt = {"proto": "ICMP", "src": "10.0.0.1"}

    with patch("detection.rules.icmp_scan_rule.time.time") as mock_time:
        mock_time.return_value = 1000
        assert rule.check(pkt) is None

        mock_time.return_value = 1001
        assert rule.check(pkt) is None

        mock_time.return_value = 1002
        alert = rule.check(pkt)

        assert alert == "⚠ Scan ICMP détecté depuis 10.0.0.1"
        assert rule.ip_icmp_times["10.0.0.1"] == []


# ---------------------------------------------------------
# Fenêtre temporelle : vieux paquets expirent
# ---------------------------------------------------------
@patch("detection.rules.icmp_scan_rule.ICMP_THRESHOLD", new=3)
@patch("detection.rules.icmp_scan_rule.ICMP_TIME_WINDOW", new=2)
def test_old_packets_are_removed():
    rule = IcmpScanRule()
    pkt = {"proto": "ICMP", "src": "8.8.8.8"}

    with patch("detection.rules.icmp_scan_rule.time.time") as mock_time:
        mock_time.return_value = 1000
        rule.check(pkt)

        mock_time.return_value = 1001
        rule.check(pkt)

        mock_time.return_value = 1004
        alert = rule.check(pkt)

        assert alert is None
        assert len(rule.ip_icmp_times["8.8.8.8"]) == 1
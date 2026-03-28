import pytest
from unittest.mock import patch

from detection.rules.syn_flood_rule import SynFloodRule


# ---------------------------------------------------------
# Initialisation
# ---------------------------------------------------------
@patch("detection.rules.syn_flood_rule.SYNFLOOD_SYN_THRESHOLD", new=3)
@patch("detection.rules.syn_flood_rule.SYNFLOOD_TIME_WINDOW", new=10)
def test_init_loads_config():
    rule = SynFloodRule()
    assert rule.time_window == 10
    assert rule.syn_threshold == 3
    assert isinstance(rule.ip_syn_times, dict)


# ---------------------------------------------------------
# Paquet non TCP → aucun alert
# ---------------------------------------------------------
@patch("detection.rules.syn_flood_rule.SYNFLOOD_SYN_THRESHOLD", new=3)
@patch("detection.rules.syn_flood_rule.SYNFLOOD_TIME_WINDOW", new=10)
def test_check_non_tcp_returns_none():
    rule = SynFloodRule()

    pkt = {"proto": "UDP", "src": "1.1.1.1", "flags": "S"}
    assert rule.check(pkt) is None


# ---------------------------------------------------------
# Paquet TCP sans flag S → aucun alert
# ---------------------------------------------------------
@patch("detection.rules.syn_flood_rule.SYNFLOOD_SYN_THRESHOLD", new=3)
@patch("detection.rules.syn_flood_rule.SYNFLOOD_TIME_WINDOW", new=10)
def test_check_tcp_without_syn_returns_none():
    rule = SynFloodRule()

    pkt = {"proto": "TCP", "src": "1.1.1.1", "flags": "A"}  # ACK, pas SYN
    assert rule.check(pkt) is None


# ---------------------------------------------------------
# Détection SYN Flood après seuil
# ---------------------------------------------------------
@patch("detection.rules.syn_flood_rule.SYNFLOOD_SYN_THRESHOLD", new=3)
@patch("detection.rules.syn_flood_rule.SYNFLOOD_TIME_WINDOW", new=10)
def test_syn_flood_detected():
    rule = SynFloodRule()

    pkt = {"proto": "TCP", "src": "10.0.0.1", "flags": "S"}

    with patch("detection.rules.syn_flood_rule.time.time") as mock_time:
        mock_time.return_value = 1000
        assert rule.check(pkt) is None

        mock_time.return_value = 1001
        assert rule.check(pkt) is None

        mock_time.return_value = 1002
        alert = rule.check(pkt)

        assert alert == "⚠ Possible SYN Flood détecté depuis 10.0.0.1"
        assert rule.ip_syn_times["10.0.0.1"] == []


# ---------------------------------------------------------
# Fenêtre temporelle : vieux timestamps expirent
# ---------------------------------------------------------
@patch("detection.rules.syn_flood_rule.SYNFLOOD_SYN_THRESHOLD", new=3)
@patch("detection.rules.syn_flood_rule.SYNFLOOD_TIME_WINDOW", new=2)
def test_old_syn_packets_are_removed():
    rule = SynFloodRule()
    pkt = {"proto": "TCP", "src": "8.8.8.8", "flags": "S"}

    with patch("detection.rules.syn_flood_rule.time.time") as mock_time:
        mock_time.return_value = 1000
        rule.check(pkt)

        mock_time.return_value = 1001
        rule.check(pkt)

        mock_time.return_value = 1004
        alert = rule.check(pkt)

        assert alert is None
        assert len(rule.ip_syn_times["8.8.8.8"]) == 1
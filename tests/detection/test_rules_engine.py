import time

import pytest

from detection.rules_engine import RulesEngine


def make_pkt(**kwargs):
    base = {
        "src": "192.168.1.100",
        "dst": "192.168.1.1",
        "proto": "TCP",
        "sport": 1234,
        "dport": 80,
        "size": 60,
    }
    base.update(kwargs)
    return base


def test_rules_engine_no_alert_for_normal_traffic():
    engine = RulesEngine()
    alerts = engine.process_packet(make_pkt())
    assert alerts == []


def test_rules_engine_forbidden_port_alert():
    engine = RulesEngine()
    alerts = engine.process_packet(make_pkt(dport=22))
    assert len(alerts) == 1
    assert "port interdit" in alerts[0]


def test_rules_engine_portscan_triggers_on_threshold():
    engine = RulesEngine()
    src = "10.0.0.1"

    # 9 paquets ne déclenchent pas encore
    for i in range(9):
        p = make_pkt(src=src, dport=1000 + i)
        assert engine.process_packet(p) == []

    # 10e paquet => alerte
    p = make_pkt(src=src, dport=2000)
    alerts = engine.process_packet(p)
    assert len(alerts) == 1
    assert "Port Scan" in alerts[0] or "Port Scan" in alerts[0].replace("⚠ ", "")


def test_rules_engine_syn_flood_triggers_on_threshold():
    engine = RulesEngine()
    src = "10.0.0.2"

    for i in range(19):
        p = make_pkt(src=src, proto="TCP", dport=80, flags="S")
        assert engine.process_packet(p) == []

    p_last = make_pkt(src=src, proto="TCP", dport=80, flags="S")
    alerts = engine.process_packet(p_last)
    assert len(alerts) == 1
    assert "SYN Flood" in alerts[0] or "SYN Flood" in alerts[0].replace("⚠ ", "")


def test_rules_engine_icmp_scan_triggers_on_threshold():
    engine = RulesEngine()
    src = "10.0.0.3"

    for i in range(4):
        p = make_pkt(src=src, proto="ICMP", dport=0)
        assert engine.process_packet(p) == []

    p_last = make_pkt(src=src, proto="ICMP", dport=0)
    alerts = engine.process_packet(p_last)
    assert len(alerts) == 1
    assert "ICMP" in alerts[0]
import pytest
from unittest.mock import MagicMock, patch

from detection.rules_engine import RulesEngine


# ---------------------------------------------------------
# Initialisation
# ---------------------------------------------------------
@patch("detection.rules_engine.ForbiddenPortsRule")
@patch("detection.rules_engine.IcmpScanRule")
@patch("detection.rules_engine.SynFloodRule")
@patch("detection.rules_engine.PortScanRule")
def test_init_creates_all_rules(mock_portscan, mock_syn, mock_icmp, mock_forbidden):
    engine = RulesEngine()

    # Vérifie que les règles sont instanciées dans le bon ordre
    assert len(engine.rules) == 4
    assert engine.rules[0] == mock_portscan.return_value
    assert engine.rules[1] == mock_syn.return_value
    assert engine.rules[2] == mock_icmp.return_value
    assert engine.rules[3] == mock_forbidden.return_value

    # Vérifie que chaque règle a bien été instanciée
    mock_portscan.assert_called_once()
    mock_syn.assert_called_once()
    mock_icmp.assert_called_once()
    mock_forbidden.assert_called_once()


# ---------------------------------------------------------
# process_packet() — collecte des alertes
# ---------------------------------------------------------
@patch("detection.rules_engine.ForbiddenPortsRule")
@patch("detection.rules_engine.IcmpScanRule")
@patch("detection.rules_engine.SynFloodRule")
@patch("detection.rules_engine.PortScanRule")
def test_process_packet_collects_alerts(mock_portscan, mock_syn, mock_icmp, mock_forbidden):
    # Mock des règles
    mock_portscan.return_value.check.return_value = None
    mock_syn.return_value.check.return_value = "ALERT_SYN"
    mock_icmp.return_value.check.return_value = None
    mock_forbidden.return_value.check.return_value = "ALERT_FORBIDDEN"

    engine = RulesEngine()

    pkt = {"src": "1.1.1.1"}

    alerts = engine.process_packet(pkt)

    # Vérifie que chaque règle a été appelée
    mock_portscan.return_value.check.assert_called_once_with(pkt)
    mock_syn.return_value.check.assert_called_once_with(pkt)
    mock_icmp.return_value.check.assert_called_once_with(pkt)
    mock_forbidden.return_value.check.assert_called_once_with(pkt)

    # Vérifie que seules les alertes non-nulles sont retournées
    assert alerts == ["ALERT_SYN", "ALERT_FORBIDDEN"]
import pytest
from unittest.mock import patch

from detection.rules.forbidden_ports_rule import ForbiddenPortsRule


# ---------------------------------------------------------
# Initialisation
# ---------------------------------------------------------
@patch("detection.rules.forbidden_ports_rule.FORBIDDEN_PORTS", [22, 23, 3389])
def test_init_loads_forbidden_ports():
    rule = ForbiddenPortsRule()
    assert rule.forbidden_ports == {22, 23, 3389}


# ---------------------------------------------------------
# Port interdit
# ---------------------------------------------------------
@patch("detection.rules.forbidden_ports_rule.FORBIDDEN_PORTS", [22, 23, 3389])
def test_check_detects_forbidden_port():
    rule = ForbiddenPortsRule()

    pkt = {
        "src": "192.168.1.50",
        "dport": 22
    }

    alert = rule.check(pkt)

    assert alert == "⚠ Tentative de connexion sur port interdit 22 depuis 192.168.1.50"


# ---------------------------------------------------------
# Port autorisé
# ---------------------------------------------------------
@patch("detection.rules.forbidden_ports_rule.FORBIDDEN_PORTS", [22, 23, 3389])
def test_check_allows_safe_port():
    rule = ForbiddenPortsRule()

    pkt = {
        "src": "192.168.1.50",
        "dport": 8080
    }

    alert = rule.check(pkt)

    assert alert is None
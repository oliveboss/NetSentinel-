import pytest

from ui.stats_panel import StatsPanel


@pytest.mark.skipif(
    pytest.importorskip("tkinter") is None,
    reason="tkinter non disponible"
)
def test_stats_panel_update_counters_and_graph(monkeypatch, tk_root):
    panel = StatsPanel(tk_root)
    panel.update_counters(5, 2, 1)
    assert "Packets capturés : 5" in panel.packets_label.cget("text")

    panel.update_graph(10)
    panel.update_graph(5)

    # generate pie update with fake table
    class FakeTable:
        def get_children(self):
            return ["a", "b"]
        def item(self, i, k):
            if i == "a":
                return {"values": ("1.1.1.1", "2.2.2.2", "TCP", 1, 2, 64)}
            return {"values": ("1.1.1.1", "2.2.2.2", "UDP", 1, 2, 64)}

    panel.update_protocols(FakeTable())


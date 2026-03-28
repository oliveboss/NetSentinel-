from ui.widgets.theme import (
    BG_DARK,
    BG_CARD,
    BG_CANVAS,
    TEXT_NORMAL,
    TEXT_MUTED,
    COLOR_TCP,
    COLOR_UDP,
    COLOR_ICMP,
    COLOR_OTHER,
    COLOR_ALERT,
    COLOR_INFO,
    COLOR_OK,
    COLOR_STOPPED,
    BTN_START,
    BTN_STOP,
    GRAPH_BAR,
)


def test_theme_colors_constants():
    assert BG_DARK == "#1e1e1e"
    assert BG_CARD == "#252526"
    assert BG_CANVAS == "#151515"

    assert TEXT_NORMAL == "white"
    assert TEXT_MUTED == "#cccccc"

    assert COLOR_TCP == "#4da6ff"
    assert COLOR_UDP == "#b366ff"
    assert COLOR_ICMP == "#66ff66"
    assert COLOR_OTHER == "#888888"

    assert COLOR_ALERT == "#ff3333"
    assert COLOR_INFO == "#ffaa00"
    assert COLOR_OK == "lime"
    assert COLOR_STOPPED == "gray"

    assert BTN_START == "#0e639c"
    assert BTN_STOP == "#c50f1f"
    assert GRAPH_BAR == "#4da6ff"

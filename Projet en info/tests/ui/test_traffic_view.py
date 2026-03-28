import pytest
from unittest.mock import MagicMock, patch
import tkinter as tk

from ui.traffic_view import TrafficView


# ---------------------------------------------------------
# INIT
# ---------------------------------------------------------
@patch("ui.traffic_view.ttk.Treeview")
def test_init_creates_widgets(mock_tree, tk_root):
    view = TrafficView(tk_root)
    assert view.filter_var.get() == ""
    assert view.auto_scroll is True
    mock_tree.assert_called_once()


# ---------------------------------------------------------
# ADD PACKET
# ---------------------------------------------------------
@patch("ui.traffic_view.ttk.Treeview")
def test_add_packet_inserts_row(mock_tree, tk_root):
    tree = MagicMock()
    mock_tree.return_value = tree

    view = TrafficView(tk_root)
    view.auto_scroll = True

    pkt = {
        "src": "1.1.1.1",
        "dst": "2.2.2.2",
        "proto": "TCP",
        "sport": 1234,
        "dport": 80,
        "size": 60
    }

    view.add_packet(pkt)

    tree.insert.assert_called_once()
    tree.yview_moveto.assert_called_once_with(1.0)
    assert len(view._all_rows) == 1


# ---------------------------------------------------------
# FILTER
# ---------------------------------------------------------
@patch("ui.traffic_view.ttk.Treeview")
def test_filter_applies_correctly(mock_tree, tk_root):
    tree = MagicMock()
    mock_tree.return_value = tree

    view = TrafficView(tk_root)

    view._all_rows = [
        ("1.1.1.1", "2.2.2.2", "TCP", 1234, 80, 60),
        ("8.8.8.8", "1.1.1.1", "UDP", None, None, 40),
    ]

    view.filter_var.set("tcp")
    view._apply_filter()

    assert tree.insert.call_count == 1


# ---------------------------------------------------------
# CLEAR
# ---------------------------------------------------------
@patch("ui.traffic_view.ttk.Treeview")
def test_clear_removes_all(mock_tree, tk_root):
    tree = MagicMock()
    tree.get_children.return_value = ["row1", "row2"]
    mock_tree.return_value = tree

    view = TrafficView(tk_root)
    view._all_rows = [1, 2]

    view.clear()

    assert view._all_rows == []
    tree.delete.assert_any_call("row1")
    tree.delete.assert_any_call("row2")


# ---------------------------------------------------------
# EXPORT CSV
# ---------------------------------------------------------
@patch("ui.traffic_view.open", create=True)
@patch("ui.traffic_view.csv.writer")
def test_export_csv(mock_writer, mock_open, tk_root):
    view = TrafficView(tk_root)
    view._all_rows = [
        ("1.1.1.1", "2.2.2.2", "TCP", 1234, 80, 60)
    ]

    view.export_csv("test.csv")

    mock_open.assert_called_once()
    mock_writer.return_value.writerow.assert_any_call(
        ["src", "dst", "proto", "sport", "dport", "size"]
    )


# ---------------------------------------------------------
# SORT COLUMN
# ---------------------------------------------------------
@patch("ui.traffic_view.ttk.Treeview")
def test_sort_column(mock_tree, tk_root):
    tree = MagicMock()
    tree.get_children.return_value = ["i1", "i2"]
    tree.set.side_effect = lambda item, col: "2" if item == "i1" else "1"
    mock_tree.return_value = tree

    view = TrafficView(tk_root)
    view._sort_column("sport", False)

    tree.move.assert_any_call("i2", "", 0)
    tree.move.assert_any_call("i1", "", 1)


# ---------------------------------------------------------
# COPY SELECTION (corrigé)
# ---------------------------------------------------------
@patch("ui.traffic_view.ttk.Treeview")
def test_copy_selection(mock_tree, tk_root):
    tree = MagicMock()
    tree.selection.return_value = ["row1"]
    tree.item.return_value = ("a", "b", "c")
    mock_tree.return_value = tree

    view = TrafficView(tk_root)

    view.clipboard_clear = MagicMock()
    view.clipboard_append = MagicMock()

    view._copy_selection()

    view.clipboard_clear.assert_any_call()
    view.clipboard_append.assert_any_call("a\tb\tc")


# ---------------------------------------------------------
# USER SCROLL
# ---------------------------------------------------------
@patch("ui.traffic_view.ttk.Treeview")
def test_on_user_scroll(mock_tree, tk_root):
    tree = MagicMock()
    tree.yview.return_value = (0.0, 0.5)
    mock_tree.return_value = tree

    view = TrafficView(tk_root)
    view.auto_scroll_var.set(True)

    event = MagicMock()
    view._on_user_scroll(event)

    assert view.auto_scroll is False


# ---------------------------------------------------------
# SELECT ROW (NORMAL)
# ---------------------------------------------------------
@patch("ui.traffic_view.ttk.Treeview")
def test_select_row_normal(mock_tree, tk_root):
    tree = MagicMock()
    tree.identify_row.return_value = "row1"
    mock_tree.return_value = tree

    view = TrafficView(tk_root)

    event = MagicMock()
    event.y = 10
    event.state = 0

    view._select_row(event)

    tree.selection_set.assert_called_once_with("row1")


# ---------------------------------------------------------
# SELECT ROW (SHIFT)
# ---------------------------------------------------------
@patch("ui.traffic_view.ttk.Treeview")
def test_select_row_shift(mock_tree, tk_root):
    tree = MagicMock()
    tree.identify_row.return_value = "row1"
    mock_tree.return_value = tree

    view = TrafficView(tk_root)

    event = MagicMock()
    event.y = 10
    event.state = 0x0001

    view._select_row(event)

    tree.selection_add.assert_called_once_with("row1")


# ---------------------------------------------------------
# SELECT ROW (CTRL)
# ---------------------------------------------------------
@patch("ui.traffic_view.ttk.Treeview")
def test_select_row_ctrl(mock_tree, tk_root):
    tree = MagicMock()
    tree.identify_row.return_value = "row1"
    mock_tree.return_value = tree

    view = TrafficView(tk_root)

    event = MagicMock()
    event.y = 10
    event.state = 0x0004

    view._select_row(event)

    tree.selection_toggle.assert_called_once_with("row1")


# ---------------------------------------------------------
# CONTEXT MENU
# ---------------------------------------------------------
@patch("ui.traffic_view.tk.Menu")
@patch("ui.traffic_view.ttk.Treeview")
def test_show_context_menu(mock_tree, mock_menu, tk_root):
    tree = MagicMock()
    tree.identify_row.return_value = "row1"
    mock_tree.return_value = tree

    menu = MagicMock()
    mock_menu.return_value = menu

    view = TrafficView(tk_root)

    event = MagicMock()
    event.y = 10
    event.x_root = 100
    event.y_root = 200

    view._show_context_menu(event)

    tree.selection_set.assert_called_once_with("row1")
    menu.tk_popup.assert_called_once_with(100, 200)
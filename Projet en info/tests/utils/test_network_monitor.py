import pytest
from unittest.mock import MagicMock, patch

from utils.network_monitor import NetworkMonitor


# ---------------------------------------------------------
# start()
# ---------------------------------------------------------
@patch("utils.network_monitor.threading.Thread")
def test_start_creates_thread(mock_thread):
    iface_getter = MagicMock()
    ui_callback = MagicMock()

    monitor = NetworkMonitor(iface_getter, ui_callback)

    monitor.start()

    assert monitor._running is True
    mock_thread.assert_called_once()
    mock_thread.return_value.start.assert_called_once()


@patch("utils.network_monitor.threading.Thread")
def test_start_does_not_restart_if_running(mock_thread):
    iface_getter = MagicMock()
    ui_callback = MagicMock()

    monitor = NetworkMonitor(iface_getter, ui_callback)
    monitor._running = True

    monitor.start()

    mock_thread.assert_not_called()


# ---------------------------------------------------------
# stop()
# ---------------------------------------------------------
def test_stop_sets_running_false():
    monitor = NetworkMonitor(MagicMock(), MagicMock())
    monitor._running = True

    monitor.stop()

    assert monitor._running is False


# ---------------------------------------------------------
# _monitor_loop() — interface = Any
# ---------------------------------------------------------
@patch("utils.network_monitor.time.sleep", return_value=None)
@patch("utils.network_monitor.psutil.net_io_counters")
def test_monitor_loop_any_interface(mock_counters, mock_sleep):
    # Fake counters
    mock_counters.side_effect = [
        {"eth0": MagicMock(packets_recv=10)},  # prev
        {"eth0": MagicMock(packets_recv=20)},  # current
    ]

    iface_getter = MagicMock(return_value="Any")
    ui_callback = MagicMock()

    monitor = NetworkMonitor(iface_getter, ui_callback, interval=0.01)
    monitor._running = True

    # On arrête après un cycle
    def stop_after_one(*args, **kwargs):
        monitor._running = False

    mock_sleep.side_effect = stop_after_one

    monitor._monitor_loop()

    ui_callback.assert_called_once_with("Any interface", "gray")


# ---------------------------------------------------------
# _monitor_loop() — trafic détecté
# ---------------------------------------------------------
@patch("utils.network_monitor.time.sleep", return_value=None)
@patch("utils.network_monitor.psutil.net_io_counters")
def test_monitor_loop_traffic_detected(mock_counters, mock_sleep):
    mock_counters.side_effect = [
        {"eth0": MagicMock(packets_recv=10)},  # prev
        {"eth0": MagicMock(packets_recv=15)},  # current → trafic
    ]

    iface_getter = MagicMock(return_value="eth0")
    ui_callback = MagicMock()

    monitor = NetworkMonitor(iface_getter, ui_callback, interval=0.01)
    monitor._running = True

    def stop_after_one(*args, **kwargs):
        monitor._running = False

    mock_sleep.side_effect = stop_after_one

    monitor._monitor_loop()

    ui_callback.assert_called_once_with("Traffic detected", "lime")


# ---------------------------------------------------------
# _monitor_loop() — pas de trafic
# ---------------------------------------------------------
@patch("utils.network_monitor.time.sleep", return_value=None)
@patch("utils.network_monitor.psutil.net_io_counters")
def test_monitor_loop_no_traffic(mock_counters, mock_sleep):
    mock_counters.side_effect = [
        {"eth0": MagicMock(packets_recv=10)},  # prev
        {"eth0": MagicMock(packets_recv=10)},  # current → pas de trafic
    ]

    iface_getter = MagicMock(return_value="eth0")
    ui_callback = MagicMock()

    monitor = NetworkMonitor(iface_getter, ui_callback, interval=0.01)
    monitor._running = True

    def stop_after_one(*args, **kwargs):
        monitor._running = False

    mock_sleep.side_effect = stop_after_one

    monitor._monitor_loop()

    ui_callback.assert_called_once_with("No traffic", "red")
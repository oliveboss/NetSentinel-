import pytest
from unittest.mock import MagicMock, patch

from controller.capture_controller import CaptureController
import state.runtime_state as state


@pytest.fixture
def iface_getter():
    return MagicMock(return_value="eth0")


@pytest.fixture
def ui_traffic():
    return MagicMock()


@pytest.fixture
def ui_monitor():
    return MagicMock()


@pytest.fixture
def ui_alert():
    return MagicMock()


@pytest.fixture
def ui_info():
    return MagicMock()


# ---------------------------------------------------------
# INITIALISATION
# ---------------------------------------------------------
@patch("controller.capture_controller.NetworkMonitor")
@patch("controller.capture_controller.RulesEngine")
def test_init_sets_callbacks(mock_rules, mock_monitor, iface_getter, ui_traffic, ui_monitor, ui_alert, ui_info):
    mock_monitor.return_value.start = MagicMock()

    controller = CaptureController(
        iface_getter,
        ui_traffic,
        ui_monitor,
        ui_alert,
        ui_info
    )

    assert state.packet_callback == controller._handle_packet
    mock_rules.assert_called_once()
    mock_monitor.assert_called_once()
    mock_monitor.return_value.start.assert_called_once()


# ---------------------------------------------------------
# _handle_packet()
# ---------------------------------------------------------
@patch("controller.capture_controller.NetworkMonitor")
@patch("controller.capture_controller.RulesEngine")
def test_handle_packet_calls_callbacks(mock_rules, mock_monitor, iface_getter, ui_traffic, ui_monitor, ui_alert, ui_info):
    mock_monitor.return_value.start = MagicMock()
    mock_rules.return_value.process_packet.return_value = ["ALERT1", "ALERT2"]

    controller = CaptureController(
        iface_getter,
        ui_traffic,
        ui_monitor,
        ui_alert,
        ui_info
    )

    pkt = {"src": "1.1.1.1"}
    controller._handle_packet(pkt)

    ui_traffic.assert_called_once_with(pkt)
    ui_alert.assert_any_call("ALERT1")
    ui_alert.assert_any_call("ALERT2")


# ---------------------------------------------------------
# start_capture()
# ---------------------------------------------------------
@patch("controller.capture_controller.threading.Thread")
@patch("controller.capture_controller.start_sniffing")
@patch("controller.capture_controller.NetworkMonitor")
@patch("controller.capture_controller.RulesEngine")
def test_start_capture_starts_thread(mock_rules, mock_monitor, mock_sniff, mock_thread,
                                     iface_getter, ui_traffic, ui_monitor, ui_alert, ui_info):

    mock_monitor.return_value.start = MagicMock()
    state.capturing = False

    controller = CaptureController(
        iface_getter, ui_traffic, ui_monitor, ui_alert, ui_info
    )

    mock_thread_instance = MagicMock()
    mock_thread.return_value = mock_thread_instance

    controller.start_capture()

    ui_info.assert_any_call("▶ Démarrage de la capture sur eth0")
    mock_thread.assert_called_once()
    mock_thread_instance.start.assert_called_once()


@patch("controller.capture_controller.threading.Thread")
@patch("controller.capture_controller.start_sniffing")
@patch("controller.capture_controller.NetworkMonitor")
@patch("controller.capture_controller.RulesEngine")
def test_start_capture_does_not_restart_if_running(mock_rules, mock_monitor, mock_sniff, mock_thread,
                                                   iface_getter, ui_traffic, ui_monitor, ui_alert, ui_info):

    mock_monitor.return_value.start = MagicMock()
    state.capturing = True

    controller = CaptureController(
        iface_getter, ui_traffic, ui_monitor, ui_alert, ui_info
    )

    controller.start_capture()

    ui_info.assert_any_call("⚠ Capture déjà en cours")
    mock_thread.assert_not_called()
    mock_sniff.assert_not_called()


# ---------------------------------------------------------
# stop_capture()
# ---------------------------------------------------------
@patch("controller.capture_controller.stop_sniffing")
@patch("controller.capture_controller.NetworkMonitor")
@patch("controller.capture_controller.RulesEngine")
def test_stop_capture(mock_rules, mock_monitor, mock_stop, iface_getter, ui_traffic, ui_monitor, ui_alert, ui_info):

    mock_monitor.return_value.start = MagicMock()

    controller = CaptureController(
        iface_getter, ui_traffic, ui_monitor, ui_alert, ui_info
    )

    controller.set_capture_status_callback(MagicMock())

    controller.stop_capture()

    mock_stop.assert_called_once()
    ui_info.assert_any_call("⏹ Capture arrêtée")
    controller.capture_status_callback.assert_called_once_with(False)
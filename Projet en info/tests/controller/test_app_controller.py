import pytest
from unittest.mock import patch, MagicMock

import controller.app_controller as app
import state.runtime_state as state


# ---------------------------------------------------------
# start_capture()
# ---------------------------------------------------------
@patch("controller.app_controller.threading.Thread")
@patch("controller.app_controller.start_sniffing")
def test_start_capture_starts_thread(mock_start_sniffing, mock_thread):
    state.capturing = False

    mock_thread_instance = MagicMock()
    mock_thread.return_value = mock_thread_instance

    app.start_capture(iface="eth0")

    # capturing doit être activé
    assert state.capturing is True

    # un thread doit être créé
    mock_thread.assert_called_once()

    # le thread doit cibler start_sniffing
    args, kwargs = mock_thread.call_args
    assert kwargs["target"] == mock_start_sniffing
    assert kwargs["daemon"] is True

    # le thread doit être démarré
    mock_thread_instance.start.assert_called_once()


@patch("controller.app_controller.threading.Thread")
@patch("controller.app_controller.start_sniffing")
def test_start_capture_does_not_restart_if_already_running(mock_start_sniffing, mock_thread):
    state.capturing = True  # déjà en capture

    app.start_capture(iface="eth0")

    # Aucun thread ne doit être créé
    mock_thread.assert_not_called()
    mock_start_sniffing.assert_not_called()


# ---------------------------------------------------------
# stop_capture()
# ---------------------------------------------------------
def test_stop_capture():
    state.capturing = True

    app.stop_capture()

    assert state.capturing is False
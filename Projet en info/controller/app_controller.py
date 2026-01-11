import threading
from capture.sniffer import start_sniffing
import state.runtime_state as state

_sniff_thread = None

def start_capture(iface=None, bpf=None):
    global _sniff_thread

    if state.capturing:
        return

    state.capturing = True

    _sniff_thread = threading.Thread(
        target=start_sniffing,
        args=(iface, bpf),
        daemon=True
    )
    _sniff_thread.start()

def stop_capture():
    state.capturing = False

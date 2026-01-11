import threading
import time
import psutil

class NetworkMonitor:
    """
    Monitor du trafic réseau sur une interface spécifique.
    Appelle un callback pour mettre à jour l'UI.
    """

    def __init__(self, iface_getter, ui_callback, interval=0.5):
        """
        iface_getter: fonction qui retourne le nom de l'interface à monitorer
        ui_callback: fonction fg(text, color) pour indiquer le trafic
        interval: temps entre checks en secondes
        """
        self.iface_getter = iface_getter
        self.ui_callback = ui_callback
        self.interval = interval
        self._running = False
        self._thread = None

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _monitor_loop(self):
        prev = psutil.net_io_counters(pernic=True)

        while self._running:
            time.sleep(self.interval)
            current = psutil.net_io_counters(pernic=True)

            selected_iface = self.iface_getter()

            # Si "Any", neutre
            if selected_iface is None or selected_iface.startswith("Any"):
                self.ui_callback("Any interface", "gray")
                prev = current
                continue

            iface = selected_iface
            traffic = False
            if iface in prev and iface in current:
                if current[iface].packets_recv > prev[iface].packets_recv:
                    traffic = True

            if traffic:
                self.ui_callback("Traffic detected", "lime")
            else:
                self.ui_callback("No traffic", "red")

            prev = current

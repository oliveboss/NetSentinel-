import threading
from capture.sniffer import start_sniffing, stop_sniffing
from utils.network_monitor import NetworkMonitor
import state.runtime_state as state


class CaptureController:
    def __init__(self, iface_getter, ui_traffic_callback, ui_monitor_callback, ui_alert_callback=None):
        """
        iface_getter : fonction qui retourne l'interface sélectionnée
        ui_traffic_callback : fonction(pkt) pour afficher paquet dans l'UI
        ui_monitor_callback : fonction(text, color) pour indicateur trafic
        ui_alert_callback : fonction(msg) pour afficher alertes dans l'UI
        """
        state.packet_callback = ui_traffic_callback
        self.iface_getter = iface_getter
        self.capture_status_callback = None
        self.ui_alert_callback = ui_alert_callback  # callback pour alertes

        # --- Network monitor pour indicateur trafic ---
        self.monitor = NetworkMonitor(
            iface_getter=iface_getter,
            ui_callback=ui_monitor_callback
        )
        self.monitor.start()

    def set_capture_status_callback(self, callback):
        """
        callback(is_running: bool) : notifier MainWindow si capture en cours ou arrêtée
        """
        self.capture_status_callback = callback

    def start_capture(self):
        if state.capturing:
            if self.ui_alert_callback:
                self.ui_alert_callback("⚠ Capture déjà en cours")
            return

        iface = self.iface_getter()
        if self.ui_alert_callback:
            self.ui_alert_callback(f"▶ Démarrage de la capture sur {iface or 'Any'}")

        thread = threading.Thread(
            target=start_sniffing,
            args=(iface,),
            daemon=True
        )
        thread.start()

        # notifier l'UI que la capture a démarré
        if self.capture_status_callback:
            self.capture_status_callback(True)

    def stop_capture(self):
        stop_sniffing()

        if self.ui_alert_callback:
            self.ui_alert_callback("⏹ Capture arrêtée")

        # notifier l'UI que la capture est arrêtée
        if self.capture_status_callback:
            self.capture_status_callback(False)

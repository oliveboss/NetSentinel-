import tkinter as tk
from tkinter import ttk

from utils.interfaces import list_interfaces
from ui.traffic_view import TrafficView
from ui.alerts_view import AlertsView
from controller.capture_controller import CaptureController


class IDSMainWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Mini IDS – Network Monitor")
        self.root.geometry("1200x800")
        self.root.configure(bg="#1e1e1e")

        self._style()
        self._build_ui()

        # --- callback pour l'indicateur trafic ---
        def traffic_ui_update(text, color):
            self.activity_text.config(text=text, fg=color)
            self.activity_dot.config(fg=color)

        # --- callback pour ajouter paquet ---
        def packet_ui_callback(pkt):
            self.traffic.add_packet(pkt)

        # --- callback pour ajouter alertes ---
        def alert_ui_callback(msg):
            self.alerts.add_alert(msg)

        # --- init controller ---
        self.controller = CaptureController(
            iface_getter=lambda: self.interfaces_map.get(self.iface_var.get()),
            ui_traffic_callback=packet_ui_callback,
            ui_monitor_callback=traffic_ui_update,
            ui_alert_callback=alert_ui_callback
        )

        # --- callback capture status ---
        def capture_status_update(is_running: bool):
            if is_running:
                self.capture_status.config(text="Running", fg="lime")
            else:
                self.capture_status.config(text="Stopped", fg="gray")

        self.controller.set_capture_status_callback(capture_status_update)

    # ----------------------------------------------------------------------
    # STYLE
    # ----------------------------------------------------------------------
    def _style(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(
            "TCombobox",
            fieldbackground="#2d2d30",
            background="#3c3c3c",
            foreground="white",
            arrowcolor="white"
        )

        style.configure(
            "Treeview",
            background="#252526",
            foreground="white",
            fieldbackground="#252526",
            rowheight=28,
            bordercolor="#3c3c3c",
            borderwidth=0
        )
        style.map("Treeview", background=[("selected", "#007acc")])

    # ----------------------------------------------------------------------
    # UI BUILD
    # ----------------------------------------------------------------------
    def _build_ui(self):
        # --- TOP BAR ---
        top = tk.Frame(self.root, bg="#1e1e1e")
        top.pack(fill="x", padx=12, pady=10)

        tk.Label(
            top, text="Interface :", bg="#1e1e1e", fg="white",
            font=("Segoe UI", 11)
        ).pack(side="left")

        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(
            top, textvariable=self.iface_var, state="readonly", width=45
        )
        self.iface_combo.pack(side="left", padx=10)

        # Load interfaces
        self.interfaces_map = {}
        display = ["Any (auto)"]
        for label, device in list_interfaces():
            display.append(label)
            self.interfaces_map[label] = device

        self.iface_combo["values"] = display
        self.iface_combo.current(0)

       
        # --- BUTTONS ---
        self._modern_button(
            top, "▶ Start", "#0e639c", lambda: self.controller.start_capture()
        ).pack(side="left", padx=6)

        self._modern_button(
            top, "⏹ Stop", "#c50f1f", lambda: self.controller.stop_capture()
        ).pack(side="left", padx=6)

        # --- STATUS INDICATOR ---
        status_frame = tk.Frame(top, bg="#1e1e1e")
        status_frame.pack(side="left", padx=20)

        self.activity_dot = tk.Label(
            status_frame, text="●", fg="red", bg="#1e1e1e",
            font=("Segoe UI", 18, "bold")
        )
        self.activity_dot.pack(side="left")

        self.activity_text = tk.Label(
            status_frame, text="No traffic", fg="gray", bg="#1e1e1e",
            font=("Segoe UI", 10)
        )
        self.activity_text.pack(side="left", padx=5)

        self.capture_status = tk.Label(
            status_frame, text="Stopped", fg="gray", bg="#1e1e1e",
            font=("Segoe UI", 10, "bold")
        )
        self.capture_status.pack(side="left", padx=10)

        # --- SEPARATOR ---
        ttk.Separator(self.root, orient="horizontal").pack(fill="x", pady=5)

        # ------------------------------------------------------------------
        # TRAFFIC + ALERTS AREA
        # ------------------------------------------------------------------
        container = tk.Frame(self.root, bg="#1e1e1e")
        container.pack(fill="both", expand=True, padx=10, pady=10)

        # Traffic view
        self.traffic = TrafficView(container)
        self.traffic.pack(fill="both", expand=True)

        # Separator
        ttk.Separator(container, orient="horizontal").pack(fill="x", pady=8)

        # Alerts view
        self.alerts = AlertsView(container)
        self.alerts.pack(fill="x")

        # --- FOOTER ---
        footer = tk.Label(
            self.root,
            text="Mini IDS – Monitoring in real time",
            bg="#1e1e1e",
            fg="#6e6e6e",
            font=("Segoe UI", 9)
        )
        footer.pack(side="bottom", pady=5)

    # ----------------------------------------------------------------------
    # MODERN BUTTON
    # ----------------------------------------------------------------------
    def _modern_button(self, parent, text, color, command):
        btn = tk.Label(
            parent, text=text, bg=color, fg="white",
            font=("Segoe UI", 10, "bold"),
            padx=14, pady=6, cursor="hand2"
        )
        btn.bind("<Button-1>", lambda e: command())
        btn.bind("<Enter>", lambda e: btn.config(bg=self._lighten(color)))
        btn.bind("<Leave>", lambda e: btn.config(bg=color))
        return btn

    def _lighten(self, color):
        c = int(color[1:], 16)
        r = min(255, (c >> 16) + 30)
        g = min(255, ((c >> 8) & 0xFF) + 30)
        b = min(255, (c & 0xFF) + 30)
        return f"#{r:02x}{g:02x}{b:02x}"

    def add_alert(self, message: str):
        self.alerts.add_alert(message)

    def run(self):
        self.root.mainloop()

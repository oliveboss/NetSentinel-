import tkinter as tk
from tkinter import ttk, filedialog

from utils.interfaces import list_interfaces
from ui.traffic_view import TrafficView
from ui.alerts_view import AlertsView
from ui.stats_panel import StatsPanel
from ui.widgets.modern_button import ModernButton
from ui.widgets.theme import *

from controller.capture_controller import CaptureController


class IDSMainWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Mini IDS – Network Monitor")
        self.root.geometry("1400x850")
        self.root.configure(bg=BG_DARK)

        # Counters
        self.packet_count = 0
        self.alert_count = 0
        self.info_count = 0

        # Stats panel visibility
        self.stats_visible = tk.BooleanVar(value=True)

        self._style()
        self._init_controller()
        self._build_ui()
        self._build_menu()
        self._schedule_graph_update()

    # ----------------------------------------------------------------------
    # CONTROLLER INIT
    # ----------------------------------------------------------------------
    def _init_controller(self):

        def traffic_ui_update(text, color):
            self.activity_text.config(text=text, fg=color)
            self.activity_dot.config(fg=color)

        def packet_ui_callback(pkt):
            self.packet_count += 1
            self.stats_panel.update_counters(self.packet_count, self.alert_count, self.info_count)
            self.traffic.add_packet(pkt)

        def alert_ui_callback(msg):
            self.alert_count += 1
            self.stats_panel.update_counters(self.packet_count, self.alert_count, self.info_count)
            self.alerts.add_alert(msg)

        def info_ui_callback(msg):
            self.info_count += 1
            self.stats_panel.update_counters(self.packet_count, self.alert_count, self.info_count)
            self.alerts.add_info(msg)

        self.controller = CaptureController(
            iface_getter=lambda: self.interfaces_map.get(self.iface_var.get()),
            ui_traffic_callback=packet_ui_callback,
            ui_monitor_callback=traffic_ui_update,
            ui_alert_callback=alert_ui_callback,
            ui_info_callback=info_ui_callback
        )

        def capture_status_update(is_running: bool):
            if is_running:
                self.capture_status.config(text="Running", fg=COLOR_OK)
            else:
                self.capture_status.config(text="Stopped", fg=COLOR_STOPPED)

        self.controller.set_capture_status_callback(capture_status_update)

    # ----------------------------------------------------------------------
    # MENU
    # ----------------------------------------------------------------------
    def _build_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # FICHIER
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Exporter trafic", command=self._export_traffic)
        file_menu.add_command(label="Exporter alertes", command=self._export_alerts)
        file_menu.add_separator()
        file_menu.add_command(label="Quitter", command=self.root.quit)
        menubar.add_cascade(label="Fichier", menu=file_menu)

        # CAPTURE
        capture_menu = tk.Menu(menubar, tearoff=0)
        capture_menu.add_command(label="Démarrer", command=self.controller.start_capture)
        capture_menu.add_command(label="Arrêter", command=self.controller.stop_capture)
        capture_menu.add_separator()
        capture_menu.add_command(label="Tester règles IDS", command=self.controller.test_rules)
        menubar.add_cascade(label="Capture", menu=capture_menu)

        # AFFICHAGE
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Effacer trafic", command=self._clear_traffic)
        view_menu.add_command(label="Effacer messages", command=self._clear_messages)
        view_menu.add_separator()
        view_menu.add_checkbutton(
            label="Auto-scroll trafic",
            variable=self.traffic.auto_scroll_var,
            command=self.traffic.toggle_auto_scroll
        )
        view_menu.add_checkbutton(
            label="Statistiques",
            variable=self.stats_visible,
            command=self._toggle_stats_panel
        )
        menubar.add_cascade(label="Affichage", menu=view_menu)

        # OUTILS
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(
            label="Activer filtre trafic",
            command=lambda: self.traffic.filter_entry.focus()
        )
        tools_menu.add_command(label="Debug (à venir)")
        menubar.add_cascade(label="Outils", menu=tools_menu)

        # AIDE
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(
            label="À propos",
            command=lambda: self.alerts.add_info("Mini IDS v1.0 – par Olivier")
        )
        menubar.add_cascade(label="Aide", menu=help_menu)

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
            background=BG_CARD,
            foreground="white",
            fieldbackground=BG_CARD,
            rowheight=28,
            bordercolor="#3c3c3c",
            borderwidth=0
        )
        style.map("Treeview", background=[("selected", "#007acc")])

    # ----------------------------------------------------------------------
    # UI BUILD
    # ----------------------------------------------------------------------
    def _build_ui(self):
        # TOP BAR
        top = tk.Frame(self.root, bg=BG_DARK)
        top.pack(fill="x", padx=12, pady=10)

        tk.Label(
            top, text="Interface :", bg=BG_DARK, fg="white",
            font=("Segoe UI", 11)
        ).pack(side="left")

        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(
            top, textvariable=self.iface_var, state="readonly", width=45
        )
        self.iface_combo.pack(side="left", padx=10)

        self.interfaces_map = {}
        display = ["Any (auto)"]
        for label, device in list_interfaces():
            display.append(label)
            self.interfaces_map[label] = device

        self.iface_combo["values"] = display
        self.iface_combo.current(0)

        # Start / Stop buttons
        ModernButton(top, "▶ Start", BTN_START, self.controller.start_capture).pack(side="left", padx=6)
        ModernButton(top, "⏹ Stop", BTN_STOP, self.controller.stop_capture).pack(side="left", padx=6)

        # Status
        status_frame = tk.Frame(top, bg=BG_DARK)
        status_frame.pack(side="left", padx=20)

        self.activity_dot = tk.Label(
            status_frame, text="●", fg="red", bg=BG_DARK,
            font=("Segoe UI", 18, "bold")
        )
        self.activity_dot.pack(side="left")

        self.activity_text = tk.Label(
            status_frame, text="No traffic", fg=TEXT_MUTED, bg=BG_DARK,
            font=("Segoe UI", 10)
        )
        self.activity_text.pack(side="left", padx=5)

        self.capture_status = tk.Label(
            status_frame, text="Stopped", fg=COLOR_STOPPED, bg=BG_DARK,
            font=("Segoe UI", 10, "bold")
        )
        self.capture_status.pack(side="left", padx=10)

        ttk.Separator(self.root, orient="horizontal").pack(fill="x", pady=5)

        # MAIN AREA
        self.main_container = tk.Frame(self.root, bg=BG_DARK)
        self.main_container.pack(fill="both", expand=True, padx=10, pady=10)

        self.main_container.grid_columnconfigure(0, weight=1)
        self.main_container.grid_columnconfigure(1, weight=0)

        # LEFT COLUMN
        self.left_col = tk.Frame(self.main_container, bg=BG_DARK)
        self.left_col.grid(row=0, column=0, sticky="nsew")

        # RIGHT COLUMN
        self.right_col = tk.Frame(self.main_container, bg=BG_DARK)
        self.right_col.grid(row=0, column=1, sticky="ns")

        # LEFT: TRAFFIC
        traffic_card = tk.Frame(self.left_col, bg=BG_CARD, bd=1, relief="solid")
        traffic_card.pack(fill="both", expand=True, padx=5, pady=5)

        self.traffic = TrafficView(traffic_card)
        self.traffic.pack(fill="both", expand=True, padx=10, pady=10)

        # LEFT: ALERTS
        alerts_card = tk.Frame(self.left_col, bg=BG_CARD, bd=1, relief="solid")
        alerts_card.pack(fill="x", padx=5, pady=5)

        self.alerts = AlertsView(alerts_card)
        self.alerts.pack(fill="x", padx=10, pady=10)

        # RIGHT: STATS PANEL
        self.stats_panel = StatsPanel(self.right_col)
        self.stats_panel.pack(fill="y", padx=5, pady=5)

    # ----------------------------------------------------------------------
    # STATS PANEL TOGGLE
    # ----------------------------------------------------------------------
    def _toggle_stats_panel(self):
        if self.stats_visible.get():
            self.right_col.grid(row=0, column=1, sticky="ns")
        else:
            self.right_col.grid_forget()

        self.main_container.grid_columnconfigure(0, weight=1)

    # ----------------------------------------------------------------------
    # CLEAR / EXPORT
    # ----------------------------------------------------------------------
    def _clear_traffic(self):
        self.traffic.clear()
        self.packet_count = 0
        self.stats_panel.update_counters(self.packet_count, self.alert_count, self.info_count)

    def _clear_messages(self):
        self.alerts.clear()
        self.alert_count = 0
        self.info_count = 0
        self.stats_panel.update_counters(self.packet_count, self.alert_count, self.info_count)

    def _export_traffic(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if path:
            self.traffic.export_csv(path)

    def _export_alerts(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if path:
            self.alerts.export_alerts(path)

    # ----------------------------------------------------------------------
    # GRAPH UPDATE LOOP
    # ----------------------------------------------------------------------
    def _schedule_graph_update(self):
        self.root.after(1000, self._update_graph_data)

    def _update_graph_data(self):
        delta = self.packet_count - getattr(self, "last_packet_total", 0)
        self.last_packet_total = self.packet_count

        self.stats_panel.update_graph(delta)
        self.stats_panel.update_protocols(self.traffic.table)

        self._schedule_graph_update()

    # ----------------------------------------------------------------------
    # RUN
    # ----------------------------------------------------------------------
    def run(self):
        self.root.mainloop()
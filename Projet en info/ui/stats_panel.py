import tkinter as tk
from tkinter import ttk
from PIL import Image, ImageDraw, ImageTk


class StatsPanel(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg="#252526", bd=1, relief="solid")

        # --- Title ---
        title = tk.Label(
            self,
            text="Statistiques",
            bg="#252526",
            fg="white",
            font=("Segoe UI", 12, "bold")
        )
        title.pack(anchor="w", padx=10, pady=(8, 4))

        # --- Counters ---
        self.packets_label = tk.Label(
            self,
            text="Packets capturés : 0",
            bg="#252526",
            fg="#4da6ff",
            font=("Segoe UI", 10)
        )
        self.packets_label.pack(anchor="w", padx=10, pady=2)

        self.alerts_label = tk.Label(
            self,
            text="Alertes détectées : 0",
            bg="#252526",
            fg="#ff3333",
            font=("Segoe UI", 10)
        )
        self.alerts_label.pack(anchor="w", padx=10, pady=2)

        self.info_label = tk.Label(
            self,
            text="Messages info : 0",
            bg="#252526",
            fg="#ffaa00",
            font=("Segoe UI", 10)
        )
        self.info_label.pack(anchor="w", padx=10, pady=2)

        # --- Graph canvas ---
        self.graph_canvas = tk.Canvas(
            self,
            bg="#151515",
            height=160,
            highlightthickness=0
        )
        self.graph_canvas.pack(fill="x", padx=10, pady=10)

        # --- Pie chart canvas ---
        self.pie_canvas = tk.Canvas(
            self,
            bg="#151515",
            height=220,
            highlightthickness=0
        )
        self.pie_canvas.pack(fill="x", padx=10, pady=10)

        # --- Legend ---
        self.legend_frame = tk.Frame(self, bg="#252526")
        self.legend_frame.pack(anchor="w", padx=10, pady=(0, 10))

        # Internal data
        self.packet_history = []
        self.pie_image = None

    # ------------------------------------------------------------------
    # PUBLIC API — called by main_window
    # ------------------------------------------------------------------
    def update_counters(self, packets, alerts, info):
        self.packets_label.config(text=f"Packets capturés : {packets}")
        self.alerts_label.config(text=f"Alertes détectées : {alerts}")
        self.info_label.config(text=f"Messages info : {info}")

    def update_graph(self, delta):
        self.packet_history.append(delta)
        if len(self.packet_history) > 50:
            self.packet_history.pop(0)
        self._draw_graph()

    def update_protocols(self, traffic_table):
        items = traffic_table.get_children()
        if not items:
            return

        proto_counts = {}
        for item in items:
            row = traffic_table.item(item, "values")

            # support returned tuple/list or dict(returned by some tk implementations)
            if isinstance(row, dict):
                row = row.get("values", ())

            if not row or len(row) < 3:
                continue

            proto = row[2]
            proto_counts[proto] = proto_counts.get(proto, 0) + 1

        total = sum(proto_counts.values())
        if total == 0:
            return

        self._draw_pie(proto_counts, total)
        self._update_legend(proto_counts, total)

    # ------------------------------------------------------------------
    # GRAPH
    # ------------------------------------------------------------------
    def _draw_graph(self):
        self.graph_canvas.delete("all")
        w = self.graph_canvas.winfo_width() or 200
        h = self.graph_canvas.winfo_height() or 160

        if not self.packet_history:
            return

        max_val = max(self.packet_history) or 1
        bar_width = max(2, w / max(50, len(self.packet_history)))

        for i, val in enumerate(self.packet_history):
            x0 = i * bar_width
            x1 = x0 + bar_width - 1
            height = (val / max_val) * (h - 30)
            y0 = h - height - 10
            y1 = h - 10
            self.graph_canvas.create_rectangle(
                x0, y0, x1, y1,
                fill="#4da6ff",
                outline=""
            )

        self.graph_canvas.create_text(
            10, 10,
            anchor="nw",
            fill="#cccccc",
            font=("Segoe UI", 9),
            text=f"Packets/s (dernières {len(self.packet_history)}s)"
        )

    # ------------------------------------------------------------------
    # PIE CHART
    # ------------------------------------------------------------------
    def _draw_pie(self, proto_counts, total):
        self.pie_canvas.delete("all")

        colors = {
            "TCP": "#4da6ff",
            "UDP": "#b366ff",
            "ICMP": "#66ff66"
        }

        img = Image.new("RGBA", (200, 200), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)

        start_angle = 0
        for proto, count in proto_counts.items():
            extent = (count / total) * 360
            color = colors.get(proto, "#888888")

            draw.pieslice(
                [0, 0, 200, 200],
                start=start_angle,
                end=start_angle + extent,
                fill=color
            )
            start_angle += extent

        self.pie_image = ImageTk.PhotoImage(img)
        self.pie_canvas.create_image(100, 100, image=self.pie_image)

    # ------------------------------------------------------------------
    # LEGEND
    # ------------------------------------------------------------------
    def _update_legend(self, proto_counts, total):
        for widget in self.legend_frame.winfo_children():
            widget.destroy()

        colors = {
            "TCP": "#4da6ff",
            "UDP": "#b366ff",
            "ICMP": "#66ff66"
        }

        ordered = ["TCP", "UDP", "ICMP"]
        for proto in proto_counts:
            if proto not in ordered:
                ordered.append(proto)

        for proto in ordered:
            count = proto_counts.get(proto, 0)
            pct = (count / total * 100) if total > 0 else 0
            color = colors.get(proto, "#888888")

            row = tk.Frame(self.legend_frame, bg="#252526")
            row.pack(anchor="w")

            box = tk.Canvas(row, width=12, height=12, bg="#252526", highlightthickness=0)
            box.create_rectangle(0, 0, 12, 12, fill=color, outline=color)
            box.pack(side="left", padx=(0, 6))

            label = tk.Label(
                row,
                text=f"{proto} : {pct:.1f}%",
                bg="#252526",
                fg="white",
                font=("Segoe UI", 9)
            )
            label.pack(side="left")
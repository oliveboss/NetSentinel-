# ui/traffic_view.py

import tkinter as tk
from tkinter import ttk

class TrafficView(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg="#1e1e1e")

        # --- Title ---
        label = tk.Label(
            self,
            text="Live Network Traffic",
            bg="#1e1e1e",
            fg="white",
            font=("Segoe UI", 12, "bold")
        )
        label.pack(anchor="w", padx=10, pady=6)

        # --- Scrollbar ---
        self.scrollbar = tk.Scrollbar(self, orient="vertical")
        self.scrollbar.pack(side="right", fill="y")

        # --- Table ---
        columns = ("src", "dst", "proto", "sport", "dport", "size")
        self.table = ttk.Treeview(
            self,
            columns=columns,
            show="headings",
            yscrollcommand=self.scrollbar.set
        )
        self.table.pack(fill="both", expand=True, padx=10, pady=6)

        self.scrollbar.config(command=self.table.yview)

        # --- Column setup ---
        titles = ["Source IP", "Destination IP", "Proto", "Src Port", "Dst Port", "Size"]
        for col, title in zip(columns, titles):
            self.table.heading(col, text=title)
            self.table.column(col, width=140, anchor="center")

        # Auto-scroll enabled by default
        self.auto_scroll = True

        # Detect user scrolling
        self.table.bind("<MouseWheel>", self._on_user_scroll)
        self.table.bind("<Button-4>", self._on_user_scroll)  # Linux
        self.table.bind("<Button-5>", self._on_user_scroll)  # Linux

        # Copy selection with Ctrl+C
        self.table.bind("<Control-c>", self._copy_selection)

    # -------------------------
    # Add packet + auto-scroll
    # -------------------------
    def add_packet(self, pkt):
        self.table.insert("", "end", values=(
            pkt["src"],
            pkt["dst"],
            pkt["proto"],
            pkt["sport"],
            pkt["dport"],
            pkt["size"]
        ))

        # Scroll only if user is at the bottom
        if self.auto_scroll:
            self.table.yview_moveto(1.0)

    # -------------------------
    # Detect manual scrolling
    # -------------------------
    def _on_user_scroll(self, event):
        first, last = self.table.yview()

        # If not at bottom → disable auto-scroll
        if last < 1.0:
            self.auto_scroll = False
        else:
            self.auto_scroll = True

    # -------------------------
    # Copy selected rows
    # -------------------------
    def _copy_selection(self, event=None):
        selected = self.table.selection()
        if not selected:
            return

        rows = []
        for item in selected:
            values = self.table.item(item, "values")
            rows.append("\t".join(values))

        text = "\n".join(rows)

        # Copy to clipboard
        self.clipboard_clear()
        self.clipboard_append(text)
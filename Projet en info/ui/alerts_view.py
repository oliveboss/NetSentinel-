import tkinter as tk
from datetime import datetime


class AlertsView(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#1e1e1e")

        # --- Title ---
        title = tk.Label(
            self,
            text="Alertes IDS",
            font=("Segoe UI", 12, "bold"),
            fg="#ff4d4d",
            bg="#1e1e1e"
        )
        title.pack(anchor="w", padx=5, pady=(0, 4))

        # --- Frame for text + scrollbar ---
        box = tk.Frame(self, bg="#1e1e1e")
        box.pack(fill="both", expand=True)

        # Scrollbar
        scrollbar = tk.Scrollbar(box, orient="vertical")
        scrollbar.pack(side="right", fill="y")

        # Text area
        self.text = tk.Text(
            box,
            height=10,
            bg="#151515",
            fg="#ff4d4d",
            insertbackground="white",
            font=("Consolas", 10),
            relief="flat",
            wrap="word",
            yscrollcommand=scrollbar.set
        )
        self.text.pack(fill="both", expand=True)

        scrollbar.config(command=self.text.yview)

        # Disable user editing
        self.text.bind("<Key>", lambda e: "break")

    def add_alert(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.text.see(tk.END)
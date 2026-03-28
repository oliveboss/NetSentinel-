import tkinter as tk


class ModernButton(tk.Label):
    def __init__(self, parent, text, color, command):
        super().__init__(
            parent,
            text=text,
            bg=color,
            fg="white",
            font=("Segoe UI", 10, "bold"),
            padx=14,
            pady=6,
            cursor="hand2"
        )

        self.default_color = color
        self.command = command

        # Events
        self.bind("<Button-1>", self._on_click)
        self.bind("<Enter>", self._on_hover)
        self.bind("<Leave>", self._on_leave)

    # -------------------------
    # Event handlers
    # -------------------------
    def _on_click(self, event):
        if callable(self.command):
            self.command()

    def _on_hover(self, event):
        self.config(bg=self._lighten(self.default_color))

    def _on_leave(self, event):
        self.config(bg=self.default_color)

    # -------------------------
    # Utility
    # -------------------------
    def _lighten(self, color):
        c = int(color[1:], 16)
        r = min(255, (c >> 16) + 30)
        g = min(255, ((c >> 8) & 0xFF) + 30)
        b = min(255, (c & 0xFF) + 30)
        return f"#{r:02x}{g:02x}{b:02x}"
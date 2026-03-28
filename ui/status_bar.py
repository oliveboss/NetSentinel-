import tkinter as tk

class StatusBar(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.var = tk.StringVar()
        self.var.set("Packets capturés: 0   |   Capturing: NO")
        self.label = tk.Label(self, textvariable=self.var, anchor="w", bg="#0f0f0f", fg="white", padx=6)
        self.label.pack(fill="x")

    def set_status(self, text):
        self.var.set(text)

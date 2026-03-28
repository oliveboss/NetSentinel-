import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
import pytest
import tkinter as tk

@pytest.fixture(scope="function")
def tk_root():
    root = tk.Tk()
    root.withdraw()  # empêche l'apparition d'une fenêtre
    yield root
    root.destroy()
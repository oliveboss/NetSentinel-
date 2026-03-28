import pytest

try:
    import tkinter as tk
except ImportError:
    tk = None

@pytest.fixture(scope="function")
def tk_root():
    if tk is None:
        pytest.skip("tkinter n'est pas disponible")

    try:
        root = tk.Tk()
        root.withdraw()
    except tk.TclError:
        pytest.skip("tkinter n'est pas installée correctement (tcl manquant)")

    yield root
    root.destroy()
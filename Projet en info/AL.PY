

import tkinter as tk
from tkinter import ttk, messagebox, Toplevel
import threading
import time
from collections import defaultdict, deque
from scapy.all import sniff, get_if_list, IP, TCP, UDP, ICMP

# ---------------- Global state ----------------
capturing = False
sniff_thread = None
packet_count = 0

# For simple detections
# store for each src IP a deque of (timestamp, dst_port)
src_ports = defaultdict(lambda: deque())
# store for flood detection: timestamps per src
src_times = defaultdict(lambda: deque())

# thresholds (ajuste pour la démo)
PORTSCAN_PORTS_THRESHOLD = 20   # nombre de ports différents en window
PORTSCAN_WINDOW = 3.0          # secondes
FLOOD_PACKET_THRESHOLD = 100   # paquets
FLOOD_WINDOW = 2.0             # secondes

# ---------------- Utility & detection ----------------
def detect_anomalies(pkt_info):
    """
    pkt_info: dict with keys src, dst, sport, dport, proto, summary
    Returns: (is_alert:bool, alert_message:str or None)
    """
    now = time.time()
    src = pkt_info.get("src")
    dport = pkt_info.get("dport")

    # PORT SCAN detection: many distinct destination ports in short time
    if src and dport is not None:
        dq = src_ports[src]
        dq.append((now, dport))
        # remove old
        while dq and now - dq[0][0] > PORTSCAN_WINDOW:
            dq.popleft()
        distinct_ports = {p for t, p in dq if p is not None}
        if len(distinct_ports) >= PORTSCAN_PORTS_THRESHOLD:
            return True, f"Port scan suspect détecté depuis {src} ({len(distinct_ports)} ports en {PORTSCAN_WINDOW}s)"

    # FLOOD detection: too many packets from same src in short time
    if src:
        tq = src_times[src]
        tq.append(now)
        while tq and now - tq[0] > FLOOD_WINDOW:
            tq.popleft()
        if len(tq) >= FLOOD_PACKET_THRESHOLD:
            return True, f"Flood suspect : {len(tq)} paquets depuis {src} en {FLOOD_WINDOW}s"

    return False, None

# ---------------- Packet processing ----------------
def extract_info(packet):
    info = {"summary": packet.summary(), "src": None, "dst": None, "sport": None, "dport": None, "proto": None}
    try:
        if IP in packet:
            info["src"] = packet[IP].src
            info["dst"] = packet[IP].dst
        if TCP in packet:
            info["sport"] = packet[TCP].sport
            info["dport"] = packet[TCP].dport
            info["proto"] = "TCP"
        elif UDP in packet:
            info["sport"] = packet[UDP].sport
            info["dport"] = packet[UDP].dport
            info["proto"] = "UDP"
        elif ICMP in packet:
            info["proto"] = "ICMP"
        else:
            info["proto"] = "OTHER"
    except Exception:
        pass
    return info

def process_packet(packet):
    global packet_count
    try:
        packet_count += 1
        info = extract_info(packet)
        summary = info.get("summary", str(packet))
        app_add_traffic(summary)
        # detection
        is_alert, message = detect_anomalies(info)
        if is_alert:
            app_add_alert(message)
    except Exception as e:
        # ignore parsing errors
        pass

# ---------------- Sniff control ----------------
def start_sniffing(iface=None, bpf_filter=None):
    """
    Sniff until capturing becomes False.
    """
    global capturing
    capturing = True
    # sniff uses stop_filter callable that receives a packet; return True to stop
    try:
        sniff(prn=process_packet, iface=iface, filter=bpf_filter, store=False,
              stop_filter=lambda pkt: not capturing)
    except Exception as e:
        # show error in GUI thread
        app_show_error(f"Erreur sniff: {e}")

def stop_sniffing():
    global capturing
    capturing = False

# ---------------- GUI helpers (these call Tkinter in main thread) ----------------
def app_add_traffic(text):
    # must be called in main thread -> use after
    def _add():
        traffic_table.insert("", "end", values=[text])
        update_status()
    root.after(0, _add)

def app_add_alert(text):
    def _add():
        # insert into alerts table with red tag
        alerts_table.insert("", "end", values=[text], tags=("alert",))
        # color tag configure
        alerts_table.tag_configure("alert", background="#4b0000", foreground="white")
        update_status()
    root.after(0, _add)

def app_show_error(text):
    def _show():
        messagebox.showerror("Erreur", text)
    root.after(0, _show)

def update_status():
    # update counters and status bar
    status_var.set(f"Packets capturés: {packet_count}   |   Capturing: {'YES' if capturing else 'NO'}")

# ---------------- GUI callbacks ----------------
def on_start():
    global sniff_thread, packet_count
    if capturing:
        return
    # clear counters optionally
    packet_count = 0
    update_status()
    # get selected interface
    iface = iface_var.get()
    if iface == "" or iface is None:
        app_show_error("Sélectionne une interface réseau avant de démarrer.")
        return
    bpf = filter_entry.get().strip()
    # start thread
    sniff_thread = threading.Thread(target=start_sniffing, args=(iface if iface != "Any" else None, bpf or None))
    sniff_thread.daemon = True
    sniff_thread.start()

def on_stop():
    stop_sniffing()

def fill_interfaces():
    # get list from scapy
    try:
        ifs = get_if_list()
    except Exception:
        ifs = []
    # add "Any" option
    iface_combo['values'] = ["Any"] + ifs
    if ifs:
        iface_combo.current(0)

def copy_selected_traffic(event=None):
    sel = traffic_table.selection()
    if not sel:
        return
    v = traffic_table.item(sel[0], "values")[0]
    root.clipboard_clear()
    root.clipboard_append(v)
    messagebox.showinfo("Copié", "Ligne copiée dans le presse-papier.")

def copy_selected_alert(event=None):
    sel = alerts_table.selection()
    if not sel:
        return
    v = alerts_table.item(sel[0], "values")[0]
    root.clipboard_clear()
    root.clipboard_append(v)
    messagebox.showinfo("Copié", "Alerte copiée dans le presse-papier.")

# ---------------- Build GUI ----------------
root = tk.Tk()
root.title("Mini IDS – Sélection d'interface & Capture")
root.geometry("1000x650")
root.configure(bg="#111111")

# Top frame: controls
top = tk.Frame(root, bg="#111111")
top.pack(fill="x", padx=10, pady=8)

tk.Label(top, text="Interface:", bg="#111111", fg="white").pack(side="left", padx=(4,2))
iface_var = tk.StringVar()
iface_combo = ttk.Combobox(top, textvariable=iface_var, state="readonly", width=35)
iface_combo.pack(side="left", padx=(0,10))

tk.Label(top, text="Filtre (BPF, ex: tcp or port 80):", bg="#111111", fg="white").pack(side="left")
filter_entry = tk.Entry(top, width=25)
filter_entry.pack(side="left", padx=6)

start_button = tk.Button(top, text="▶ Démarrer", bg="#28a745", fg="white", command=on_start, width=12)
start_button.pack(side="left", padx=8)

stop_button = tk.Button(top, text="⏹ Arrêter", bg="#dc3545", fg="white", command=on_stop, width=12)
stop_button.pack(side="left")

# Middle: traffic table and alerts side by side
middle = tk.PanedWindow(root, orient="horizontal", sashrelief="raised", bg="#111111")
middle.pack(fill="both", expand=True, padx=10, pady=6)

# Traffic frame
traf_frame = tk.Frame(middle, bg="#1b1b1b")
middle.add(traf_frame, stretch="always")

tk.Label(traf_frame, text="Trafic Réseau (live)", bg="#1b1b1b", fg="white", font=("Arial", 12, "bold")).pack(anchor="w", padx=6, pady=4)
traffic_table = ttk.Treeview(traf_frame, columns=("msg",), show="headings", height=20)
traffic_table.heading("msg", text="Résumé du paquet")
traffic_table.pack(fill="both", expand=True, padx=6, pady=6)
traffic_table.bind("<Double-1>", copy_selected_traffic)

# Alerts frame
alert_frame = tk.Frame(middle, bg="#1b1b1b", width=350)
middle.add(alert_frame)

tk.Label(alert_frame, text="Alertes IDS", bg="#1b1b1b", fg="white", font=("Arial", 12, "bold")).pack(anchor="w", padx=6, pady=4)
alerts_table = ttk.Treeview(alert_frame, columns=("alert",), show="headings", height=10)
alerts_table.heading("alert", text="Alertes détectées")
alerts_table.pack(fill="both", expand=False, padx=6, pady=6)
alerts_table.bind("<Double-1>", copy_selected_alert)

# Bottom: status bar
status_var = tk.StringVar()
status_var.set("Packets capturés: 0   |   Capturing: NO")
status = tk.Label(root, textvariable=status_var, bg="#0f0f0f", fg="white", anchor="w", padx=6)
status.pack(fill="x", side="bottom")

# menu
menu = tk.Menu(root)
root.config(menu=menu)
file_menu = tk.Menu(menu, tearoff=0)
file_menu.add_command(label="Quitter", command=root.quit)
menu.add_cascade(label="Fichier", menu=file_menu)
help_menu = tk.Menu(menu, tearoff=0)
help_menu.add_command(label="À propos", command=lambda: messagebox.showinfo("À propos", "Mini IDS - Démo"))
menu.add_cascade(label="Aide", menu=help_menu)

# style tweak for dark look
style = ttk.Style()
style.theme_use("default")
style.configure("Treeview", background="#222222", foreground="white", fieldbackground="#222222", rowheight=24)
style.map("Treeview", background=[("selected", "#0057b7")])

# fill interface list now
fill_interfaces()

# start mainloop
root.mainloop()

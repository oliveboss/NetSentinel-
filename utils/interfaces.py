import psutil
import socket

def list_interfaces():
    """
    Retourne uniquement les interfaces réseau actives avec IPv4
    Exemple :
    [
        ("Wi-Fi (192.168.1.12)", "Wi-Fi"),
        ("Ethernet (10.0.0.5)", "Ethernet")
    ]
    """

    interfaces = []

    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    for name, iface_stats in stats.items():
        # interface doit être active
        if not iface_stats.isup:
            continue

        # ignorer loopback & virtuelles
        lname = name.lower()
        if "loopback" in lname or "virtual" in lname or "vmware" in lname:
            continue

        ip = None
        for addr in addrs.get(name, []):
            if addr.family == socket.AF_INET:
                ip = addr.address
                break

        if not ip:
            continue  # ignorer interfaces sans IPv4

        # nom lisible
        if "wi-fi" in lname or "wifi" in lname or "wlan" in lname:
            label = f"Wi-Fi ({ip})"
        elif "ethernet" in lname or "eth" in lname:
            label = f"Ethernet ({ip})"
        else:
            label = f"{name} ({ip})"

        interfaces.append((label, name))

    return interfaces

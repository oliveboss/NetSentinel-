import time
from state.runtime_state import src_times
from config.thresholds import FLOOD_PACKET_THRESHOLD, FLOOD_WINDOW

def detect(pkt_info):
    src = pkt_info.get("src")
    if not src:
        return None

    now = time.time()
    dq = src_times[src]
    dq.append(now)

    while dq and now - dq[0] > FLOOD_WINDOW:
        dq.popleft()

    if len(dq) >= FLOOD_PACKET_THRESHOLD:
        return f"Flood suspect détecté depuis {src}"

    return None

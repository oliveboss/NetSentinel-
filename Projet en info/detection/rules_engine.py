from detection.rules.portscan import detect as portscan_detect
from detection.rules.flood import detect as flood_detect

def detect_anomalies(pkt_info):
    for rule in (portscan_detect, flood_detect):
        alert = rule(pkt_info)
        if alert:
            return True, alert
    return False, None

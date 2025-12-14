from scapy.all import sniff, IP, TCP, UDP
import threading
import time
from collections import deque

# Store last 50 packets for the dashboard
packet_log = deque(maxlen=50)
running = True

def process_packet(packet):
    """Callback function for every captured packet."""
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        
        try:
            sport = packet[packet.payload.name].sport
            dport = packet[packet.payload.name].dport
        except:
            sport = "-"
            dport = "-"

        log_entry = {
            "time": time.strftime("%H:%M:%S"),
            "src": src,
            "dst": dst,
            "proto": proto,
            "port": dport
        }
        packet_log.append(log_entry)

def start_monitoring(interface="eth0"):
    """Starts the sniffing thread."""
    t = threading.Thread(target=lambda: sniff(iface=interface, prn=process_packet, store=False))
    t.daemon = True
    t.start()

from flask import Flask, render_template, jsonify, request
import subprocess
import os
import threading
import time
import datetime
import requests
from collections import deque
from scapy.all import sniff, IP, TCP, UDP

app = Flask(__name__)

# --- CONFIGURATION ---
LOG_FILE = "kali_shield.log"
packet_log = deque(maxlen=50)
geo_cache = {} # Stores IP locations to avoid repeat API calls
INTERFACE = "eth0" # Change to wlan0 if using Wi-Fi

def log_event(category, message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] [{category.upper()}] {message}"
    with open(LOG_FILE, "a") as f:
        f.write(entry + "\n")
    return entry

def get_ip_location(ip):
    """Queries a Geo-IP API for the origin of an IP address."""
    if ip in ["127.0.0.1", "localhost"] or ip.startswith("192.168.") or ip.startswith("10."):
        return "Local Network"
    
    if ip in geo_cache:
        return geo_cache[ip]

    try:
        # Free API (ip-api.com) - No key required for low volume
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=1).json()
        if resp.get('status') == 'success':
            loc = f"{resp.get('city')}, {resp.get('countryCode')}"
            geo_cache[ip] = loc
            return loc
    except:
        pass
    return "Unknown"

# --- TRAFFIC MONITORING ---
def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        port = packet[packet.payload.name].dport if hasattr(packet[packet.payload.name], 'dport') else "-"
        
        entry = {
            "time": time.strftime("%H:%M:%S"),
            "src": src_ip,
            "loc": get_ip_location(src_ip),
            "dst": packet[IP].dst,
            "proto": proto,
            "port": port
        }
        packet_log.append(entry)

def start_sniffing():
    sniff(iface=INTERFACE, prn=process_packet, store=False)

# --- ROUTES ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/traffic')
def get_traffic():
    return jsonify(list(packet_log))

@app.route('/api/logs')
def get_logs():
    if not os.path.exists(LOG_FILE): return jsonify([])
    with open(LOG_FILE, "r") as f:
        return jsonify(f.readlines()[-15:])

@app.route('/api/firewall', methods=['POST'])
def firewall_control():
    data = request.json
    port, action = data.get('port'), data.get('action')
    if not port or int(port) in [22, 5000]:
        return jsonify({"message": "Protected Port"}), 400
    
    flag = "-A" if action == "block" else "-D"
    cmd = f"iptables {flag} INPUT -p tcp --dport {port} -j DROP"
    try:
        subprocess.run(cmd.split(), check=True)
        msg = log_event("Firewall", f"{action.upper()}ED port {port}")
        return jsonify({"message": msg})
    except:
        return jsonify({"message": "Error: Rule might already exist/not exist"}), 500

@app.route('/api/usb')
def get_usb():
    devices = []
    base = "/sys/bus/usb/devices"
    if os.path.exists(base):
        for d in os.listdir(base):
            p = os.path.join(base, d)
            if os.path.exists(os.path.join(p, 'product')):
                with open(os.path.join(p, 'product'), 'r') as f: name = f.read().strip()
                with open(os.path.join(p, 'authorized'), 'r') as f: auth = f.read().strip()
                devices.append({"id": d, "name": name, "status": "Active" if auth == "1" else "Blocked"})
    return jsonify(devices)

@app.route('/api/usb_control', methods=['POST'])
def usb_control():
    data = request.json
    dev_id, action = data.get('id'), data.get('action')
    val = "1" if action == "unblock" else "0"
    try:
        with open(f"/sys/bus/usb/devices/{dev_id}/authorized", "w") as f:
            f.write(val)
        log_event("USB", f"{action.upper()}ED device {dev_id}")
        return jsonify({"message": "Success"})
    except:
        return jsonify({"message": "Permission Denied"}), 500

if __name__ == '__main__':
    if os.geteuid() != 0:
        print("!!! RUN AS SUDO !!!")
        exit()
    threading.Thread(target=start_sniffing, daemon=True).start()
    app.run(host='0.0.0.0', port=5000)

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw, get_if_list
from datetime import datetime
import threading
import collections
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cybersec2024'
socketio = SocketIO(app, cors_allowed_origins="*")

# ── Global State ──
capture_running = False
capture_thread = None
stats = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "arp": 0, "dns": 0, "suspicious": 0}
ip_counter = collections.Counter()
ip_port_map = collections.defaultdict(set)
packets_log = []


def reset_stats():
    global stats, ip_counter, ip_port_map, packets_log
    stats = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "arp": 0, "dns": 0, "suspicious": 0}
    ip_counter.clear()
    ip_port_map.clear()
    packets_log.clear()


def get_tcp_flags(flags):
    flag_map = {'F': 'FIN', 'S': 'SYN', 'R': 'RST', 'P': 'PSH', 'A': 'ACK', 'U': 'URG'}
    active = [name for symbol, name in flag_map.items() if symbol in str(flags)]
    return '+'.join(active) if active else str(flags)


def process_packet(packet):
    global stats
    stats["total"] += 1
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    src_ip = dst_ip = src_port = dst_port = protocol = flags = dns_query = payload = ""
    alert = None

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        ip_counter[src_ip] += 1

    if packet.haslayer(TCP):
        stats["tcp"] += 1
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = get_tcp_flags(packet[TCP].flags)
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load[:40].decode('utf-8', errors='ignore').strip()[:30]
            except:
                pass

    elif packet.haslayer(UDP):
        stats["udp"] += 1
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    elif packet.haslayer(ICMP):
        stats["icmp"] += 1
        protocol = "ICMP"
        icmp_codes = {0: "Echo Reply", 8: "Echo Request", 3: "Unreachable", 11: "TTL Exceeded"}
        flags = icmp_codes.get(packet[ICMP].type, f"Type {packet[ICMP].type}")

    elif packet.haslayer(ARP):
        stats["arp"] += 1
        protocol = "ARP"
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        flags = "Who-has" if packet[ARP].op == 1 else "Is-at"

    else:
        protocol = "OTHER"

    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        stats["dns"] += 1
        dns_query = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')

    # Threat Detection
    if dst_port and src_ip:
        ip_port_map[src_ip].add(dst_port)
        if len(ip_port_map[src_ip]) >= 10:
            alert = f"⚠ PORT SCAN from {src_ip}"
            stats["suspicious"] += 1
        elif ip_counter[src_ip] > 150:
            alert = f"⚠ HIGH TRAFFIC from {src_ip}"
            stats["suspicious"] += 1

    pkt_data = {
        "time": timestamp,
        "protocol": protocol,
        "src_ip": str(src_ip),
        "dst_ip": str(dst_ip),
        "src_port": str(src_port) if src_port else "",
        "dst_port": str(dst_port) if dst_port else "",
        "flags": flags,
        "dns": dns_query,
        "payload": payload,
        "alert": alert
    }

    packets_log.append(pkt_data)
    if len(packets_log) > 500:
        packets_log.pop(0)

    # Emit to frontend
    socketio.emit('packet', pkt_data)
    socketio.emit('stats', stats)
    if alert:
        socketio.emit('alert', {"message": alert, "ip": src_ip})


def start_sniffing(iface, bpf_filter, count):
    global capture_running
    try:
        sniff(
            iface=iface if iface else None,
            filter=bpf_filter if bpf_filter else None,
            prn=process_packet,
            count=int(count) if int(count) > 0 else 0,
            stop_filter=lambda x: not capture_running,
            store=False
        )
    except Exception as e:
        socketio.emit('error', {"message": str(e)})
    finally:
        capture_running = False
        socketio.emit('stopped', {})


# ── Routes ──
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/interfaces')
def get_interfaces():
    return jsonify(get_if_list())


@app.route('/start', methods=['POST'])
def start_capture():
    global capture_running, capture_thread
    if capture_running:
        return jsonify({"status": "already running"})

    data = request.json
    iface = data.get('iface', '')
    bpf_filter = data.get('filter', '')
    count = data.get('count', 0)

    reset_stats()
    capture_running = True
    capture_thread = threading.Thread(
        target=start_sniffing, args=(iface, bpf_filter, count), daemon=True
    )
    capture_thread.start()
    return jsonify({"status": "started"})


@app.route('/stop', methods=['POST'])
def stop_capture():
    global capture_running
    capture_running = False
    return jsonify({"status": "stopped"})


@app.route('/stats')
def get_stats():
    return jsonify(stats)


@app.route('/packets')
def get_packets():
    return jsonify(packets_log[-100:])


if __name__ == '__main__':
    print("\n Advanced Packet Sniffer")
    print("   Open browser: http://localhost:5000")
    print("   Linux: Run with sudo\n")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)

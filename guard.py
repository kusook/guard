from scapy.all import *
import time
from collections import defaultdict
import threading
import re
from flask import Flask, jsonify

app = Flask(__name__)
nids_thread = None

stop_event = threading.Event()

stats = {"TotalPacks": 0, "ThreatsNum": 0, "LastThreat": {"type": None, "ip": None, "time": None}}
syn_history = defaultdict(lambda: {"ports": [], "timestamps": []})

def check_port_scanning(pack):
    if TCP in pack and pack[TCP].flags == 'S':
        if IP in pack:
            ip = pack[IP].src
            port = pack[TCP].dport
            now = time.time()

            new_ports = []
            new_timestamps = []

            for i in range(len(syn_history[ip]["timestamps"])):
                if now - syn_history[ip]["timestamps"][i] < 10:
                    new_ports.append(syn_history[ip]["ports"][i])
                    new_timestamps.append(syn_history[ip]["timestamps"][i])
            
            new_ports.append(port)
            new_timestamps.append(now)

            syn_history[ip]["ports"] = new_ports
            syn_history[ip]["timestamps"] = new_timestamps

            unique_ports = len(set(new_ports))
            total_ports = len(new_ports)

            if unique_ports > 10:
                stats["LastThreat"] = {"type": "Сканирование портов", "ip": ip, "time": time.strftime('%Y-%m-%d %H:%M:%S')}
                stats["ThreatsNum"] += 1
                with open("nids_logs.txt", "a") as file:
                    now = time.strftime('%Y-%m-%d %H:%M:%S')
                    file.write(f"[{now}] Тип: Сканирование портов IP: {ip}\n")
                return {"src": ip, "type": "Сканирование портов", "word": None}
            if total_ports > 15:
                stats["LastThreat"] = {"type": "SYN-флуд", "ip": ip, "time": time.strftime('%Y-%m-%d %H:%M:%S')}
                stats["ThreatsNum"] += 1
                with open("nids_logs.txt", "a") as file:
                    now = time.strftime('%Y-%m-%d %H:%M:%S')
                    file.write(f"[{now}] Тип: SYN-флуд IP: {ip}\n")
                return {"src":ip, "type": "SYN-флуд", "word": None}

def pack_processing(pack):
    stats["TotalPacks"] += 1
    
    check_port_scanning(pack)

    if IP in pack:
        src = pack[IP].src
        dst = pack[IP].dst

    if TCP in pack and Raw in pack:
        try:
            data = pack[Raw].load.decode('utf-8',errors='ignore')
            
            rules = [
                ("SQL-иньекция", ["union", "select from", "or 1=1", "'--"]),
                ("Межсайтовый скриптинг (XSS)", ["<script>", "javascript:", "alert("]),
                ("Path Traversal (Обход путей)", ["etc/passwd", "etc/shadow", "win.ini"])
            ]

            for type, keywords in rules:
                for word in keywords:
                    if word.lower() in data.lower():
                        stats['ThreatsNum'] += 1
                        stats["LastThreat"] = {"type": type, "ip": src, "time": time.strftime('%Y-%m-%d %H:%M:%S')}

                        with open("nids_logs.txt", "a") as file:
                            now = time.strftime('%Y-%m-%d %H:%M:%S')
                            file.write(f"[{now}] Тип: {type} IP: {src}\n")
                            
                        return {"src": src, "type": type, "word": word}
                        break
        except:
            pass    

def show_stats():
    return stats
        
def show_logs():
    try:
        with open("nids_logs.txt", "r") as file:
            logs = file.readlines()
            if logs:
                for s in logs[-10:]:
                    s = s.strip()
                    try:
                        type = re.search("Тип: (.+?) IP", s)
                        ip = re.search(" IP:(.+?)",s)
                    except:
                        type = ''
                    return {"time": s[1:20], "type": type, "ip": ip}
            else:
                return None #Пустые логи
    except FileNotFoundError:
        return None

def run_nids():
    stop_event.clear()
    
    try:
        sniff(prn=pack_processing, store=0, count=0, stop_filter=lambda x: stop_event.is_set())
    except:
        print("\nКонец работы программы")
        
def stop_nids():
    stop_event.set()
    
@app.route("/")
def index():
    return app.send_static_file("guard_ui.html")
    
@app.route("/api/start", methods=["POST"])
def api_start():
    global nids_thread
    if not nids_thread or not nids_thread.is_alive():
        nids_thread = threading.Thread(target=run_nids, daemon=True)
        nids_thread.start()
    return jsonify({"running": True})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    stop_nids()
    return jsonify({"running": False})

@app.route("/api/stats")
def api_stats():
    ip = ''
    time = ''
    try:
        with open("nids_logs.txt", "r") as f:
            for line in f.readlines()[-1]:
                line = line.strip()
                ip = re.search("IP: (.+)", line)
                time = line[1:20]
    except FileNotFoundError:
        pass
        
    return jsonify({
        "total_packets": stats["TotalPacks"],
        "total_threats": stats["ThreatsNum"],
        "last_threat": stats["LastThreat"],
    })

@app.route("/api/logs")
def api_logs():
    logs = []
    try:
        with open("nids_logs.txt", "r") as f:
            for line in f.readlines()[-50:]:
                line = line.strip()
                t = re.search("Тип: (.+?) IP", line)
                ip = re.search("IP: (.+)", line)
                logs.append({
                    "time": line[1:20],
                    "type": t.group(1) if t else "Unknown",
                    "ip": ip.group(1) if ip else "?"
                })
    except FileNotFoundError:
        pass
    return jsonify(list(reversed(logs)))

if __name__ == "__main__":
    app.run(debug=True)



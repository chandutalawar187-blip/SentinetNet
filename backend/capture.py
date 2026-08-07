from scapy.all import sniff
from collections import defaultdict
from datetime import datetime

import json
import time
import socket
import threading
import joblib
import pandas as pd

# Interface can be provided via CLI --iface or SENTINET_INTERFACE env var
import os
import argparse

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('--iface', default=None)
args, _ = parser.parse_known_args()

INTERFACE = args.iface or os.environ.get('SENTINET_INTERFACE')

_DIR = os.path.dirname(os.path.abspath(__file__))
ALERT_FILE = os.path.join(_DIR, "..", "shared", "alerts.json")
ALERT_JSONL = os.path.join(_DIR, "..", "shared", "alerts.jsonl")
BLOCKED_FILE = os.path.join(_DIR, "..", "shared", "blocked.json")

# Normalize interface argument: accept interface name, IP address (map to OS interface), or tokens like 'loopback'
if not INTERFACE:
    INTERFACE = None
else:
    # Attempt to map IP -> interface name using scapy's get_if_list/get_if_addr where possible
    try:
        import ipaddress
        from scapy.all import get_if_list, get_if_addr
        is_ip = False
        try:
            ipaddress.ip_address(INTERFACE)
            is_ip = True
        except Exception:
            is_ip = False

        mapped_iface = None
        if is_ip:
            for ifname in get_if_list():
                try:
                    addr = get_if_addr(ifname)
                    if addr == INTERFACE:
                        mapped_iface = ifname
                        break
                except Exception:
                    continue
            # common token fallback for loopback IPs
            if not mapped_iface and INTERFACE.startswith('127.'):
                for ifname in get_if_list():
                    if 'loop' in ifname.lower() or ifname.lower().startswith('lo'):
                        mapped_iface = ifname
                        break
        else:
            # Accept tokens like 'loopback' or 'lo'
            if INTERFACE.lower() in ('loopback', 'lo'):
                for ifname in get_if_list():
                    if 'loop' in ifname.lower() or ifname.lower().startswith('lo'):
                        mapped_iface = ifname
                        break
            else:
                mapped_iface = INTERFACE

        if mapped_iface:
            INTERFACE = mapped_iface
            print(f"Mapped interface token/IP to OS interface: {INTERFACE}")
        else:
            print(f"Warning: could not map interface '{INTERFACE}' to an OS interface; using scapy default (None)")
            INTERFACE = None
    except Exception as e:
        print('Interface mapping disabled or failed:', e)
        # fallback to using the provided string as-is
        print(f"Using interface: {INTERFACE}")

WINDOW = 30

tcp_tracker = defaultdict(dict)
udp_tracker = defaultdict(dict)

last_attack = None

# Optional ML model and per-source stats
MODEL_FILE = os.path.join(_DIR, "..", "models", "cic_model.pkl")
ENCODER_FILE = os.path.join(_DIR, "..", "models", "cic_encoder.pkl")
model = None
encoder = None
try:
    model = joblib.load(MODEL_FILE)
    encoder = joblib.load(ENCODER_FILE)
    print("Loaded ML model and encoder")
except Exception as e:
    model = None
    encoder = None
    print("ML model not loaded:", e)

packet_counts = defaultdict(int)
byte_counts = defaultdict(int)
first_seen = {}

# Detection configuration (tunable thresholds)
PORTSCAN_THRESHOLD = 20        # unique destination ports in WINDOW -> PortScan
UDPSCAN_THRESHOLD = 5          # unique UDP ports in WINDOW -> UDP_SCAN
SYN_FLOOD_THRESHOLD = 50       # SYN packets in WINDOW -> SYN_FLOOD
ICMP_FLOOD_THRESHOLD = 50      # ICMP packets in WINDOW -> ICMP_FLOOD
SLOWLORIS_THRESHOLD = 30       # many small TCP payloads in WINDOW -> SLOWLORIS
WINDOW = 30                    # sliding window in seconds for rate-based checks
BLOCK_ENABLED = True           # whether to auto-block high severity IPs
BLOCK_COOLDOWN = 300           # seconds to wait before re-blocking same IP

# Data breach / exfiltration thresholds
DATA_EXFIL_BYTES_TOTAL = 5 * 1024 * 1024   # total bytes in WINDOW considered exfiltration (5 MB)
DATA_EXFIL_RATE = 1 * 1024 * 1024          # bytes/sec rate that flags exfil (1 MB/s)

# Rate limiter configuration
RATE_LIMIT_PKT_PER_SEC = 200              # packets per second threshold
RATE_LIMIT_WINDOW = 5                     # seconds window for rate limiting
RATE_LIMIT_COOLDOWN = 60                  # seconds to ignore/process after rate limit

# Trackers for advanced detection
syn_timestamps = defaultdict(list)
icmp_timestamps = defaultdict(list)
small_payload_timestamps = defaultdict(list)
packet_timestamps = defaultdict(list)
rate_limited = {}
blocked_ips = {}
last_block_time = {}

# Load persistent blocked IPs if present
try:
    if os.path.exists(BLOCKED_FILE):
        with open(BLOCKED_FILE, 'r', encoding='utf-8') as _bf:
            data = _bf.read().strip()
            if data:
                loaded = json.loads(data)
                if isinstance(loaded, dict):
                    blocked_ips.update(loaded)
                elif isinstance(loaded, list):
                    # list of IPs -> set current time
                    for ip in loaded:
                        blocked_ips[ip] = time.time()
except Exception as e:
    print('Failed to load blocked file:', e)

MY_IP = socket.gethostbyname(
    socket.gethostname()
)

print(
    "Victim IP:",
    MY_IP
)


def block_ip(ip):
    # Blocking wrapper using netsh (Windows). Silently ignore localhost and private ranges.
    if not BLOCK_ENABLED:
        return
    if ip == '127.0.0.1' or ip.startswith('192.168.') or ip.startswith('10.'):
        # avoid blocking common local ranges by default
        return
    now = time.time()
    last = last_block_time.get(ip, 0)
    if now - last < BLOCK_COOLDOWN:
        return
    cmd = (
        f'netsh advfirewall firewall '
        f'add rule '
        f'name="SentinelBlock_{ip}" '
        f'dir=in '
        f'action=block '
        f'remoteip={ip}'
    )

    # Attempt to block at OS level, but always persist blocked list
    try:
        rc = os.system(cmd)
        print(f'netsh exit code: {rc}')
    except Exception as e:
        print('Failed to execute netsh:', e)

    # Record in memory and persist
    try:
        last_block_time[ip] = now
        blocked_ips[ip] = now
        with open(BLOCKED_FILE, 'w', encoding='utf-8') as bf:
            json.dump(blocked_ips, bf)
        print(f'Persisted blocked IP {ip} to {BLOCKED_FILE}')
    except Exception as e:
        print('Failed to persist blocked IP:', e)


def save_alert(alert):

    # Append each alert as a single JSON line to alerts.jsonl for atomic appends
    try:
        with open(ALERT_JSONL, 'a', encoding='utf-8') as f:
            f.write(json.dumps(alert, ensure_ascii=False) + '\n')
    except Exception as e:
        print('Failed to append alert to jsonl:', e)
        # Fallback: try to write to ALERT_FILE atomically
        try:
            alerts = []
            if os.path.exists(ALERT_FILE):
                with open(ALERT_FILE, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if content.strip():
                        alerts = json.loads(content)
            alerts.append(alert)
            tmp = ALERT_FILE + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(alerts, f, indent=4)
            os.replace(tmp, ALERT_FILE)
        except Exception as e2:
            print('Fallback write failed:', e2)


# Background writer: periodically consolidates alerts.jsonl into alerts.json (atomic replace)
def alerts_jsonl_to_json():
    tmp = ALERT_FILE + '.tmp'
    while True:
        try:
            if os.path.exists(ALERT_JSONL):
                alerts = []
                with open(ALERT_JSONL, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            alerts.append(json.loads(line))
                        except Exception as e:
                            # skip malformed line
                            print('Skipping malformed JSONL line:', e)
                # Write atomically
                with open(tmp, 'w', encoding='utf-8') as f:
                    json.dump(alerts, f, indent=4)
                try:
                    os.replace(tmp, ALERT_FILE)
                except Exception:
                    try:
                        os.remove(ALERT_FILE)
                    except Exception:
                        pass
                    os.replace(tmp, ALERT_FILE)
        except Exception as e:
            print('alerts_jsonl_to_json error:', e)
        time.sleep(2)

# Start consolidation thread
threading.Thread(target=alerts_jsonl_to_json, daemon=True).start()


def create_alert(
    attack,
    src,
    ports,
    host,
    mac,
    port_list
):

    global last_attack

    key = (
        attack,
        src
    )

    if key == last_attack:
        return

    last_attack = key

    risk = min(
        ports * 5,
        100
    )

    severity = "LOW"

    if risk >= 80:

        severity = "HIGH"

    elif risk >= 50:

        severity = "MEDIUM"

    alert = {

        "time":
        str(
            datetime.now()
        ),

        "attack":
        attack,

        "attacker":
        src,

        "attacker_host":
        host,

        "attacker_mac":
        mac,

        "ports":
        ports,

        "attacked_ports":
        port_list,

        "severity":
        severity,

        "risk_score":
        risk,

        "analysis":
        f"{attack} detected",

        "explanation":
        "Traffic aggregation analysis",

        "recommendation":
        "Investigate source"

    }

    print(alert)

    save_alert(
        alert
    )


def cleanup():

    global last_attack

    while True:

        now = time.time()

        for src in list(
            tcp_tracker.keys()
        ):

            tcp_tracker[src] = {

                p:t

                for p,t

                in tcp_tracker[
                    src
                ].items()

                if now - t < WINDOW

            }

            ports = len(
                tcp_tracker[src]
            )

            print(
                f"ACTIVE TCP={ports}"
            )

            if ports < 10:

                last_attack = None

        for src in list(
            udp_tracker.keys()
        ):

            udp_tracker[src] = {

                p:t

                for p,t

                in udp_tracker[
                    src
                ].items()

                if now - t < WINDOW

            }

        time.sleep(1)


def process(packet):

    global last_attack

    try:

        if not packet.haslayer(
            "IP"
        ):
            return

        src = packet[
            "IP"
        ].src

        if src == MY_IP:
            return

        # Ignore already-blocked IPs immediately
        if src in blocked_ips:
            # If within cooldown, skip processing
            last_blk = blocked_ips.get(src, 0)
            if time.time() - last_blk < BLOCK_COOLDOWN:
                print(f'Ignored packet from blocked IP {src}')
                return

        # Rate limiter: track packet arrival timestamps and apply cooldown
        now = time.time()
        packet_timestamps[src].append(now)
        # prune timestamps older than RATE_LIMIT_WINDOW
        packet_timestamps[src] = [t for t in packet_timestamps[src] if now - t < RATE_LIMIT_WINDOW]
        # compute rate (per-second approximate)
        recent_count = len([t for t in packet_timestamps[src] if now - t < 1])
        if src in rate_limited:
            # still in cooldown?
            if now - rate_limited[src] < RATE_LIMIT_COOLDOWN:
                # drop processing to reduce load
                print(f'Rate-limited: dropping packet from {src}')
                return
            else:
                del rate_limited[src]

        if recent_count >= RATE_LIMIT_PKT_PER_SEC:
            # Trigger rate-limit action
            rate_limited[src] = now
            print(f'Rate limit triggered for {src} (pkts/s={recent_count})')
            try:
                create_alert('RATE_LIMIT', src, recent_count, 'Unknown Device', 'Unknown', [])
            except Exception:
                pass
            return

        try:
            host = socket.gethostbyaddr(
                src
            )[0]

        except:

            host = "Unknown Device"

        mac = "Unknown"

        if packet.haslayer(
            "Ether"
        ):

            mac = packet[
                "Ether"
            ].src

        if packet.haslayer(
            "TCP"
        ):

            port = packet[
                "TCP"
            ].dport

            tcp_tracker[src][port] = time.time()

            ports = len(
                tcp_tracker[src]
            )

            port_list = sorted(

                list(

                    tcp_tracker[
                        src
                    ].keys()

                )

            )

            print(
                f"TCP PORTS={ports}"
            )

            # Update simple per-source counters
            packet_counts[src] += 1
            try:
                byte_counts[src] += len(packet)
            except Exception:
                byte_counts[src] += 0
            if src not in first_seen:
                first_seen[src] = time.time()

            now = time.time()
            # TCP flags - robust check using bitmask
            try:
                tcp_flags_val = int(packet['TCP'].flags)
            except Exception:
                try:
                    tcp_flags_val = int(str(packet['TCP'].flags))
                except Exception:
                    tcp_flags_val = 0

            # SYN flag is 0x02
            if tcp_flags_val & 0x02:
                syn_timestamps[src].append(now)
                # prune old
                syn_timestamps[src] = [t for t in syn_timestamps[src] if now - t < WINDOW]

            # Update small-payload tracker for Slowloris-like behavior
            try:
                payload_len = len(bytes(packet['TCP'].payload))
            except Exception:
                payload_len = 0

            if payload_len > 0 and payload_len < 200:
                small_payload_timestamps[src].append(now)
                small_payload_timestamps[src] = [t for t in small_payload_timestamps[src] if now - t < WINDOW]

            # Decide attack by priority: SYN flood, portscan, slowloris, ML/heuristic
            attack = None

            # SYN flood detection
            if len(syn_timestamps[src]) >= SYN_FLOOD_THRESHOLD:
                attack = 'SYN_FLOOD'

            # Port scan override
            if attack is None and ports >= PORTSCAN_THRESHOLD:
                attack = 'PortScan'

            # Slowloris detection
            if attack is None and len(small_payload_timestamps[src]) >= SLOWLORIS_THRESHOLD:
                attack = 'SLOWLORIS'

            # If still undecided, use ML or fallback heuristic
            if attack is None:
                if model is not None:
                    duration = now - first_seen.get(src, now)
                    if duration <= 0:
                        duration = 0.0001
                    try:
                        feature_cols = getattr(model, 'feature_names_in_', None)
                        if feature_cols is not None:
                            row = {c: 0.0 for c in feature_cols}
                            row.update({
                                'Flow Duration': duration,
                                'Total Fwd Packets': packet_counts[src],
                                'Total Backward Packets': 0,
                                'Flow Bytes/s': byte_counts[src] / duration,
                                'Flow Packets/s': packet_counts[src] / duration
                            })
                            X_row = pd.DataFrame([row], columns=feature_cols)
                        else:
                            X_row = pd.DataFrame([{
                                'Flow Duration': duration,
                                'Total Fwd Packets': packet_counts[src],
                                'Total Backward Packets': 0,
                                'Flow Bytes/s': byte_counts[src] / duration,
                                'Flow Packets/s': packet_counts[src] / duration
                            }])
                    except Exception:
                        X_row = pd.DataFrame([{
                            'Flow Duration': duration,
                            'Total Fwd Packets': packet_counts[src],
                            'Total Backward Packets': 0,
                            'Flow Bytes/s': byte_counts[src] / duration,
                            'Flow Packets/s': packet_counts[src] / duration
                        }])
                    try:
                        pred = model.predict(X_row)[0]
                        try:
                            attack = encoder.inverse_transform([pred])[0]
                        except Exception:
                            attack = str(pred)
                    except Exception as e:
                        print('Model prediction failed:', e)
                        # fallback to heuristic
                        if ports >= 10:
                            attack = 'SUSPICIOUS'
                        else:
                            attack = 'BENIGN'
                else:
                    if ports >= 10:
                        attack = 'SUSPICIOUS'
                    else:
                        attack = 'BENIGN'

            # If a high-severity network attack detected, block the IP
            if attack in ('SYN_FLOOD', 'SYN_FLOOD', 'PortScan', 'SLOWLORIS'):
                try:
                    block_ip(src)
                except Exception as e:
                    print('Auto-block failed:', e)

        elif packet.haslayer(
            "UDP"
        ):

            port = packet[
                "UDP"
            ].dport

            udp_tracker[src][port] = time.time()

            ports = len(
                udp_tracker[src]
            )

            port_list = sorted(

                list(

                    udp_tracker[
                        src
                    ].keys()

                )

            )

            print(
                f"UDP PORTS={ports}"
            )

            # Update per-source counters
            packet_counts[src] += 1
            try:
                byte_counts[src] += len(packet)
            except Exception:
                byte_counts[src] += 0
            if src not in first_seen:
                first_seen[src] = time.time()

            # Prefer heuristic override for clear UDP scans
            if ports >= UDPSCAN_THRESHOLD:
                attack = "UDP_SCAN"

            else:
                # small UDP flows still analyzed by ML if available
                if model is not None:
                    now = time.time()
                    duration = now - first_seen.get(src, now)
                    if duration <= 0:
                        duration = 0.0001
                    try:
                        feature_cols = getattr(model, 'feature_names_in_', None)
                        if feature_cols is not None:
                            row = {c: 0.0 for c in feature_cols}
                            row.update({
                                "Flow Duration": duration,
                                "Total Fwd Packets": packet_counts[src],
                                "Total Backward Packets": 0,
                                "Flow Bytes/s": byte_counts[src] / duration,
                                "Flow Packets/s": packet_counts[src] / duration
                            })
                            X_row = pd.DataFrame([row], columns=feature_cols)
                        else:
                            X_row = pd.DataFrame([{
                                "Flow Duration": duration,
                                "Total Fwd Packets": packet_counts[src],
                                "Total Backward Packets": 0,
                                "Flow Bytes/s": byte_counts[src] / duration,
                                "Flow Packets/s": packet_counts[src] / duration
                            }])
                    except Exception:
                        X_row = pd.DataFrame([{
                            "Flow Duration": duration,
                            "Total Fwd Packets": packet_counts[src],
                            "Total Backward Packets": 0,
                            "Flow Bytes/s": byte_counts[src] / duration,
                            "Flow Packets/s": packet_counts[src] / duration
                        }])
                    try:
                        pred = model.predict(X_row)[0]
                        try:
                            attack = encoder.inverse_transform([pred])[0]
                        except Exception:
                            attack = str(pred)
                    except Exception as e:
                        print("Model prediction failed:", e)
                        # fallback heuristic
                        if ports >= UDPSCAN_THRESHOLD:
                            attack = "UDP_SCAN"
                        elif ports >= 3:
                            attack = "SUSPICIOUS"
                        else:
                            attack = "BENIGN"
                else:
                    if ports >= UDPSCAN_THRESHOLD:
                        attack = "UDP_SCAN"
                    elif ports >= 3:
                        attack = "SUSPICIOUS"
                    else:
                        attack = "BENIGN"

        elif packet.haslayer(
            "ICMP"
        ):
            # ICMP flood detection
            try:
                icmp_timestamps[src].append(time.time())
                now = time.time()
                icmp_timestamps[src] = [t for t in icmp_timestamps[src] if now - t < WINDOW]
                ports = len(icmp_timestamps[src])
                port_list = []
                if ports >= ICMP_FLOOD_THRESHOLD:
                    attack = 'ICMP_FLOOD'
                else:
                    attack = 'BENIGN'
            except Exception as e:
                print('ICMP processing error:', e)
                return

        else:

            return

        print(
            "ML ->",
            attack
        )

        if attack != "BENIGN":

            create_alert(

                attack,

                src,

                ports,

                host,

                mac,

                port_list

            )

            # Auto-block high severity attacks
            try:
                if attack in ("PortScan", "SYN_FLOOD", "ICMP_FLOOD", "SLOWLORIS"):
                    block_ip(src)
                elif attack == "UDP_SCAN" and ports >= 10:
                    block_ip(src)
            except Exception as e:
                print('Block after alert failed:', e)

    except Exception as e:

        print(e)


threading.Thread(

    target=cleanup,

    daemon=True

).start()

print(
    "SentinelNet started..."
)

sniff(

    iface=INTERFACE,

    prn=process,

    store=0

)
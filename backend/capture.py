from scapy.all import sniff
from collections import defaultdict
from datetime import datetime

import json
import time
import socket
import threading

INTERFACE = r"\Device\NPF_Loopback"

ALERT_FILE = "../shared/alerts.json"

WINDOW = 30

tcp_tracker = defaultdict(dict)
udp_tracker = defaultdict(dict)

last_attack = None

MY_IP = socket.gethostbyname(
    socket.gethostname()
)

print(
    "Victim IP:",
    MY_IP
)


def save_alert(alert):

    alerts = []

    try:

        with open(
            ALERT_FILE,
            "r"
        ) as f:

            content = f.read()

            if content.strip():

                alerts = json.loads(
                    content
                )

    except:

        alerts = []

    alerts.append(
        alert
    )

    with open(
        ALERT_FILE,
        "w"
    ) as f:

        json.dump(
            alerts,
            f,
            indent=4
        )


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

            if ports >= 20:

                attack = "PortScan"

            elif ports >= 10:

                attack = "SUSPICIOUS"

            else:

                attack = "BENIGN"

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

            if ports >= 5:

                attack = "UDP_SCAN"

            elif ports >= 3:

                attack = "SUSPICIOUS"

            else:

                attack = "BENIGN"

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
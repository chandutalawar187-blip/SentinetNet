from collections import defaultdict
import time

ports_seen = defaultdict(set)
timestamps = defaultdict(list)

WINDOW = 10

def detect(src_ip, dst_port):

    current = time.time()

    timestamps[src_ip].append(current)

    timestamps[src_ip] = [
        t for t in timestamps[src_ip]
        if current - t < WINDOW
    ]

    ports_seen[src_ip].add(dst_port)

    if len(ports_seen[src_ip]) > 10:
        return "PORT_SCAN"

    return "NORMAL"
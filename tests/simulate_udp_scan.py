from scapy.all import IP, UDP, send
import time

# Destination is localhost loopback interface used by capture.py
dst = '127.0.0.1'
src = '127.0.0.2'

ports = list(range(4000, 4036))  # 36 ports

print(f"Sending {len(ports)} UDP packets to {dst} from {src}...")
for p in ports:
    pkt = IP(dst=dst, src=src)/UDP(dport=p)/b"test"
    send(pkt, verbose=False)
    time.sleep(0.05)

print("Done")

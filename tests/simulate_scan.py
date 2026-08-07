from scapy.all import IP, TCP, send
import time

# Destination is localhost loopback interface used by capture.py
dst = '127.0.0.1'
# Use an alternate loopback source to avoid being filtered as MY_IP in capture
src = '127.0.0.2'

ports = list(range(2000, 2035))  # 35 ports

print(f"Sending {len(ports)} TCP SYN packets to {dst} from {src}...")
for p in ports:
    pkt = IP(dst=dst, src=src)/TCP(dport=p, flags='S')
    send(pkt, verbose=False)
    time.sleep(0.05)  # 50ms between packets

print("Done")

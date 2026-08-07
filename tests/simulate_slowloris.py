from scapy.all import IP, TCP, send
import time

# Slowloris-like: many small TCP payloads to same port spaced out

dst = '127.0.0.1'
src = '127.0.0.2'
port = 8080

packets = 80
print(f"Sending {packets} small TCP payloads slowly to {dst}:{port} from {src}...")
for i in range(packets):
    pkt = IP(dst=dst, src=src)/TCP(dport=port, sport=2000 + (i % 40000), flags='PA')/b'GET / HTTP/1.1\r\nHost: localhost\r\n'
    send(pkt, verbose=False)
    time.sleep(0.5)

print('Done')

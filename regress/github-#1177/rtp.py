# Listen on the address:port argument for RTP until 1 s passes without
# a packet (5 s at most), and print the number of payload bytes that
# arrived and the number of them that are 0x50.
import socket
import sys
import time

ip, port = sys.argv[1].split(":")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((ip, int(port)))
payload = b""
end = time.monotonic() + 5
while (left := end - time.monotonic()) > 0:
    s.settimeout(min(left, 1) if payload else left)
    try:
        payload += s.recv(2048)[12:]
    except socket.timeout:
        break
print(len(payload), payload.count(0x50))

# From port 28900 (in the SDP of uac.xml), send an RTP packet to the
# port every 2 ms, and print how long after the first one the first
# echo comes in, in ms (999: none in 500 ms).
import select
import socket
import struct
import sys
import time

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 28900))
to = ("127.0.0.1", int(sys.argv[1]))
start = time.monotonic()
seq = 0
while time.monotonic() - start < 0.5:
    s.sendto(struct.pack("!HHII", 0x8000, seq & 0xFFFF, 160 * seq, 1) + b"\xff" * 160, to)
    if select.select([s], [], [], 0.002)[0]:
        print(int(1000 * (time.monotonic() - start)))
        sys.exit()
    seq += 1
print(999)

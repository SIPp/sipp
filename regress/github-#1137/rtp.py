# Listen on each address:port argument for 4 s, echo the packets that
# arrive, and print the number of them at each, in the order of the
# arguments.
import select
import socket
import sys
import time

socks = []
for arg in sys.argv[1:]:
    ip, port = arg.split(":")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, int(port)))
    s.setblocking(False)
    socks.append(s)
counts = [0] * len(socks)
end = time.monotonic() + 4
while (left := end - time.monotonic()) > 0:
    for s in select.select(socks, [], [], left)[0]:
        try:
            while True:
                data, peer = s.recvfrom(2048)
                s.sendto(data, peer)
                counts[socks.index(s)] += 1
        except BlockingIOError:
            pass
print(*counts)

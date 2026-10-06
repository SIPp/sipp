# Open the address:port argument for RTP half a second late, when the
# call has started to play to it, and print the number of packets that
# arrive until 1 s passes without one (6 s at most).
import socket
import sys
import time

ip, port = sys.argv[1].split(":")
time.sleep(0.5)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((ip, int(port)))
packets = 0
end = time.monotonic() + 6
while (left := end - time.monotonic()) > 0:
    s.settimeout(min(left, 1) if packets else left)
    try:
        s.recv(2048)
        packets += 1
    except socket.timeout:
        break
print(packets)

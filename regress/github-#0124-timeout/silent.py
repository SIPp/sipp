#!/usr/bin/env python3
# This regression test is a part of SIPp.
# silent.py server PORT: accept connections and never answer their
# WebSocket handshake, keeping them open; print the number of each one
# as it comes, until killed. silent.py client PORT:
# connect and send nothing; print how long until the server closes.
import socket
import sys
import time

mode, port = sys.argv[1], int(sys.argv[2])
if mode == "server":
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(8)
    conns = []
    while True:
        conns.append(s.accept()[0])
        print(len(conns), flush=True)
else:
    c = socket.create_connection(("127.0.0.1", port))
    c.settimeout(8)
    start = time.time()
    try:
        c.recv(1)
    except (socket.timeout, ConnectionResetError):
        pass
    print("%.1f" % (time.time() - start), flush=True)

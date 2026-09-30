#!/usr/bin/env python3
# This regression test is a part of SIPp.
# A TCP UAS on 127.0.0.1 whose first connection fails after the call is
# set up, as a proxy's does when it fails over to its backup: peer.py
# PORT MODE, MODE "reset" to reset it when the BYE comes, unanswered,
# "close" to close it after the ACK. It answers the BYE that comes on a
# second connection, and exits 0 once it has.
import re
import socket
import struct
import sys

PORT, MODE = int(sys.argv[1]), sys.argv[2]


def messages(conn):
    """The start lines and headers of the messages of a connection."""
    data = b""
    while True:
        while b"\r\n\r\n" in data:
            head, rest = data.split(b"\r\n\r\n", 1)
            m = re.search(rb"(?im)^(?:content-length|l)\s*:\s*(\d+)", head)
            n = int(m.group(1)) if m else 0
            if len(rest) < n:
                break
            data = rest[n:]
            yield head.decode()
        more = conn.recv(65536)
        if not more:
            return
        data += more


def answer(conn, head):
    lines = [h for h in head.split("\r\n")[1:]
             if re.match(r"(?i)(via|from|to|call-id|cseq)\s*:", h)]
    lines = [h + ";tag=peer" if re.match(r"(?i)to\s*:", h) and "tag=" not in h
             else h for h in lines]
    conn.sendall(("SIP/2.0 200 OK\r\n" + "\r\n".join(lines) +
                  "\r\nContact: <sip:peer@127.0.0.1:%d;transport=tcp>\r\n"
                  "Content-Length: 0\r\n\r\n" % PORT).encode())


listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", PORT))
listener.listen(1)
listener.settimeout(5)

conn = listener.accept()[0]
for head in messages(conn):
    method = head.split(" ", 1)[0]
    if method == "INVITE":
        answer(conn, head)
    elif method == "ACK" and MODE == "close":
        conn.close()
        break
    elif method == "BYE":
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        conn.close()
        break

conn = listener.accept()[0]
for head in messages(conn):
    if head.startswith("BYE "):
        answer(conn, head)
        sys.exit(0)
sys.exit(1)

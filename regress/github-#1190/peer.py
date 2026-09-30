# The peer of uas.xml: the INVITE and its ACK come from one port, the
# re-INVITE, its CANCEL and ACK, and the BYE from another, as when a
# proxy fails over. Each response must come to the port of its request.
# Usage: peer.py udp|tcp <sipp port> <first port> <second port>
import re
import socket
import sys

proto, sipp_port, port1, port2 = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
sipp = ("127.0.0.1", sipp_port)
call_id = "resp-dest-%s@127.0.0.1" % proto
from_hdr = "<sip:peer@127.0.0.1>;tag=peer1"


def fail(why):
    print(why, file=sys.stderr)
    sys.exit(1)


class Peer:
    def __init__(self, port):
        self.port = port
        self.buf = b""
        if proto == "udp":
            self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.s.bind(("127.0.0.1", port))
        else:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.s.bind(("127.0.0.1", port))
            self.s.connect(sipp)

    def send(self, msg):
        msg = msg.replace("\n", "\r\n").encode()
        if proto == "udp":
            self.s.sendto(msg, sipp)
        else:
            self.s.sendall(msg)

    def recv(self, timeout):
        """The next message, or None."""
        self.s.settimeout(timeout)
        try:
            if proto == "udp":
                return self.s.recv(65535).decode()
            while True:
                m = re.match(rb"(.*?\r\n\r\n)", self.buf, re.S)
                if m:
                    cl = re.search(rb"\r\nContent-Length: *(\d+)", m.group(1), re.I)
                    end = len(m.group(1)) + (int(cl.group(1)) if cl else 0)
                    if len(self.buf) >= end:
                        msg, self.buf = self.buf[:end], self.buf[end:]
                        return msg.decode()
                data = self.s.recv(65535)
                if not data:
                    return None
                self.buf += data
        except socket.timeout:
            return None

    def expect(self, status, cseq):
        """Wait for the response status to cseq, skipping retransmissions
        of earlier ones."""
        while True:
            msg = self.recv(5)
            if msg is None:
                fail("port %d: no %d to %s" % (self.port, status, cseq))
            first = msg.split("\r\n", 1)[0]
            got = re.search(r"^CSeq: *(.*?)\r$", msg, re.M | re.I).group(1)
            if first.startswith("SIP/2.0 %d " % status) and got == cseq:
                return msg

    def request(self, method, cseq, branch, to):
        tp = proto.upper()
        self.send("%s sip:sipp@127.0.0.1:%d SIP/2.0\n"
                  "Via: SIP/2.0/%s 127.0.0.1:%d;branch=%s\n"
                  "From: %s\n"
                  "To: %s\n"
                  "Call-ID: %s\n"
                  "CSeq: %s\n"
                  "Contact: <sip:peer@127.0.0.1:%d;transport=%s>\n"
                  "Max-Forwards: 70\n"
                  "Content-Length: 0\n\n"
                  % (method, sipp_port, tp, self.port, branch, from_hdr, to,
                     call_id, cseq, self.port, proto))


a = Peer(port1)
a.request("INVITE", "1 INVITE", "z9hG4bK-a1", "<sip:sipp@127.0.0.1>")
ok = a.expect(200, "1 INVITE")
to = re.search(r"^To: *(.*?)\r$", ok, re.M).group(1)
a.request("ACK", "1 ACK", "z9hG4bK-a2", to)

b = Peer(port2)
b.request("INVITE", "2 INVITE", "z9hG4bK-b1", to)
b.request("CANCEL", "2 CANCEL", "z9hG4bK-b1", to)
b.expect(487, "2 INVITE")
b.expect(200, "2 CANCEL")
b.request("ACK", "2 ACK", "z9hG4bK-b1", to)
b.request("BYE", "3 BYE", "z9hG4bK-b2", to)
b.expect(200, "3 BYE")

# Nothing but the answers to the first INVITE on the first port.
while True:
    msg = a.recv(0.5)
    if msg is None:
        break
    if not re.search(r"^CSeq: *1 INVITE\r$", msg, re.M):
        fail("port %d got: %s" % (port1, msg.split("\r\n", 1)[0]))

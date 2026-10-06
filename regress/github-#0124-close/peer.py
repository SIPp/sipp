#!/usr/bin/env python3
# This regression test is a part of SIPp.
# WebSocket clients that close, break the rules, or ping without reading,
# against a SIPp UAS with -aa on 127.0.0.1: peer.py PORT [CERT] (WSS if
# a CERT is given; then it only closes in the middle of a TLS record).
import socket
import ssl
import struct
import sys

PORT = int(sys.argv[1])
HANDSHAKE = (b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
             b"Connection: Upgrade\r\n"
             b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
             b"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: sip\r\n\r\n")
OPTIONS = ("OPTIONS sip:uas@127.0.0.1 SIP/2.0\r\n"
           "Via: SIP/2.0/WS 127.0.0.1:9;branch=z9hG4bK-%s\r\n"
           "From: <sip:py@127.0.0.1>;tag=py\r\n"
           "To: <sip:uas@127.0.0.1>\r\n"
           "Call-ID: %s@127.0.0.1\r\n"
           "CSeq: 1 OPTIONS\r\n"
           "Content-Length: 0\r\n\r\n")


def fail(why):
    print(why, file=sys.stderr, flush=True)
    sys.exit(1)


def frame(opcode, payload, mask=b"\1\2\3\4"):
    """A client's frame, masked."""
    if isinstance(payload, str):
        payload = payload.encode()
    n = len(payload)
    head = struct.pack("!BB", 0x80 | opcode, 0x80 | n) if n < 126 else \
        struct.pack("!BBH", 0x80 | opcode, 0x80 | 126, n)
    if mask == b"\0\0\0\0":
        return head + mask + payload
    return head + mask + bytes(c ^ mask[i % 4] for i, c in enumerate(payload))


def frames(data):
    """The opcodes and payloads of a server's frames."""
    out = []
    while len(data) >= 2:
        n, h = data[1] & 0x7f, 2
        if n == 126:
            n, h = struct.unpack("!H", data[2:4])[0], 4
        out.append((data[0] & 0xf, data[h:h + n]))
        data = data[h + n:]
    return out


def opened(rcvbuf=0):
    s = socket.socket()
    if rcvbuf:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    s.settimeout(5)
    s.connect(("127.0.0.1", PORT))
    s.sendall(HANDSHAKE)
    head = b""
    while b"\r\n\r\n" not in head:
        data = s.recv(4096)
        if not data:
            fail("closed during the handshake")
        head += data
    if not head.startswith(b"HTTP/1.1 101 "):
        fail("got %r" % head)
    return s, head.split(b"\r\n\r\n", 1)[1]


def until_eof(s, data=b""):
    """What the server sends, until it closes the connection."""
    while True:
        try:
            more = s.recv(65536)
        except socket.timeout:
            fail("the server does not close the connection")
        if not more:
            s.close()
            return frames(data)
        data += more


def expect_close(name, sent, code):
    s, rest = opened()
    s.sendall(sent)
    got = until_eof(s, rest)
    if got != [(0x8, struct.pack("!H", code))]:
        fail("%s: got %r" % (name, got))


def ping_flood():
    # Pings with a small receive buffer, and no reading meanwhile: SIPp
    # answers the last one, but not all of them.
    s, rest = opened(4096)
    count = 100000
    # A mask of zeros, to make them fast.
    zero = b"\0\0\0\0"
    s.sendall(b"".join(frame(0x9, b"%07d" % i + b"p" * 118, zero) for i in range(count)))
    s.sendall(frame(0x8, b"\x03\xe8"))
    got = until_eof(s, rest)
    pongs = [p for op, p in got if op == 0xa]
    if not pongs or pongs[-1][:7] != b"%07d" % (count - 1) or \
            got[-1] != (0x8, b"\x03\xe8"):
        fail("no pong to the last ping, or no close after it")
    if len(pongs) > count // 2:
        fail("%d pongs to %d pings" % (len(pongs), count))

    # Pings, and a reset without reading the pongs.
    s, rest = opened(4096)
    s.sendall(frame(0x9, b"p" * 125, zero) * count)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.close()


def alive():
    s, rest = opened()
    s.sendall(frame(0x1, OPTIONS % ("alive", "alive")))
    s.sendall(frame(0x8, b"\x03\xe8"))
    got = until_eof(s, rest)
    if len(got) != 2 or not got[0][1].startswith(b"SIP/2.0 200 "):
        fail("the UAS does not answer: %r" % got)


def wss(cert):
    # A SIP message and a close in one TLS record, and then half of
    # another record: the UAS answers, closes, and goes on.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cert)
    ctx.check_hostname = False
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(incoming, outgoing)
    s = socket.create_connection(("127.0.0.1", PORT), 5)

    def read():
        while True:
            try:
                return tls.read(65536)
            except ssl.SSLWantReadError:
                data = s.recv(65536)
                if not data:
                    return b""
                incoming.write(data)
            except ssl.SSLError:
                return b""

    while True:
        try:
            tls.do_handshake()
            break
        except ssl.SSLWantReadError:
            s.sendall(outgoing.read())
            incoming.write(s.recv(65536))
    tls.write(HANDSHAKE)
    s.sendall(outgoing.read())
    head = b""
    while b"\r\n\r\n" not in head:
        head += read()
    tls.write(frame(0x1, OPTIONS % ("wss", "wss")) + frame(0x8, b"\x03\xe8"))
    s.sendall(outgoing.read())
    data = head.split(b"\r\n\r\n", 1)[1]
    while len(frames(data)) < 2:
        more = read()
        if not more:
            break
        data += more
    got = frames(data)
    if len(got) != 2 or not got[0][1].startswith(b"SIP/2.0 200 ") or \
            got[1] != (0x8, b"\x03\xe8"):
        fail("WSS: got %r" % got)
    # Half a record, which SIPp does not read unless it goes on reading
    # after the close; it may have closed the connection already.
    tls.write(b"x" * 100)
    record = outgoing.read()
    try:
        s.sendall(record[:len(record) // 2])
        s.recv(65536)
    except OSError:
        pass
    s.close()

if len(sys.argv) > 2:
    wss(sys.argv[2])
    sys.exit(0)

# The answer to a message goes before the close that came with it, and
# then the server closes the connection.
s, rest = opened()
s.sendall(frame(0x1, OPTIONS % ("close", "close")) + frame(0x8, b"\x03\xe8"))
got = until_eof(s, rest)
if len(got) != 2 or not got[0][1].startswith(b"SIP/2.0 200 ") or \
        got[1] != (0x8, b"\x03\xe8"):
    fail("an OPTIONS and a close: got %r" % got)

expect_close("a close alone", frame(0x8, b"\x03\xe8"), 1000)
expect_close("a status code for no frame", frame(0x8, b"\x03\xed"), 1002)
expect_close("a reason that is not UTF-8", frame(0x8, b"\x03\xe8\xff"), 1007)
expect_close("a text message that is not UTF-8", frame(0x1, b"\xff OPTIONS"), 1007)
ping_flood()
alive()

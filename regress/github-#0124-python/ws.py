#!/usr/bin/env python3
# This regression test is a part of SIPp.
# The other end of SIPp's SIP over WebSocket, from the websockets library.
#   ws.py server PORT [CERT KEY]: a UAS for one call, on path /sip; over
#   TLS with a certificate.
#   ws.py client PORT: a UAC for one call, and a peer that breaks the
#   framing, which SIPp must drop.
import asyncio
import re
import socket
import ssl
import struct
import sys

import websockets


def fail(why):
    print(why, file=sys.stderr, flush=True)
    sys.exit(1)


def reply(req, code):
    lines = req.split("\r\n")
    out = ["SIP/2.0 " + code]
    for line in lines[1:]:
        if re.match(r"(?i)(via|from|call-id|cseq):", line):
            out.append(line)
        elif re.match(r"(?i)to:", line):
            out.append(line if "tag=" in line else line + ";tag=py")
    return "\r\n".join(out) + "\r\nContent-Length: 0\r\n\r\n"


def frame(opcode, payload):
    """A server's frame, unmasked."""
    if isinstance(payload, str):
        payload = payload.encode()
    n = len(payload)
    head = struct.pack("!BB", 0x80 | opcode, n) if n < 126 else \
        struct.pack("!BBH", 0x80 | opcode, 126, n)
    return head + payload


async def uas(ws, path=None):
    request = getattr(ws, "request", None)
    path = request.path if request else (path or ws.path)
    if path != "/sip" or ws.subprotocol != "sip":
        fail("path %r, subprotocol %r" % (path, ws.subprotocol))
    async for msg in ws:
        if isinstance(msg, bytes):
            fail("a binary frame from SIPp")
        first = msg.split("\r\n", 1)[0]
        if not re.search(r"(?m)^Via: SIP/2\.0/WSS? ", msg):
            fail("no WS Via in " + first)
        if first.startswith("INVITE"):
            # In one write: a binary frame, a text one, and a keepalive.
            # And a ping.
            ws.transport.write(frame(0x2, reply(msg, "100 Trying")) +
                               frame(0x1, reply(msg, "200 OK")) +
                               frame(0x1, "\r\n\r\n"))
            await asyncio.wait_for(await ws.ping(b"hello"), 5)
        elif first.startswith("BYE"):
            # A message in fragments.
            ok = reply(msg, "200 OK")
            await ws.send([ok[:10], ok[10:20], ok[20:]])
            await ws.close()
            done.set_result(True)


async def server(port, cert=None):
    global done
    done = asyncio.get_running_loop().create_future()
    tls = None
    if cert:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(*cert)
    async with websockets.serve(uas, "127.0.0.1", port, subprotocols=["sip"],
                                ssl=tls):
        print("listening", flush=True)
        await asyncio.wait_for(done, 10)


def request(method, cseq, port):
    return ("%s sip:service@127.0.0.1:%d SIP/2.0\r\n"
            "Via: SIP/2.0/WS 127.0.0.1:9;branch=z9hG4bK-py-%d\r\n"
            "From: <sip:py@127.0.0.1>;tag=py\r\n"
            "To: <sip:service@127.0.0.1:%d>%s\r\n"
            "Call-ID: py-1@127.0.0.1\r\n"
            "CSeq: %d %s\r\n"
            "Contact: <sip:py@127.0.0.1:9;transport=ws>\r\n"
            "Max-Forwards: 70\r\n"
            "Content-Length: 0\r\n\r\n") % (
                method, port, cseq, port, "%s", cseq, method)


async def client(port):
    # A client that does not mask its frames.
    s = socket.create_connection(("127.0.0.1", port), 5)
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
              b"Connection: Upgrade\r\n"
              b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
              b"Sec-WebSocket-Version: 13\r\n"
              b"Sec-WebSocket-Protocol: sip\r\n\r\n")
    head = b""
    while b"\r\n\r\n" not in head:
        head += s.recv(1000)
    if b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" not in head:
        fail("got %r" % head)
    s.sendall(b"\x81\x04ping")
    rest = head.split(b"\r\n\r\n", 1)[1]
    while True:
        data = s.recv(1000)
        if not data:
            break
        rest += data
    # A close frame with status 1002.
    if rest != b"\x88\x02\x03\xea":
        fail("got %r after an unmasked frame" % rest)
    s.close()

    uri = "ws://127.0.0.1:%d/" % port
    async with websockets.connect(uri, subprotocols=["sip"]) as ws:
        if ws.subprotocol != "sip":
            fail("subprotocol %r" % ws.subprotocol)
        # An INVITE in fragments.
        invite = request("INVITE", 1, port) % ""
        await ws.send([invite[:7], invite[7:]])
        while True:
            msg = await asyncio.wait_for(ws.recv(), 5)
            if isinstance(msg, bytes):
                fail("a binary frame from SIPp")
            if not msg.startswith("SIP/2.0 1"):
                break
        if not msg.startswith("SIP/2.0 200"):
            fail("got " + msg.split("\r\n", 1)[0])
        tag = re.search(r"(?mi)^To:.*(;tag=[^\r;]*)", msg).group(1)
        await asyncio.wait_for(await ws.ping(b"hello"), 5)
        # An ACK in a binary frame.
        await ws.send((request("ACK", 1, port) % tag).encode())
        await ws.send(request("BYE", 2, port) % tag)
        msg = await asyncio.wait_for(ws.recv(), 5)
        if not msg.startswith("SIP/2.0 200"):
            fail("got " + msg.split("\r\n", 1)[0] + " to the BYE")


if sys.argv[1] == "server":
    asyncio.run(server(int(sys.argv[2]), sys.argv[3:5]))
else:
    asyncio.run(client(int(sys.argv[2])))

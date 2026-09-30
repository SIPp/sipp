#!/usr/bin/env python3
# This regression test is a part of SIPp.
# A DNS server on 127.0.0.1:53 with the NAPTR and SRV records of the
# test. It logs each query as "type name" to its first argument, and
# answers NXDOMAIN to those it has no records for.
import socket
import struct
import sys

NAPTR, SRV = 35, 33

RECORDS = {
    # No NAPTR: _sip._udp and _sip._tcp. The best target does not
    # resolve, the next one is the UAS, the last one a dead port.
    (SRV, '_sip._udp.example.test'): [
        (5, 0, 25815, 'gone.test'),
        (10, 0, 25814, 'sip1.test'),
        (20, 0, 25815, 'sip2.test'),
    ],
    (SRV, '_sip._tcp.example.test'): [
        (10, 0, 25816, 'sip1.test'),
        (20, 0, 25815, 'sip2.test'),
    ],
    # NAPTR to an SRV name of its own for UDP; the better TCP one is not
    # for us.
    (NAPTR, 'naptr.test'): [
        (5, 10, 's', 'SIP+D2T', '_tcp.naptr.test'),
        (10, 10, 's', 'SIP+D2U', '_udp.naptr.test'),
    ],
    (SRV, '_udp.naptr.test'): [(10, 0, 25814, 'sip1.test')],
    (SRV, '_tcp.naptr.test'): [(10, 0, 25815, 'sip2.test')],
    (SRV, '_sip._udp.naptr.test'): [(10, 0, 25815, 'sip2.test')],
    # NAPTR for SCTP only: UDP takes _sip._udp.
    (NAPTR, 'other.test'): [(10, 10, 's', 'SIP+D2S', '_sctp.other.test')],
    (SRV, '_sip._udp.other.test'): [(10, 0, 25814, 'sip1.test')],
}


def name(n):
    return b''.join(bytes([len(l)]) + l.encode() for l in n.split('.')) + b'\0'


def string(s):
    return bytes([len(s)]) + s.encode()


def rdata(qtype, r):
    if qtype == SRV:
        return struct.pack('!HHH', *r[:3]) + name(r[3])
    return (struct.pack('!HH', *r[:2]) + string(r[2]) + string(r[3]) +
            string('') + name(r[4]))


def answer(query):
    i = 12
    labels = []
    while query[i]:
        labels.append(query[i + 1:i + 1 + query[i]].decode())
        i += 1 + query[i]
    qtype, = struct.unpack('!H', query[i + 1:i + 3])
    question = query[12:i + 5]
    qname = '.'.join(labels).lower()
    log.write('%d %s\n' % (qtype, qname))
    log.flush()
    records = RECORDS.get((qtype, qname), [])
    flags = 0x8180 if records else 0x8183
    msg = query[:2] + struct.pack('!HHHHH', flags, 1, len(records), 0, 0)
    msg += question
    for r in records:
        d = rdata(qtype, r)
        msg += struct.pack('!HHHIH', 0xc00c, qtype, 1, 60, len(d)) + d
    return msg


log = open(sys.argv[1], 'w')
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', 53))
open(sys.argv[2], 'w').close()
while True:
    query, peer = s.recvfrom(4096)
    s.sendto(answer(query), peer)

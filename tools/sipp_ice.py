#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Small STUN/ICE/TURN probe for SIPp WebRTC interoperability tests."""

from __future__ import annotations

import argparse
import binascii
import hashlib
import hmac
import os
import socket
import struct
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

MAGIC_COOKIE = 0x2112A442
COOKIE = struct.pack("!I", MAGIC_COOKIE)

BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101
ALLOCATE_REQUEST = 0x0003
ALLOCATE_SUCCESS = 0x0103

USERNAME = 0x0006
MESSAGE_INTEGRITY = 0x0008
ERROR_CODE = 0x0009
LIFETIME = 0x000D
REALM = 0x0014
NONCE = 0x0015
XOR_RELAYED_ADDRESS = 0x0016
REQUESTED_TRANSPORT = 0x0019
XOR_MAPPED_ADDRESS = 0x0020
PRIORITY = 0x0024
USE_CANDIDATE = 0x0025
FINGERPRINT = 0x8028
ICE_CONTROLLING = 0x802A
ICE_CONTROLLED = 0x8029


@dataclass(frozen=True)
class StunMessage:
    message_type: int
    transaction_id: bytes
    attributes: List[Tuple[int, bytes]]

    def all(self, attr_type: int) -> List[bytes]:
        return [value for kind, value in self.attributes if kind == attr_type]

    def first(self, attr_type: int) -> Optional[bytes]:
        values = self.all(attr_type)
        return values[0] if values else None


def _pad(value: bytes) -> bytes:
    return value + b"\x00" * ((-len(value)) % 4)


def _attribute(kind: int, value: bytes) -> bytes:
    return struct.pack("!HH", kind, len(value)) + _pad(value)


def _header(message_type: int, length: int, txid: bytes) -> bytes:
    if len(txid) != 12:
        raise ValueError("STUN transaction id must be 12 bytes")
    return struct.pack("!HHI", message_type, length, MAGIC_COOKIE) + txid


def build_message(message_type: int, attributes: Iterable[Tuple[int, bytes]] = (), *,
                  txid: Optional[bytes] = None, integrity_key: Optional[bytes] = None,
                  fingerprint: bool = True) -> bytes:
    txid = os.urandom(12) if txid is None else txid
    body = b"".join(_attribute(kind, value) for kind, value in attributes)
    if integrity_key is not None:
        # RFC 5389/8489 MESSAGE-INTEGRITY: the HMAC input stops before the
        # attribute itself, while the header length points through its value.
        mi_length = len(body) + 24
        digest = hmac.new(integrity_key, _header(message_type, mi_length, txid) + body, hashlib.sha1).digest()
        body += _attribute(MESSAGE_INTEGRITY, digest)
    if fingerprint:
        final_length = len(body) + 8
        prefix = _header(message_type, final_length, txid) + body
        value = (binascii.crc32(prefix) & 0xFFFFFFFF) ^ 0x5354554E
        body += _attribute(FINGERPRINT, struct.pack("!I", value))
    return _header(message_type, len(body), txid) + body


def parse_message(data: bytes) -> StunMessage:
    if len(data) < 20:
        raise ValueError("truncated STUN header")
    message_type, length, cookie = struct.unpack_from("!HHI", data, 0)
    if message_type & 0xC000:
        raise ValueError("invalid STUN message type")
    if cookie != MAGIC_COOKIE:
        raise ValueError("invalid STUN magic cookie")
    if length % 4 or 20 + length != len(data):
        raise ValueError("invalid STUN message length")
    txid = data[8:20]
    attrs: List[Tuple[int, bytes]] = []
    offset = 20
    end = 20 + length
    while offset < end:
        if offset + 4 > end:
            raise ValueError("truncated STUN attribute")
        kind, size = struct.unpack_from("!HH", data, offset)
        offset += 4
        if offset + size > end:
            raise ValueError("truncated STUN attribute value")
        attrs.append((kind, data[offset:offset + size]))
        offset += (size + 3) & ~3
    return StunMessage(message_type, txid, attrs)


def _find_attribute(data: bytes, wanted: int) -> Optional[Tuple[int, bytes]]:
    if len(data) < 20:
        raise ValueError("truncated STUN header")
    length = struct.unpack_from("!H", data, 2)[0]
    if 20 + length != len(data):
        raise ValueError("invalid STUN message length")
    offset, end = 20, 20 + length
    while offset + 4 <= end:
        start = offset
        kind, size = struct.unpack_from("!HH", data, offset)
        offset += 4
        if offset + size > end:
            raise ValueError("truncated STUN attribute value")
        value = data[offset:offset + size]
        if kind == wanted:
            return start, value
        offset += (size + 3) & ~3
    return None


def verify_fingerprint(data: bytes) -> bool:
    found = _find_attribute(data, FINGERPRINT)
    if found is None:
        return True
    offset, value = found
    if len(value) != 4:
        return False
    expected = (binascii.crc32(data[:offset]) & 0xFFFFFFFF) ^ 0x5354554E
    return hmac.compare_digest(value, struct.pack("!I", expected))


def verify_message_integrity(data: bytes, key: bytes) -> bool:
    found = _find_attribute(data, MESSAGE_INTEGRITY)
    if found is None:
        return False
    offset, supplied = found
    if len(supplied) != 20:
        return False
    message_type = struct.unpack_from("!H", data, 0)[0]
    txid = data[8:20]
    body_before = data[20:offset]
    digest = hmac.new(key, _header(message_type, len(body_before) + 24, txid) + body_before, hashlib.sha1).digest()
    return hmac.compare_digest(supplied, digest)


def decode_xor_address(value: bytes, txid: bytes) -> Tuple[str, int]:
    if len(value) < 4:
        raise ValueError("truncated XOR address")
    family = value[1]
    port = struct.unpack_from("!H", value, 2)[0] ^ (MAGIC_COOKIE >> 16)
    if family == 0x01:
        if len(value) != 8:
            raise ValueError("invalid IPv4 XOR address")
        raw = bytes(a ^ b for a, b in zip(value[4:8], COOKIE))
        return socket.inet_ntop(socket.AF_INET, raw), port
    if family == 0x02:
        if len(value) != 20:
            raise ValueError("invalid IPv6 XOR address")
        mask = COOKIE + txid
        raw = bytes(a ^ b for a, b in zip(value[4:20], mask))
        return socket.inet_ntop(socket.AF_INET6, raw), port
    raise ValueError(f"unknown XOR address family {family}")


def _error_code(message: StunMessage) -> Optional[int]:
    value = message.first(ERROR_CODE)
    if value is None or len(value) < 4:
        return None
    return (value[2] & 0x07) * 100 + value[3]


def _resolved_udp(server: Tuple[str, int]):
    host, port = server
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        raise RuntimeError(f"cannot resolve {host}:{port}: {exc}") from exc
    if not infos:
        raise RuntimeError(f"cannot resolve {host}:{port}")
    return infos


def _request(server: Tuple[str, int], packet: bytes, timeout: float) -> Tuple[StunMessage, bytes]:
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    last_error: Optional[BaseException] = None
    for family, socktype, proto, _, sockaddr in _resolved_udp(server):
        try:
            with socket.socket(family, socktype, proto) as sock:
                sock.settimeout(timeout)
                sock.sendto(packet, sockaddr)
                data, _ = sock.recvfrom(65535)
        except (OSError, socket.timeout) as exc:
            last_error = exc
            continue
        response = parse_message(data)
        if response.transaction_id != packet[8:20]:
            last_error = RuntimeError("STUN response transaction id mismatch")
            continue
        if not verify_fingerprint(data):
            raise RuntimeError("STUN response fingerprint mismatch")
        return response, data
    raise RuntimeError(f"STUN request failed: {last_error or 'no usable address'}")


def stun_binding(server: Tuple[str, int], timeout: float = 3.0) -> Tuple[str, int]:
    request = build_message(BINDING_REQUEST)
    response, _ = _request(server, request, timeout)
    if response.message_type != BINDING_SUCCESS:
        raise RuntimeError(f"STUN binding failed with error {_error_code(response)}")
    value = response.first(XOR_MAPPED_ADDRESS)
    if value is None:
        raise RuntimeError("STUN response has no XOR-MAPPED-ADDRESS")
    return decode_xor_address(value, response.transaction_id)


def ice_check(server: Tuple[str, int], local_ufrag: str, remote_ufrag: str, remote_password: str,
              *, priority: int = 1845501695, controlling: bool = True,
              use_candidate: bool = False, timeout: float = 3.0) -> Tuple[str, int]:
    if not local_ufrag or not remote_ufrag or not remote_password:
        raise ValueError("ICE ufrags and remote password must be non-empty")
    if not 0 <= priority <= 0xFFFFFFFF:
        raise ValueError("ICE priority must fit in an unsigned 32-bit integer")
    attrs: List[Tuple[int, bytes]] = [
        (USERNAME, f"{remote_ufrag}:{local_ufrag}".encode()),
        (PRIORITY, struct.pack("!I", priority)),
        (ICE_CONTROLLING if controlling else ICE_CONTROLLED, os.urandom(8)),
    ]
    if use_candidate:
        attrs.append((USE_CANDIDATE, b""))
    key = remote_password.encode()
    request = build_message(BINDING_REQUEST, attrs, integrity_key=key)
    response, raw = _request(server, request, timeout)
    if response.message_type != BINDING_SUCCESS:
        raise RuntimeError(f"ICE connectivity check failed with error {_error_code(response)}")
    if not verify_message_integrity(raw, key):
        raise RuntimeError("ICE response MESSAGE-INTEGRITY mismatch")
    value = response.first(XOR_MAPPED_ADDRESS)
    if value is None:
        raise RuntimeError("ICE response has no XOR-MAPPED-ADDRESS")
    return decode_xor_address(value, response.transaction_id)


def _turn_key(username: str, realm: str, password: str) -> bytes:
    return hashlib.md5(f"{username}:{realm}:{password}".encode()).digest()


def _turn_allocate_authenticated(server: Tuple[str, int], username: str, password: str,
                                 realm_raw: bytes, nonce_raw: bytes, requested_udp: bytes,
                                 timeout: float) -> Tuple[StunMessage, bytes, bytes]:
    try:
        realm = realm_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError("TURN realm is not valid UTF-8") from exc
    key = _turn_key(username, realm, password)
    attrs = [(USERNAME, username.encode()), (REALM, realm_raw), (NONCE, nonce_raw),
             (REQUESTED_TRANSPORT, requested_udp)]
    request = build_message(ALLOCATE_REQUEST, attrs, integrity_key=key)
    response, raw = _request(server, request, timeout)
    return response, raw, key


def turn_allocate(server: Tuple[str, int], username: str, password: str,
                  timeout: float = 3.0) -> Tuple[Tuple[str, int], Optional[int]]:
    if not username or not password:
        raise ValueError("TURN username and password must be non-empty")
    requested_udp = struct.pack("!I", 17 << 24)
    first = build_message(ALLOCATE_REQUEST, [(REQUESTED_TRANSPORT, requested_udp)])
    challenge, _ = _request(server, first, timeout)
    realm_raw, nonce_raw = challenge.first(REALM), challenge.first(NONCE)
    if _error_code(challenge) not in (401, 438) or realm_raw is None or nonce_raw is None:
        raise RuntimeError(f"TURN server did not return an authentication challenge: {_error_code(challenge)}")

    response, raw, key = _turn_allocate_authenticated(
        server, username, password, realm_raw, nonce_raw, requested_udp, timeout)

    # RFC 5766/8656 servers may invalidate a nonce between the challenge and
    # authenticated request. Retry exactly once with the fresh realm/nonce.
    if _error_code(response) == 438:
        new_realm = response.first(REALM) or realm_raw
        new_nonce = response.first(NONCE)
        if new_nonce is None:
            raise RuntimeError("TURN stale-nonce response has no NONCE")
        response, raw, key = _turn_allocate_authenticated(
            server, username, password, new_realm, new_nonce, requested_udp, timeout)

    if response.message_type != ALLOCATE_SUCCESS:
        raise RuntimeError(f"TURN allocation failed with error {_error_code(response)}")
    if not verify_message_integrity(raw, key):
        raise RuntimeError("TURN allocation MESSAGE-INTEGRITY mismatch")
    relayed = response.first(XOR_RELAYED_ADDRESS)
    if relayed is None:
        raise RuntimeError("TURN allocation has no XOR-RELAYED-ADDRESS")
    lifetime_raw = response.first(LIFETIME)
    lifetime = struct.unpack("!I", lifetime_raw)[0] if lifetime_raw and len(lifetime_raw) == 4 else None
    return decode_xor_address(relayed, response.transaction_id), lifetime


def _server(value: str) -> Tuple[str, int]:
    value = value.strip()
    if value.startswith("["):
        end = value.find("]")
        if end <= 1 or end + 1 >= len(value) or value[end + 1] != ":":
            raise argparse.ArgumentTypeError("expected [IPv6]:PORT")
        host = value[1:end]
        raw_port = value[end + 2:]
    else:
        host, sep, raw_port = value.rpartition(":")
        if not sep or not host:
            raise argparse.ArgumentTypeError("expected HOST:PORT")
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("invalid port") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be 1..65535")
    return host, port


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="STUN/ICE/TURN probe for SIPp media tests")
    parser.add_argument("--timeout", type=float, default=3.0)
    sub = parser.add_subparsers(dest="command", required=True)

    binding = sub.add_parser("stun", help="perform a STUN binding request")
    binding.add_argument("server", type=_server)

    ice = sub.add_parser("ice-check", help="perform an ICE connectivity check")
    ice.add_argument("server", type=_server)
    ice.add_argument("--local-ufrag", required=True)
    ice.add_argument("--remote-ufrag", required=True)
    ice.add_argument("--remote-password", required=True)
    ice.add_argument("--priority", type=int, default=1845501695)
    ice.add_argument("--controlled", action="store_true")
    ice.add_argument("--use-candidate", action="store_true")

    turn = sub.add_parser("turn-allocate", help="allocate a UDP relay on a TURN server")
    turn.add_argument("server", type=_server)
    turn.add_argument("--username", required=True)
    turn.add_argument("--password", required=True)

    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    try:
        if args.command == "stun":
            address = stun_binding(args.server, args.timeout)
            print(f"{address[0]}:{address[1]}")
        elif args.command == "ice-check":
            address = ice_check(args.server, args.local_ufrag, args.remote_ufrag, args.remote_password,
                                priority=args.priority, controlling=not args.controlled,
                                use_candidate=args.use_candidate, timeout=args.timeout)
            print(f"{address[0]}:{address[1]}")
        else:
            address, lifetime = turn_allocate(args.server, args.username, args.password, args.timeout)
            print(f"{address[0]}:{address[1]} lifetime={lifetime if lifetime is not None else 'unknown'}")
    except (ValueError, RuntimeError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

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
import stringprep
import struct
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from sipp_endpoint import parse_endpoint

MAGIC_COOKIE = 0x2112A442
COOKIE = struct.pack("!I", MAGIC_COOKIE)

BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101
ALLOCATE_REQUEST = 0x0003
ALLOCATE_SUCCESS = 0x0103
REFRESH_REQUEST = 0x0004
REFRESH_SUCCESS = 0x0104

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

INITIAL_RTO = 0.5
MAX_RETRANSMITS = 7


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


@dataclass(frozen=True)
class UdpTarget:
    family: int
    socktype: int
    proto: int
    sockaddr: tuple


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
        mi_length = len(body) + 24
        digest = hmac.new(
            integrity_key, _header(message_type, mi_length, txid) + body, hashlib.sha1
        ).digest()
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
    digest = hmac.new(
        key, _header(message_type, len(body_before) + 24, txid) + body_before, hashlib.sha1
    ).digest()
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


def _resolved_udp(server: Tuple[str, int]) -> List[UdpTarget]:
    host, port = server
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        raise RuntimeError(f"cannot resolve {host}:{port}: {exc}") from exc
    targets: List[UdpTarget] = []
    seen = set()
    for family, socktype, proto, _, sockaddr in infos:
        key = (family, socktype, proto, sockaddr)
        if key not in seen:
            seen.add(key)
            targets.append(UdpTarget(family, socktype, proto, sockaddr))
    if not targets:
        raise RuntimeError(f"cannot resolve {host}:{port}")
    return targets


def _bind_address(bind: Tuple[str, int], family: int) -> tuple:
    host, port = bind
    try:
        infos = socket.getaddrinfo(host, port, family, socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        raise OSError(f"cannot resolve bind address {host}:{port}: {exc}") from exc
    if not infos:
        raise OSError(f"cannot resolve bind address {host}:{port}")
    return infos[0][4]


def _same_source(source: tuple, expected: tuple) -> bool:
    return source[0] == expected[0] and source[1] == expected[1]


def _request(server: Tuple[str, int], packet: bytes, timeout: float, *,
             bind: Optional[Tuple[str, int]] = None,
             target: Optional[UdpTarget] = None) -> Tuple[StunMessage, bytes, UdpTarget]:
    """Send a STUN transaction with RFC 8489-style UDP retransmission.

    ``timeout`` is an overall deadline for the whole transaction, not a
    per-address timeout. Malformed, unrelated, wrong-source and wrong-txid
    datagrams are ignored until the current receive window expires.
    """
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if len(packet) < 20:
        raise ValueError("truncated STUN request")

    deadline = time.monotonic() + timeout
    last_error: Optional[BaseException] = None
    targets = [target] if target is not None else _resolved_udp(server)

    for index, candidate in enumerate(targets):
        now = time.monotonic()
        if now >= deadline:
            break
        remaining_targets = len(targets) - index
        candidate_deadline = min(
            deadline, now + (deadline - now) / remaining_targets)
        try:
            with socket.socket(candidate.family, candidate.socktype, candidate.proto) as sock:
                if bind is not None:
                    sock.bind(_bind_address(bind, candidate.family))

                rto = INITIAL_RTO
                for _ in range(MAX_RETRANSMITS + 1):
                    now = time.monotonic()
                    if now >= candidate_deadline:
                        break
                    sock.sendto(packet, candidate.sockaddr)
                    receive_deadline = min(candidate_deadline, now + rto)

                    while True:
                        remaining = receive_deadline - time.monotonic()
                        if remaining <= 0:
                            break
                        sock.settimeout(remaining)
                        try:
                            data, source = sock.recvfrom(65535)
                        except socket.timeout:
                            break

                        if not _same_source(source, candidate.sockaddr):
                            continue
                        try:
                            response = parse_message(data)
                        except ValueError:
                            continue
                        if response.transaction_id != packet[8:20]:
                            continue
                        if not verify_fingerprint(data):
                            raise RuntimeError("STUN response fingerprint mismatch")
                        return response, data, candidate

                    rto *= 2
        except OSError as exc:
            last_error = exc
            continue

    if time.monotonic() >= deadline:
        last_error = last_error or TimeoutError("transaction deadline expired")
    raise RuntimeError(f"STUN request failed: {last_error or 'no matching response'}")


def stun_binding(server: Tuple[str, int], timeout: float = 3.0) -> Tuple[str, int]:
    request = build_message(BINDING_REQUEST)
    response, _, _ = _request(server, request, timeout)
    if response.message_type != BINDING_SUCCESS:
        raise RuntimeError(f"STUN binding failed with error {_error_code(response)}")
    value = response.first(XOR_MAPPED_ADDRESS)
    if value is None:
        raise RuntimeError("STUN response has no XOR-MAPPED-ADDRESS")
    return decode_xor_address(value, response.transaction_id)


def ice_check(server: Tuple[str, int], local_ufrag: str, remote_ufrag: str,
              remote_password: str, *, priority: int = 1845501695,
              controlling: bool = True, use_candidate: bool = False,
              bind: Optional[Tuple[str, int]] = None,
              timeout: float = 3.0) -> Tuple[str, int]:
    if not local_ufrag or not remote_ufrag or not remote_password:
        raise ValueError("ICE ufrags and remote password must be non-empty")
    if not 0 <= priority <= 0xFFFFFFFF:
        raise ValueError("ICE priority must fit in an unsigned 32-bit integer")
    if use_candidate and not controlling:
        raise ValueError("USE-CANDIDATE is only valid for the controlling ICE agent")

    attrs: List[Tuple[int, bytes]] = [
        (USERNAME, f"{remote_ufrag}:{local_ufrag}".encode()),
        (PRIORITY, struct.pack("!I", priority)),
        (ICE_CONTROLLING if controlling else ICE_CONTROLLED, os.urandom(8)),
    ]
    if use_candidate:
        attrs.append((USE_CANDIDATE, b""))

    key = remote_password.encode()
    request = build_message(BINDING_REQUEST, attrs, integrity_key=key)
    response, raw, _ = _request(server, request, timeout, bind=bind)
    error = _error_code(response)
    if error == 487:
        raise RuntimeError("ICE role conflict (487)")
    if response.message_type != BINDING_SUCCESS:
        raise RuntimeError(f"ICE connectivity check failed with error {error}")
    if not verify_message_integrity(raw, key):
        raise RuntimeError("ICE response MESSAGE-INTEGRITY mismatch")
    value = response.first(XOR_MAPPED_ADDRESS)
    if value is None:
        raise RuntimeError("ICE response has no XOR-MAPPED-ADDRESS")
    return decode_xor_address(value, response.transaction_id)


def _saslprep(value: str) -> str:
    mapped = []
    for char in value:
        if stringprep.in_table_b1(char):
            continue
        if stringprep.in_table_c12(char):
            mapped.append(" ")
        else:
            mapped.append(char)
    prepared = unicodedata.normalize("NFKC", "".join(mapped))

    prohibited = (
        stringprep.in_table_c12, stringprep.in_table_c21, stringprep.in_table_c22,
        stringprep.in_table_c3, stringprep.in_table_c4, stringprep.in_table_c5,
        stringprep.in_table_c6, stringprep.in_table_c7, stringprep.in_table_c8,
        stringprep.in_table_c9,
    )
    for char in prepared:
        if stringprep.in_table_a1(char) or any(check(char) for check in prohibited):
            raise ValueError("credential contains a character prohibited by SASLprep")

    has_randal = any(stringprep.in_table_d1(char) for char in prepared)
    if has_randal:
        if any(stringprep.in_table_d2(char) for char in prepared):
            raise ValueError("credential violates SASLprep bidirectional rules")
        if not prepared or not stringprep.in_table_d1(prepared[0]) or \
                not stringprep.in_table_d1(prepared[-1]):
            raise ValueError("credential violates SASLprep bidirectional rules")
    return prepared


def _turn_key(username: str, realm: str, password: str) -> bytes:
    prepared_user = _saslprep(username)
    prepared_password = _saslprep(password)
    return hashlib.md5(
        f"{prepared_user}:{realm}:{prepared_password}".encode("utf-8")
    ).digest()


def _turn_allocate_authenticated(server: Tuple[str, int], username: str, password: str,
                                 realm_raw: bytes, nonce_raw: bytes, requested_udp: bytes,
                                 timeout: float, target: UdpTarget
                                 ) -> Tuple[StunMessage, bytes, bytes]:
    try:
        realm = realm_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError("TURN realm is not valid UTF-8") from exc
    prepared_user = _saslprep(username)
    key = _turn_key(username, realm, password)
    attrs = [
        (USERNAME, prepared_user.encode("utf-8")),
        (REALM, realm_raw),
        (NONCE, nonce_raw),
        (REQUESTED_TRANSPORT, requested_udp),
    ]
    request = build_message(ALLOCATE_REQUEST, attrs, integrity_key=key)
    response, raw, _ = _request(server, request, timeout, target=target)
    return response, raw, key


def _turn_release(server: Tuple[str, int], username: str, password: str,
                  realm_raw: bytes, nonce_raw: bytes, timeout: float,
                  target: UdpTarget) -> None:
    for attempt in range(2):
        try:
            realm = realm_raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RuntimeError("TURN realm is not valid UTF-8") from exc
        prepared_user = _saslprep(username)
        key = _turn_key(username, realm, password)
        attrs = [
            (USERNAME, prepared_user.encode("utf-8")),
            (REALM, realm_raw),
            (NONCE, nonce_raw),
            (LIFETIME, struct.pack("!I", 0)),
        ]
        packet = build_message(REFRESH_REQUEST, attrs, integrity_key=key)
        response, raw, _ = _request(server, packet, timeout, target=target)
        error = _error_code(response)
        if error == 438 and attempt == 0:
            nonce_raw = response.first(NONCE)
            realm_raw = response.first(REALM) or realm_raw
            if nonce_raw is None:
                raise RuntimeError("TURN stale-nonce response has no NONCE")
            continue
        if response.message_type != REFRESH_SUCCESS:
            raise RuntimeError(f"TURN release failed with error {error}")
        if not verify_message_integrity(raw, key):
            raise RuntimeError("TURN release MESSAGE-INTEGRITY mismatch")
        return
    raise RuntimeError("TURN release failed after stale nonce retry")


def turn_allocate(server: Tuple[str, int], username: str, password: str,
                  timeout: float = 3.0, *, keep: bool = False
                  ) -> Tuple[Tuple[str, int], Optional[int]]:
    if not username or not password:
        raise ValueError("TURN username and password must be non-empty")

    requested_udp = struct.pack("!I", 17 << 24)
    first = build_message(ALLOCATE_REQUEST, [(REQUESTED_TRANSPORT, requested_udp)])
    challenge, _, target = _request(server, first, timeout)
    realm_raw, nonce_raw = challenge.first(REALM), challenge.first(NONCE)
    if _error_code(challenge) not in (401, 438) or realm_raw is None or nonce_raw is None:
        raise RuntimeError(
            f"TURN server did not return an authentication challenge: {_error_code(challenge)}")

    response, raw, key = _turn_allocate_authenticated(
        server, username, password, realm_raw, nonce_raw, requested_udp, timeout, target)

    if _error_code(response) == 438:
        realm_raw = response.first(REALM) or realm_raw
        nonce_raw = response.first(NONCE)
        if nonce_raw is None:
            raise RuntimeError("TURN stale-nonce response has no NONCE")
        response, raw, key = _turn_allocate_authenticated(
            server, username, password, realm_raw, nonce_raw, requested_udp, timeout, target)

    if response.message_type != ALLOCATE_SUCCESS:
        raise RuntimeError(f"TURN allocation failed with error {_error_code(response)}")
    if not verify_message_integrity(raw, key):
        raise RuntimeError("TURN allocation MESSAGE-INTEGRITY mismatch")

    relayed = response.first(XOR_RELAYED_ADDRESS)
    if relayed is None:
        raise RuntimeError("TURN allocation has no XOR-RELAYED-ADDRESS")
    address = decode_xor_address(relayed, response.transaction_id)
    lifetime_raw = response.first(LIFETIME)
    lifetime = (
        struct.unpack("!I", lifetime_raw)[0]
        if lifetime_raw and len(lifetime_raw) == 4 else None
    )

    if not keep:
        _turn_release(server, username, password, realm_raw, nonce_raw, timeout, target)
    return address, lifetime


def _server(value: str) -> Tuple[str, int]:
    return parse_endpoint(value)


def _read_secret(value: Optional[str], file_name: Optional[str], env_name: Optional[str],
                 label: str) -> str:
    if value is not None:
        return value
    if file_name is not None:
        try:
            return Path(file_name).read_text(encoding="utf-8").rstrip("\r\n")
        except OSError as exc:
            raise ValueError(f"cannot read {label} file: {exc}") from exc
    if env_name is not None:
        try:
            return os.environ[env_name]
        except KeyError as exc:
            raise ValueError(f"environment variable {env_name!r} is not set") from exc
    raise ValueError(f"{label} is required")


def _add_secret_options(parser: argparse.ArgumentParser, option: str, help_name: str) -> None:
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(f"--{option}", help=f"{help_name} (visible in process arguments)")
    group.add_argument(f"--{option}-file", help=f"read {help_name} from a file")
    group.add_argument(f"--{option}-env", help=f"read {help_name} from an environment variable")


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="STUN/ICE/TURN probe for SIPp media tests")
    parser.add_argument("--timeout", type=float, default=3.0,
                        help="overall transaction deadline in seconds")
    sub = parser.add_subparsers(dest="command", required=True)

    binding = sub.add_parser("stun", help="perform a STUN binding request")
    binding.add_argument("server", type=_server)

    ice = sub.add_parser("ice-check", help="perform an ICE connectivity check")
    ice.add_argument("server", type=_server)
    ice.add_argument("--local-ufrag", required=True)
    ice.add_argument("--remote-ufrag", required=True)
    _add_secret_options(ice, "remote-password", "remote ICE password")
    ice.add_argument("--priority", type=int, default=1845501695)
    ice.add_argument("--controlled", action="store_true")
    ice.add_argument("--use-candidate", action="store_true")
    ice.add_argument("--bind", type=_server,
                     help="source HOST:PORT to use for the ICE connectivity check")

    turn = sub.add_parser("turn-allocate", help="allocate a UDP relay on a TURN server")
    turn.add_argument("server", type=_server)
    turn.add_argument("--username", required=True)
    _add_secret_options(turn, "password", "TURN password")
    turn.add_argument("--keep", action="store_true",
                      help="keep the TURN allocation instead of releasing it before exit")

    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    try:
        if args.command == "stun":
            address = stun_binding(args.server, args.timeout)
            print(f"{address[0]}:{address[1]}")
        elif args.command == "ice-check":
            remote_password = _read_secret(
                args.remote_password, args.remote_password_file,
                args.remote_password_env, "remote ICE password")
            address = ice_check(
                args.server, args.local_ufrag, args.remote_ufrag, remote_password,
                priority=args.priority, controlling=not args.controlled,
                use_candidate=args.use_candidate, bind=args.bind, timeout=args.timeout)
            print(f"{address[0]}:{address[1]}")
        else:
            password = _read_secret(
                args.password, args.password_file, args.password_env, "TURN password")
            address, lifetime = turn_allocate(
                args.server, args.username, password, args.timeout, keep=args.keep)
            state = "kept" if args.keep else "released"
            print(
                f"{address[0]}:{address[1]} "
                f"lifetime={lifetime if lifetime is not None else 'unknown'} {state}"
            )
    except (ValueError, RuntimeError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

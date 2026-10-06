#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import importlib.util
import io
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
spec = importlib.util.spec_from_file_location("sipp_ice", ROOT / "tools" / "sipp_ice.py")
ice = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = ice
spec.loader.exec_module(ice)

TXID = bytes.fromhex("0102030405060708090a0b0c")
RFC5769_REQUEST = bytes.fromhex(
    "000100582112a442b7e7a701bc34d686fa87dfae"
    "802200105354554e207465737420636c69656e74"
    "002400046e0001ff"
    "80290008932ff9b151263b36"
    "000600096576746a3a68367659202020"
    "000800149aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a2"
    "80280004e57a3bcf"
)
RFC5769_PASSWORD = b"VOkJxbRl1RmTxUk/WvJxBt"
# RFC 5769 section 2.4: request with long-term authentication.
RFC5769_LONG_TERM_REQUEST = bytes.fromhex(
    "000100602112a44278ad3433c6ad72c029da412e"
    "00060012e3839ee38388e383aae38383e382afe382b90000"
    "0015001c662f2f3439396b39353464364f4c33346f4c39465354767936347341"
    "0014000b6578616d706c652e6f726700"
    "00080014f67024656dd64a3e02b8e0712e85c9a28ca89666"
)
RFC5769_LONG_TERM_USERNAME = "\u30DE\u30C8\u30EA\u30C3\u30AF\u30B9"
RFC5769_LONG_TERM_PASSWORD = "The\u00ADM\u00AAtr\u2168"
ALLOCATE_ERROR = 0x0113
REFRESH_ERROR = 0x0114


def xor_ipv4(address="192.0.2.1", port=3478):
    raw = socket.inet_pton(socket.AF_INET, address)
    xport = port ^ (ice.MAGIC_COOKIE >> 16)
    xaddr = bytes(a ^ b for a, b in zip(raw, ice.COOKIE))
    return b"\x00\x01" + struct.pack("!H", xport) + xaddr


def xor_ipv6(address, port, txid):
    raw = socket.inet_pton(socket.AF_INET6, address)
    xport = port ^ (ice.MAGIC_COOKIE >> 16)
    mask = ice.COOKIE + txid
    xaddr = bytes(a ^ b for a, b in zip(raw, mask))
    return b"\x00\x02" + struct.pack("!H", xport) + xaddr


def error_value(code):
    return b"\x00\x00" + bytes([code // 100, code % 100])


def raw_response(message_type, attrs, key=None, txid=TXID):
    data = ice.build_message(message_type, attrs, txid=txid, integrity_key=key)
    return ice.parse_message(data), data


def target(port):
    return ice.UdpTarget(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP,
                         ("127.0.0.1", port))


def udp_socket(family=socket.AF_INET):
    host = "::1" if family == socket.AF_INET6 else "127.0.0.1"
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.bind((host, 0))
    except OSError:
        sock.close()
        raise unittest.SkipTest("IPv6 loopback is unavailable")
    return sock


def xor_address(address, port, txid):
    if ":" in address:
        return xor_ipv6(address, port, txid)
    return xor_ipv4(address, port)


class MockTurnServer:
    """Loopback TURN server: 401 challenge, Allocate, Refresh LIFETIME=0.

    Like a real server it identifies the allocation by its 5-tuple: a
    Refresh from another source than the Allocate gets 437 Allocation
    Mismatch.
    """

    def __init__(self, family=socket.AF_INET, *, realm=b"example.org",
                 username="user", password="pass", unauthenticated=False,
                 stale_allocate=False, stale_refresh=False, answer_refresh=True,
                 bad_integrity=False, delay=0.0):
        self.sock = udp_socket(family)
        self.sock.settimeout(0.05)
        self.host = self.sock.getsockname()[0]
        self.port = self.sock.getsockname()[1]
        self.relay = ("2001:db8::7", 50000) if family == socket.AF_INET6 \
            else ("198.51.100.7", 50000)
        self.realm = realm
        self.username = username
        self.key = ice._turn_key(username, realm.decode(), password)
        self.nonce = b"nonce-1"
        self.unauthenticated = unauthenticated
        self.stale_allocate = stale_allocate
        self.stale_refresh = stale_refresh
        self.answer_refresh = answer_refresh
        self.bad_integrity = bad_integrity
        self.delay = delay
        self.allocation = None  # client source of the current allocation
        self.requests = []
        self.sources = []
        self.errors = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run)

    @property
    def endpoint(self):
        return self.host, self.port

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join(timeout=2)
        self.sock.close()

    def _run(self):
        while not self._stop.is_set():
            try:
                data, peer = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            message = ice.parse_message(data)
            self.requests.append((message, data))
            self.sources.append(peer)
            if self.delay:
                time.sleep(self.delay)
            reply = self._reply(message, data, peer)
            if reply is not None:
                self.sock.sendto(reply, peer)

    def _authenticated(self, message, data):
        if message.first(ice.MESSAGE_INTEGRITY) is None:
            return False
        if message.first(ice.USERNAME) != self.username.encode() or \
                message.first(ice.REALM) != self.realm or \
                message.first(ice.NONCE) != self.nonce or \
                not ice.verify_message_integrity(data, self.key):
            self.errors.append("bad credentials")
            return False
        return True

    def _challenge(self, message_type, code, txid):
        return ice.build_message(message_type, [
            (ice.ERROR_CODE, error_value(code)),
            (ice.REALM, self.realm),
            (ice.NONCE, self.nonce),
        ], txid=txid)

    def _stale(self, message_type, txid):
        self.nonce = b"nonce-%d" % (int(self.nonce[6:]) + 1)
        return self._challenge(message_type, 438, txid)

    def _reply(self, message, data, peer):
        txid = message.transaction_id
        key = None if self.unauthenticated else self.key
        if message.message_type == ice.ALLOCATE_REQUEST:
            if self.stale_allocate and message.first(ice.MESSAGE_INTEGRITY) is not None:
                self.stale_allocate = False
                return self._stale(ALLOCATE_ERROR, txid)
            if not self.unauthenticated and not self._authenticated(message, data):
                return self._challenge(ALLOCATE_ERROR, 401, txid)
            self.allocation = peer
            return ice.build_message(ice.ALLOCATE_SUCCESS, [
                (ice.XOR_RELAYED_ADDRESS, xor_address(*self.relay, txid)),
                (ice.LIFETIME, struct.pack("!I", 600)),
            ], txid=txid, integrity_key=b"wrong" if self.bad_integrity else key)
        if message.message_type == ice.REFRESH_REQUEST and self.answer_refresh:
            if peer != self.allocation:
                return ice.build_message(
                    REFRESH_ERROR, [(ice.ERROR_CODE, error_value(437))], txid=txid)
            if self.stale_refresh:
                self.stale_refresh = False
                return self._stale(REFRESH_ERROR, txid)
            if not self.unauthenticated and not self._authenticated(message, data):
                return self._challenge(REFRESH_ERROR, 401, txid)
            self.allocation = None
            return ice.build_message(
                ice.REFRESH_SUCCESS, [], txid=txid, integrity_key=key)
        return None

    def types(self):
        return [message.message_type for message, _ in self.requests]


class StunCodecTests(unittest.TestCase):
    def test_build_parse_roundtrip(self):
        packet = ice.build_message(
            ice.BINDING_REQUEST, [(ice.USERNAME, b"remote:local")], txid=TXID)
        message = ice.parse_message(packet)
        self.assertEqual(message.message_type, ice.BINDING_REQUEST)
        self.assertEqual(message.transaction_id, TXID)
        self.assertEqual(message.first(ice.USERNAME), b"remote:local")
        self.assertTrue(ice.verify_fingerprint(packet))

    def test_message_integrity(self):
        key = b"candidate-password"
        packet = ice.build_message(
            ice.BINDING_REQUEST,
            [(ice.PRIORITY, struct.pack("!I", 1234))],
            txid=TXID, integrity_key=key)
        self.assertTrue(ice.verify_message_integrity(packet, key))
        self.assertFalse(ice.verify_message_integrity(packet, b"wrong"))

    def test_rfc5769_message_integrity_and_fingerprint(self):
        message = ice.parse_message(RFC5769_REQUEST)
        self.assertEqual(message.message_type, ice.BINDING_REQUEST)
        self.assertTrue(ice.verify_message_integrity(RFC5769_REQUEST, RFC5769_PASSWORD))
        self.assertTrue(ice.verify_fingerprint(RFC5769_REQUEST))

    def test_rfc5769_long_term_key_vector(self):
        message = ice.parse_message(RFC5769_LONG_TERM_REQUEST)
        realm = message.first(ice.REALM).decode()
        self.assertEqual(realm, "example.org")
        self.assertEqual(
            message.first(ice.USERNAME).decode(), RFC5769_LONG_TERM_USERNAME)
        self.assertEqual(ice._saslprep(RFC5769_LONG_TERM_PASSWORD), "TheMatrIX")
        key = ice._turn_key(
            RFC5769_LONG_TERM_USERNAME, realm, RFC5769_LONG_TERM_PASSWORD)
        self.assertTrue(ice.verify_message_integrity(RFC5769_LONG_TERM_REQUEST, key))
        attrs, built_key = ice._long_term_attributes(
            RFC5769_LONG_TERM_USERNAME, RFC5769_LONG_TERM_PASSWORD,
            message.first(ice.REALM), message.first(ice.NONCE))
        self.assertEqual(built_key, key)
        rebuilt = ice.build_message(
            ice.BINDING_REQUEST, [attrs[0], attrs[2], attrs[1]],
            txid=message.transaction_id, integrity_key=key, fingerprint=False)
        self.assertEqual(rebuilt, RFC5769_LONG_TERM_REQUEST)

    def test_fingerprint_detects_tampering(self):
        packet = bytearray(ice.build_message(ice.BINDING_REQUEST, txid=TXID))
        packet[-1] ^= 1
        self.assertFalse(ice.verify_fingerprint(bytes(packet)))

    def test_parser_rejects_trailing_bytes(self):
        packet = ice.build_message(ice.BINDING_REQUEST, txid=TXID)
        with self.assertRaises(ValueError):
            ice.parse_message(packet + b"junk")

    def test_xor_mapped_ipv4(self):
        self.assertEqual(
            ice.decode_xor_address(xor_ipv4(), TXID), ("192.0.2.1", 3478))

    def test_xor_mapped_ipv6(self):
        value = xor_ipv6("2001:db8::1234", 50000, TXID)
        self.assertEqual(
            ice.decode_xor_address(value, TXID), ("2001:db8::1234", 50000))

    def test_rejects_truncated_attribute(self):
        packet = ice.build_message(
            ice.BINDING_REQUEST, [(ice.USERNAME, b"abcd")],
            txid=TXID, fingerprint=False)
        with self.assertRaises(ValueError):
            ice.parse_message(packet[:-1])

    def test_server_parser_is_strict_about_ipv6_brackets(self):
        self.assertEqual(
            ice._server("stun.example.org:3478"), ("stun.example.org", 3478))
        self.assertEqual(
            ice._server("[2001:db8::1]:3478"), ("2001:db8::1", 3478))
        with self.assertRaises(Exception):
            ice._server("::1:3478")

    def test_bind_parser_accepts_port_zero(self):
        self.assertEqual(ice._bind("127.0.0.1:0"), ("127.0.0.1", 0))
        self.assertEqual(ice._bind("[::1]:0"), ("::1", 0))
        with self.assertRaises(Exception):
            ice._server("127.0.0.1:0")
        with self.assertRaises(Exception):
            ice._bind("127.0.0.1:65536")

    def test_retransmit_schedule_follows_rfc8489(self):
        self.assertEqual(
            ice._retransmit_waits(0.5), [0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 8.0])

    def test_ice_validation(self):
        with self.assertRaises(ValueError):
            ice.ice_check(("127.0.0.1", 3478), "", "remote", "password")
        with self.assertRaises(ValueError):
            ice.ice_check(
                ("127.0.0.1", 3478), "local", "remote", "password", priority=-1)
        with self.assertRaises(ValueError):
            ice.ice_check(
                ("127.0.0.1", 3478), "local", "remote", "password",
                priority=1 << 32)
        with self.assertRaisesRegex(ValueError, "USE-CANDIDATE"):
            ice.ice_check(
                ("127.0.0.1", 3478), "local", "remote", "password",
                controlling=False, use_candidate=True)


class RequestTests(unittest.TestCase):
    def test_stray_datagram_is_ignored(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]

        def worker():
            request, peer = server.recvfrom(65535)
            txid = request[8:20]
            server.sendto(b"bad", peer)
            response = ice.build_message(
                ice.BINDING_SUCCESS,
                [(ice.XOR_MAPPED_ADDRESS, xor_ipv4("127.0.0.1", peer[1]))],
                txid=txid)
            server.sendto(response, peer)
            server.close()

        thread = threading.Thread(target=worker)
        thread.start()
        try:
            self.assertEqual(
                ice.stun_binding(("127.0.0.1", port), timeout=2.0)[0],
                "127.0.0.1")
        finally:
            thread.join(timeout=2)

    def test_request_retransmits_after_loss(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        received = []

        def worker():
            first, peer = server.recvfrom(65535)
            received.append(first)
            second, peer = server.recvfrom(65535)
            received.append(second)
            txid = second[8:20]
            response = ice.build_message(
                ice.BINDING_SUCCESS,
                [(ice.XOR_MAPPED_ADDRESS, xor_ipv4("127.0.0.1", peer[1]))],
                txid=txid)
            server.sendto(response, peer)
            server.close()

        thread = threading.Thread(target=worker)
        thread.start()
        try:
            ice.stun_binding(("127.0.0.1", port), timeout=2.0)
            self.assertGreaterEqual(len(received), 2)
        finally:
            thread.join(timeout=2)

    def test_wrong_source_is_ignored(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        stray = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        def worker():
            request, peer = server.recvfrom(65535)
            txid = request[8:20]
            fake = ice.build_message(
                ice.BINDING_SUCCESS,
                [(ice.XOR_MAPPED_ADDRESS, xor_ipv4("203.0.113.1", 9))],
                txid=txid)
            stray.sendto(fake, peer)
            real = ice.build_message(
                ice.BINDING_SUCCESS,
                [(ice.XOR_MAPPED_ADDRESS, xor_ipv4("127.0.0.1", peer[1]))],
                txid=txid)
            server.sendto(real, peer)
            server.close()
            stray.close()

        thread = threading.Thread(target=worker)
        thread.start()
        try:
            mapped = ice.stun_binding(("127.0.0.1", port), timeout=2.0)
            self.assertEqual(mapped[0], "127.0.0.1")
        finally:
            thread.join(timeout=2)

    @unittest.skipUnless(socket.has_ipv6, "IPv6 is unavailable")
    def test_ipv6_loopback_binding_roundtrip(self):
        server = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            server.bind(("::1", 0))
        except OSError:
            server.close()
            self.skipTest("IPv6 loopback is unavailable")
        port = server.getsockname()[1]

        def worker():
            request, peer = server.recvfrom(65535)
            txid = request[8:20]
            response = ice.build_message(
                ice.BINDING_SUCCESS,
                [(ice.XOR_MAPPED_ADDRESS, xor_ipv6("::1", peer[1], txid))],
                txid=txid)
            server.sendto(response, peer)
            server.close()

        thread = threading.Thread(target=worker)
        thread.start()
        try:
            mapped = ice.stun_binding(("::1", port), timeout=2.0)
            self.assertEqual(mapped[0], "::1")
        finally:
            thread.join(timeout=2)

    def test_ice_bind_uses_requested_source_port(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        server_port = server.getsockname()[1]
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("127.0.0.1", 0))
        bind_port = probe.getsockname()[1]
        probe.close()
        seen_port = []

        def worker():
            request, peer = server.recvfrom(65535)
            seen_port.append(peer[1])
            txid = request[8:20]
            response = ice.build_message(
                ice.BINDING_SUCCESS,
                [(ice.XOR_MAPPED_ADDRESS, xor_ipv4("127.0.0.1", peer[1]))],
                txid=txid, integrity_key=b"secret")
            server.sendto(response, peer)
            server.close()

        thread = threading.Thread(target=worker)
        thread.start()
        try:
            ice.ice_check(
                ("127.0.0.1", server_port), "local", "remote", "secret",
                bind=("127.0.0.1", bind_port), timeout=2.0)
            self.assertEqual(seen_port, [bind_port])
        finally:
            thread.join(timeout=2)

    def test_bad_fingerprint_is_dropped(self):
        server = udp_socket()
        port = server.getsockname()[1]

        def worker():
            request, peer = server.recvfrom(65535)
            txid = request[8:20]
            response = ice.build_message(
                ice.BINDING_SUCCESS,
                [(ice.XOR_MAPPED_ADDRESS, xor_ipv4("127.0.0.1", peer[1]))],
                txid=txid)
            corrupted = bytearray(response)
            corrupted[-1] ^= 1
            server.sendto(bytes(corrupted), peer)
            server.sendto(response, peer)
            server.close()

        thread = threading.Thread(target=worker)
        thread.start()
        try:
            mapped = ice.stun_binding(("127.0.0.1", port), timeout=2.0)
            self.assertEqual(mapped[0], "127.0.0.1")
        finally:
            thread.join(timeout=2)

    def test_request_sends_rc_requests_then_waits_rm_rto(self):
        server = udp_socket()
        server.settimeout(0.05)
        port = server.getsockname()[1]
        received = []
        stop = threading.Event()

        def worker():
            while not stop.is_set():
                try:
                    received.append(server.recvfrom(65535)[0])
                except socket.timeout:
                    continue

        thread = threading.Thread(target=worker)
        thread.start()
        try:
            with mock.patch.object(ice, "INITIAL_RTO", 0.01):
                started = time.monotonic()
                with self.assertRaises(RuntimeError):
                    ice.stun_binding(("127.0.0.1", port), timeout=10.0)
                elapsed = time.monotonic() - started
        finally:
            stop.set()
            thread.join(timeout=2)
            server.close()
        self.assertEqual(len(received), ice.REQUEST_COUNT)
        # 0.01 * (1 + 2 + ... + 32) + 16 * 0.01 = 0.79 s, far below 10 s.
        self.assertLess(elapsed, 3.0)
        self.assertGreaterEqual(elapsed, 0.7)

    def test_deadline_is_split_between_resolved_addresses(self):
        silent = udp_socket()
        silent_port = silent.getsockname()[1]
        server = udp_socket()
        port = server.getsockname()[1]

        def worker():
            request, peer = server.recvfrom(65535)
            response = ice.build_message(
                ice.BINDING_SUCCESS,
                [(ice.XOR_MAPPED_ADDRESS, xor_ipv4("127.0.0.1", peer[1]))],
                txid=request[8:20])
            server.sendto(response, peer)

        thread = threading.Thread(target=worker)
        thread.start()
        targets = [target(silent_port), target(port)]
        try:
            with mock.patch.object(ice, "_resolved_udp", return_value=targets):
                started = time.monotonic()
                mapped = ice.stun_binding(("stun.example.org", port), timeout=1.0)
                elapsed = time.monotonic() - started
            self.assertEqual(mapped[0], "127.0.0.1")
            # The silent first address gets about half of the deadline.
            self.assertGreaterEqual(elapsed, 0.4)
            self.assertLess(elapsed, 1.0)
            silent.settimeout(0)
            self.assertTrue(silent.recvfrom(65535))
        finally:
            thread.join(timeout=2)
            server.close()
            silent.close()

    def _ice_responder(self, family, host, seen):
        server = udp_socket(family)
        port = server.getsockname()[1]

        def worker():
            request, peer = server.recvfrom(65535)
            seen.append((ice.parse_message(request), request, peer))
            txid = request[8:20]
            response = ice.build_message(
                ice.BINDING_SUCCESS,
                [(ice.XOR_MAPPED_ADDRESS, xor_address(host, peer[1], txid))],
                txid=txid, integrity_key=b"secret")
            server.sendto(response, peer)
            server.close()

        thread = threading.Thread(target=worker)
        thread.start()
        return port, thread

    def test_ice_bind_port_zero_pins_address(self):
        seen = []
        port, thread = self._ice_responder(socket.AF_INET, "127.0.0.1", seen)
        try:
            mapped = ice.ice_check(
                ("127.0.0.1", port), "local", "remote", "secret",
                bind=("127.0.0.1", 0), timeout=2.0)
        finally:
            thread.join(timeout=2)
        self.assertEqual(seen[0][2][0], "127.0.0.1")
        self.assertNotEqual(seen[0][2][1], 0)
        self.assertEqual(mapped, ("127.0.0.1", seen[0][2][1]))

    def test_ipv6_ice_check_roundtrip(self):
        seen = []
        port, thread = self._ice_responder(socket.AF_INET6, "::1", seen)
        try:
            mapped = ice.ice_check(
                ("::1", port), "local", "remote", "secret",
                bind=("::1", 0), use_candidate=True, timeout=2.0)
        finally:
            thread.join(timeout=2)
        message, raw, peer = seen[0]
        self.assertEqual(message.first(ice.USERNAME), b"remote:local")
        self.assertIsNotNone(message.first(ice.USE_CANDIDATE))
        self.assertTrue(ice.verify_message_integrity(raw, b"secret"))
        self.assertEqual(mapped, ("::1", peer[1]))

    def test_role_conflict_is_explicit(self):
        packet = ice.build_message(
            0x0111, [(ice.ERROR_CODE, error_value(487))], txid=TXID)
        response = ice.parse_message(packet)
        fake_target = target(3478)
        with mock.patch.object(
                ice, "_request", return_value=(response, packet, fake_target)):
            with self.assertRaisesRegex(RuntimeError, "role conflict"):
                ice.ice_check(
                    ("127.0.0.1", 3478), "local", "remote", "secret")


class TurnTests(unittest.TestCase):
    def test_saslprep_is_applied_to_turn_password(self):
        self.assertEqual(
            ice._turn_key("user", "example.org", "I\u00ADX"),
            ice._turn_key("user", "example.org", "IX"))
        self.assertEqual(
            ice._turn_key("user", "example.org", "A\u00A0B"),
            ice._turn_key("user", "example.org", "A B"))

    def test_xor_relay_address_can_be_parsed(self):
        response = ice.build_message(
            ice.ALLOCATE_SUCCESS,
            [(ice.XOR_RELAYED_ADDRESS, xor_ipv4("198.51.100.7", 50000))],
            txid=TXID)
        message = ice.parse_message(response)
        self.assertEqual(
            ice.decode_xor_address(message.first(ice.XOR_RELAYED_ADDRESS), TXID),
            ("198.51.100.7", 50000))

    def test_stale_nonce_retry_uses_new_nonce_and_integrity_key(self):
        realm = b"example.org"
        nonce1 = b"nonce-1"
        nonce2 = b"nonce-2"
        key = ice._turn_key("user", "example.org", "pass")
        fake_target = target(3478)
        calls = []

        challenge = raw_response(0x0113, [
            (ice.ERROR_CODE, error_value(401)),
            (ice.REALM, realm),
            (ice.NONCE, nonce1),
        ])
        stale = raw_response(0x0113, [
            (ice.ERROR_CODE, error_value(438)),
            (ice.REALM, realm),
            (ice.NONCE, nonce2),
        ])
        success = raw_response(ice.ALLOCATE_SUCCESS, [
            (ice.XOR_RELAYED_ADDRESS, xor_ipv4("198.51.100.7", 50000)),
            (ice.LIFETIME, struct.pack("!I", 600)),
        ], key=key)

        def request(server, packet, timeout, **kwargs):
            message = ice.parse_message(packet)
            calls.append((message, packet, kwargs))
            if len(calls) == 1:
                return challenge[0], challenge[1], fake_target
            self.assertIs(kwargs.get("target"), fake_target)
            self.assertEqual(message.first(ice.REALM), realm)
            if len(calls) == 2:
                self.assertEqual(message.first(ice.NONCE), nonce1)
                self.assertTrue(ice.verify_message_integrity(packet, key))
                return stale[0], stale[1], fake_target
            self.assertEqual(message.first(ice.NONCE), nonce2)
            self.assertTrue(ice.verify_message_integrity(packet, key))
            return success[0], success[1], fake_target

        with mock.patch.object(ice, "_request", side_effect=request):
            result = ice.turn_allocate(
                ("turn.example.org", 3478), "user", "pass", keep=True)
        self.assertEqual(result.address, ("198.51.100.7", 50000))
        self.assertEqual(result.lifetime, 600)
        self.assertEqual(result.state, "kept")
        self.assertEqual(len(calls), 3)

    def test_turn_allocation_is_released_by_default(self):
        realm = b"example.org"
        nonce = b"nonce-1"
        key = ice._turn_key("user", "example.org", "pass")
        fake_target = target(3478)
        calls = []
        challenge = raw_response(0x0113, [
            (ice.ERROR_CODE, error_value(401)),
            (ice.REALM, realm),
            (ice.NONCE, nonce),
        ])
        success = raw_response(ice.ALLOCATE_SUCCESS, [
            (ice.XOR_RELAYED_ADDRESS, xor_ipv4("198.51.100.7", 50000)),
            (ice.LIFETIME, struct.pack("!I", 600)),
        ], key=key)
        released = raw_response(ice.REFRESH_SUCCESS, [], key=key)

        def request(server, packet, timeout, **kwargs):
            message = ice.parse_message(packet)
            calls.append((message, packet, kwargs))
            if len(calls) == 1:
                return challenge[0], challenge[1], fake_target
            self.assertIs(kwargs.get("target"), fake_target)
            if len(calls) == 2:
                self.assertEqual(message.message_type, ice.ALLOCATE_REQUEST)
                return success[0], success[1], fake_target
            self.assertEqual(message.message_type, ice.REFRESH_REQUEST)
            self.assertEqual(message.first(ice.LIFETIME), struct.pack("!I", 0))
            self.assertTrue(ice.verify_message_integrity(packet, key))
            return released[0], released[1], fake_target

        with mock.patch.object(ice, "_request", side_effect=request):
            result = ice.turn_allocate(
                ("turn.example.org", 3478), "user", "pass")
        self.assertEqual(result.address, ("198.51.100.7", 50000))
        self.assertEqual(result.state, "released")
        self.assertEqual(len(calls), 3)

    def test_release_failure_still_returns_relay(self):
        key = ice._turn_key("user", "example.org", "pass")
        fake_target = target(3478)
        challenge = raw_response(ALLOCATE_ERROR, [
            (ice.ERROR_CODE, error_value(401)),
            (ice.REALM, b"example.org"),
            (ice.NONCE, b"nonce-1"),
        ])
        success = raw_response(ice.ALLOCATE_SUCCESS, [
            (ice.XOR_RELAYED_ADDRESS, xor_ipv4("198.51.100.7", 50000)),
        ], key=key)
        replies = [
            (challenge[0], challenge[1], fake_target),
            (success[0], success[1], fake_target),
            RuntimeError("STUN request failed: timed out"),
        ]
        with mock.patch.object(ice, "_request", side_effect=replies):
            result = ice.turn_allocate(("turn.example.org", 3478), "user", "pass")
        self.assertEqual(result.address, ("198.51.100.7", 50000))
        self.assertEqual(result.state, "release-failed")
        self.assertIn("timed out", result.release_error)

    def test_first_response_other_error_is_reported(self):
        refused = raw_response(ALLOCATE_ERROR, [(ice.ERROR_CODE, error_value(403))])
        with mock.patch.object(
                ice, "_request", return_value=(refused[0], refused[1], target(3478))):
            with self.assertRaisesRegex(RuntimeError, "error 403"):
                ice.turn_allocate(("turn.example.org", 3478), "user", "pass")

    def test_turn_allocate_and_release_over_udp(self):
        with MockTurnServer() as server:
            result = ice.turn_allocate(server.endpoint, "user", "pass", timeout=2.0)
        self.assertEqual(server.errors, [])
        self.assertEqual(result.address, server.relay)
        self.assertEqual(result.lifetime, 600)
        self.assertEqual(result.state, "released")
        self.assertTrue(result.authenticated)
        self.assertEqual(server.types(), [
            ice.ALLOCATE_REQUEST, ice.ALLOCATE_REQUEST, ice.REFRESH_REQUEST])
        refresh, raw = server.requests[-1]
        self.assertEqual(refresh.first(ice.LIFETIME), struct.pack("!I", 0))
        self.assertTrue(ice.verify_message_integrity(raw, server.key))

    def test_ipv6_turn_allocate_over_udp(self):
        with MockTurnServer(socket.AF_INET6) as server:
            result = ice.turn_allocate(("::1", server.port), "user", "pass", timeout=2.0)
        self.assertEqual(server.errors, [])
        self.assertEqual(result.address, ("2001:db8::7", 50000))
        self.assertEqual(result.state, "released")

    def test_turn_release_retries_stale_nonce_over_udp(self):
        with MockTurnServer(stale_refresh=True) as server:
            result = ice.turn_allocate(server.endpoint, "user", "pass", timeout=2.0)
        self.assertEqual(server.errors, [])
        self.assertEqual(result.state, "released")
        refreshes = [message for message, _ in server.requests
                     if message.message_type == ice.REFRESH_REQUEST]
        self.assertEqual(
            [message.first(ice.NONCE) for message in refreshes],
            [b"nonce-1", b"nonce-2"])

    def test_turn_keep_skips_release_over_udp(self):
        with MockTurnServer() as server:
            result = ice.turn_allocate(
                server.endpoint, "user", "pass", timeout=2.0, keep=True)
        self.assertEqual(result.state, "kept")
        self.assertNotIn(ice.REFRESH_REQUEST, server.types())

    def test_unauthenticated_allocation_is_reported_and_released(self):
        with MockTurnServer(unauthenticated=True) as server:
            result = ice.turn_allocate(server.endpoint, "user", "pass", timeout=2.0)
        self.assertFalse(result.authenticated)
        self.assertEqual(result.state, "released")
        self.assertEqual(server.types(), [ice.ALLOCATE_REQUEST, ice.REFRESH_REQUEST])
        self.assertEqual(len(set(server.sources)), 1)
        refresh, _ = server.requests[-1]
        self.assertEqual(refresh.first(ice.LIFETIME), struct.pack("!I", 0))
        self.assertIsNone(refresh.first(ice.MESSAGE_INTEGRITY))

    def test_every_transaction_uses_the_allocate_source(self):
        # Allocate, 438 retry and Refresh with its 438 retry: a Refresh from
        # another source would get 437 and leave the allocation behind.
        with MockTurnServer(stale_allocate=True, stale_refresh=True) as server:
            result = ice.turn_allocate(server.endpoint, "user", "pass", timeout=2.0)
        self.assertEqual(server.errors, [])
        self.assertEqual(result.state, "released")
        self.assertIsNone(server.allocation)
        self.assertEqual(
            server.types(), [ice.ALLOCATE_REQUEST] * 3 + [ice.REFRESH_REQUEST] * 2)
        self.assertEqual(len(set(server.sources)), 1)

    def test_refresh_from_another_source_is_an_allocation_mismatch(self):
        # A new socket for the Refresh, as each transaction used to open one.
        with MockTurnServer() as server:
            ice.turn_allocate(server.endpoint, "user", "pass", timeout=2.0, keep=True)
            with self.assertRaisesRegex(RuntimeError, "error 437"):
                ice._turn_release(server.endpoint, "user", "pass", server.realm,
                                  server.nonce, 2.0, target(server.port), None)
        self.assertEqual(server.allocation, server.sources[1])

    def test_release_uses_the_address_that_answered(self):
        silent = udp_socket()
        try:
            with MockTurnServer() as server:
                targets = [target(silent.getsockname()[1]), target(server.port)]
                with mock.patch.object(ice, "_resolved_udp", return_value=targets):
                    result = ice.turn_allocate(
                        ("turn.example.org", server.port), "user", "pass", timeout=1.0)
            # The silent address was tried first and got only the challenge.
            silent.settimeout(0)
            seen = [ice.parse_message(silent.recvfrom(65535)[0]).message_type]
        finally:
            silent.close()
        self.assertEqual(seen, [ice.ALLOCATE_REQUEST])
        self.assertEqual(result.state, "released")
        self.assertEqual(len(set(server.sources)), 1)

    def test_allocation_transactions_share_one_deadline(self):
        # Each answer takes 0.4 s: the challenge fits in the 0.6 s budget,
        # the Allocate does not. Per-request timeouts would let both succeed.
        with MockTurnServer(delay=0.4) as server:
            started = time.monotonic()
            with self.assertRaisesRegex(RuntimeError, "deadline"):
                ice.turn_allocate(server.endpoint, "user", "pass", timeout=0.6)
            elapsed = time.monotonic() - started
        self.assertLess(elapsed, 0.75)

    def test_release_gets_its_own_deadline(self):
        # Each answer takes 0.4 s: the challenge and the Allocate use most of
        # the 1.0 s budget, and the release still gets a full 1.0 s.
        with MockTurnServer(delay=0.4) as server:
            started = time.monotonic()
            result = ice.turn_allocate(server.endpoint, "user", "pass", timeout=1.0)
            elapsed = time.monotonic() - started
        self.assertEqual(result.address, server.relay)
        self.assertEqual(result.state, "released")
        self.assertGreater(elapsed, 1.1)
        self.assertLess(elapsed, 2.0)

    def test_integrity_failure_still_releases_the_allocation(self):
        with MockTurnServer(bad_integrity=True) as server:
            with self.assertRaisesRegex(RuntimeError, "MESSAGE-INTEGRITY"):
                ice.turn_allocate(server.endpoint, "user", "pass", timeout=2.0)
        self.assertEqual(server.types()[-1], ice.REFRESH_REQUEST)
        self.assertIsNone(server.allocation)

    def test_integrity_failure_with_keep_sends_no_release(self):
        with MockTurnServer(bad_integrity=True) as server:
            with self.assertRaisesRegex(RuntimeError, "MESSAGE-INTEGRITY"):
                ice.turn_allocate(
                    server.endpoint, "user", "pass", timeout=2.0, keep=True)
        self.assertNotIn(ice.REFRESH_REQUEST, server.types())

    def test_cli_release_failure_prints_relay_and_warns(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with MockTurnServer(answer_refresh=False) as server:
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = ice.main([
                    "--timeout", "1", "turn-allocate",
                    f"127.0.0.1:{server.port}", "--username", "user",
                    "--password", "pass",
                ])
        self.assertEqual(status, 0)
        self.assertEqual(
            stdout.getvalue(), "198.51.100.7:50000 lifetime=600 release-failed\n")
        self.assertIn("was not released", stderr.getvalue())

    def test_turn_credentials_must_be_non_empty(self):
        with self.assertRaises(ValueError):
            ice.turn_allocate(("127.0.0.1", 3478), "", "pass")

    def test_secret_can_be_read_from_file_or_environment(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write("secret\n")
            name = handle.name
        try:
            self.assertEqual(ice._read_secret(None, name, None, "password"), "secret")
            with mock.patch.dict(os.environ, {"SIPP_TURN_PASSWORD": "env-secret"}):
                self.assertEqual(
                    ice._read_secret(None, None, "SIPP_TURN_PASSWORD", "password"),
                    "env-secret")
        finally:
            os.unlink(name)


if __name__ == "__main__":
    unittest.main()

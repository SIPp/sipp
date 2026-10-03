#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import importlib.util
import os
import socket
import struct
import sys
import tempfile
import threading
import unittest
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
            address, lifetime = ice.turn_allocate(
                ("turn.example.org", 3478), "user", "pass", keep=True)
        self.assertEqual(address, ("198.51.100.7", 50000))
        self.assertEqual(lifetime, 600)
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
            address, _ = ice.turn_allocate(
                ("turn.example.org", 3478), "user", "pass")
        self.assertEqual(address, ("198.51.100.7", 50000))
        self.assertEqual(len(calls), 3)

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

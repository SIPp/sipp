#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import importlib.util
import socket
import struct
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
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


def error_value(code):
    return b"\x00\x00" + bytes([code // 100, code % 100])


def raw_response(message_type, attrs, key=None, txid=TXID):
    data = ice.build_message(message_type, attrs, txid=txid, integrity_key=key)
    return ice.parse_message(data), data


class StunCodecTests(unittest.TestCase):
    def test_build_parse_roundtrip(self):
        packet = ice.build_message(ice.BINDING_REQUEST, [(ice.USERNAME, b"remote:local")], txid=TXID)
        message = ice.parse_message(packet)
        self.assertEqual(message.message_type, ice.BINDING_REQUEST)
        self.assertEqual(message.transaction_id, TXID)
        self.assertEqual(message.first(ice.USERNAME), b"remote:local")
        self.assertTrue(ice.verify_fingerprint(packet))

    def test_message_integrity(self):
        key = b"candidate-password"
        packet = ice.build_message(ice.BINDING_REQUEST,
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
        self.assertEqual(ice.decode_xor_address(xor_ipv4(), TXID), ("192.0.2.1", 3478))

    def test_rejects_truncated_attribute(self):
        packet = ice.build_message(ice.BINDING_REQUEST, [(ice.USERNAME, b"abcd")], txid=TXID, fingerprint=False)
        with self.assertRaises(ValueError):
            ice.parse_message(packet[:-1])

    def test_server_parser_accepts_hostname_and_bracketed_ipv6(self):
        self.assertEqual(ice._server("stun.example.org:3478"), ("stun.example.org", 3478))
        self.assertEqual(ice._server("[2001:db8::1]:3478"), ("2001:db8::1", 3478))

    def test_ice_validation(self):
        with self.assertRaises(ValueError):
            ice.ice_check(("127.0.0.1", 3478), "", "remote", "password")
        with self.assertRaises(ValueError):
            ice.ice_check(("127.0.0.1", 3478), "local", "remote", "password", priority=-1)
        with self.assertRaises(ValueError):
            ice.ice_check(("127.0.0.1", 3478), "local", "remote", "password", priority=1 << 32)


class TurnTests(unittest.TestCase):
    def test_long_term_key_is_stable(self):
        self.assertEqual(ice._turn_key("user", "example.org", "pass"),
                         ice._turn_key("user", "example.org", "pass"))
        self.assertNotEqual(ice._turn_key("user", "example.org", "pass"),
                            ice._turn_key("user", "example.org", "other"))

    def test_xor_relay_address_can_be_parsed(self):
        response = ice.build_message(ice.ALLOCATE_SUCCESS,
                                     [(ice.XOR_RELAYED_ADDRESS, xor_ipv4("198.51.100.7", 50000))],
                                     txid=TXID)
        message = ice.parse_message(response)
        self.assertEqual(ice.decode_xor_address(message.first(ice.XOR_RELAYED_ADDRESS), TXID),
                         ("198.51.100.7", 50000))

    def test_stale_nonce_is_retried_once(self):
        realm = b"example.org"
        nonce1 = b"nonce-1"
        nonce2 = b"nonce-2"
        key = ice._turn_key("user", "example.org", "pass")

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

        with mock.patch.object(ice, "_request", side_effect=[challenge, stale, success]) as request:
            address, lifetime = ice.turn_allocate(("turn.example.org", 3478), "user", "pass")
        self.assertEqual(address, ("198.51.100.7", 50000))
        self.assertEqual(lifetime, 600)
        self.assertEqual(request.call_count, 3)

    def test_stale_nonce_without_nonce_fails(self):
        realm = b"example.org"
        challenge = raw_response(0x0113, [
            (ice.ERROR_CODE, error_value(401)),
            (ice.REALM, realm),
            (ice.NONCE, b"nonce-1"),
        ])
        stale = raw_response(0x0113, [
            (ice.ERROR_CODE, error_value(438)),
            (ice.REALM, realm),
        ])
        with mock.patch.object(ice, "_request", side_effect=[challenge, stale]):
            with self.assertRaisesRegex(RuntimeError, "no NONCE"):
                ice.turn_allocate(("turn.example.org", 3478), "user", "pass")

    def test_turn_credentials_must_be_non_empty(self):
        with self.assertRaises(ValueError):
            ice.turn_allocate(("127.0.0.1", 3478), "", "pass")


if __name__ == "__main__":
    unittest.main()

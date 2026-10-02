#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import importlib.util
import socket
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sipp_ice", ROOT / "tools" / "sipp_ice.py")
ice = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = ice
spec.loader.exec_module(ice)

TXID = bytes.fromhex("0102030405060708090a0b0c")


def xor_ipv4(address="192.0.2.1", port=3478):
    raw = socket.inet_pton(socket.AF_INET, address)
    xport = port ^ (ice.MAGIC_COOKIE >> 16)
    xaddr = bytes(a ^ b for a, b in zip(raw, ice.COOKIE))
    return b"\x00\x01" + struct.pack("!H", xport) + xaddr


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

    def test_fingerprint_detects_tampering(self):
        packet = bytearray(ice.build_message(ice.BINDING_REQUEST, txid=TXID))
        packet[-1] ^= 1
        self.assertFalse(ice.verify_fingerprint(bytes(packet)))

    def test_xor_mapped_ipv4(self):
        self.assertEqual(ice.decode_xor_address(xor_ipv4(), TXID), ("192.0.2.1", 3478))

    def test_rejects_truncated_attribute(self):
        packet = ice.build_message(ice.BINDING_REQUEST, [(ice.USERNAME, b"abcd")], txid=TXID, fingerprint=False)
        with self.assertRaises(ValueError):
            ice.parse_message(packet[:-1])


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


if __name__ == "__main__":
    unittest.main()

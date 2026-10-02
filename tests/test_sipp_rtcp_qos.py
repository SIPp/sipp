#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import argparse
import base64
import hashlib
import hmac
import importlib.util
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sipp_rtcp_qos", ROOT / "tools" / "sipp_rtcp_qos.py")
qos = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = qos
spec.loader.exec_module(qos)


def receiver_report(*, fraction=64, lost=3, jitter=80, lsr=0x00010000, dlsr=0x00010000):
    lost24 = lost & 0xFFFFFF
    block = (
        struct.pack("!I", 0x11223344)
        + bytes([fraction])
        + lost24.to_bytes(3, "big")
        + struct.pack("!IIII", 0x00010002, jitter, lsr, dlsr)
    )
    return struct.pack("!BBH", 0x81, 201, 7) + struct.pack("!I", 0x55667788) + block


def make_srtcp(plain, inline_key, index=7, tag_bytes=10):
    master_key, master_salt = qos._sdes_material(inline_key)
    enc_key = qos._srtcp_kdf(master_key, master_salt, 0x03, 16)
    auth_key = qos._srtcp_kdf(master_key, master_salt, 0x04, 20)
    salt_key = qos._srtcp_kdf(master_key, master_salt, 0x05, 14)
    ssrc = struct.unpack_from("!I", plain, 4)[0]
    iv_int = int.from_bytes(salt_key + b"\x00\x00", "big") ^ (ssrc << 64) ^ (index << 16)
    encrypted = plain[:8] + qos._aes_ctr(enc_key, iv_int.to_bytes(16, "big"), plain[8:])
    authenticated = encrypted + struct.pack("!I", 0x80000000 | index)
    tag = hmac.new(auth_key, authenticated, hashlib.sha1).digest()[:tag_bytes]
    return authenticated + tag


class RtcpParserTests(unittest.TestCase):
    def test_receiver_report(self):
        packet = qos.parse_rtcp(receiver_report())[0]
        self.assertEqual(packet.packet_type, 201)
        self.assertEqual(packet.sender_ssrc, 0x55667788)
        self.assertEqual(len(packet.reports), 1)
        report = packet.reports[0]
        self.assertEqual(report.ssrc, 0x11223344)
        self.assertEqual(report.cumulative_lost, 3)
        self.assertAlmostEqual(report.loss_percent, 25.0)

    def test_signed_cumulative_loss(self):
        report = qos.parse_rtcp(receiver_report(lost=-2))[0].reports[0]
        self.assertEqual(report.cumulative_lost, -2)

    def test_rejects_truncation(self):
        with self.assertRaises(ValueError):
            qos.parse_rtcp(receiver_report()[:-1])

    def test_rejects_wrong_version(self):
        data = bytearray(receiver_report())
        data[0] = 0x41
        with self.assertRaises(ValueError):
            qos.parse_rtcp(bytes(data))

    def test_bracketed_ipv6_listener_endpoint(self):
        self.assertEqual(qos._host_port("[2001:db8::1]:9001"), ("2001:db8::1", 9001))
        self.assertEqual(qos._host_port("127.0.0.1:9001"), ("127.0.0.1", 9001))


class QosTests(unittest.TestCase):
    def test_rtt_from_lsr_dlsr(self):
        report = qos.parse_rtcp(receiver_report())[0].reports[0]
        self.assertAlmostEqual(qos.rtt_ms(report, 0x00030000), 1000.0)

    def test_jitter_loss_and_mos(self):
        report = qos.parse_rtcp(receiver_report(jitter=80, fraction=0, lsr=0, dlsr=0))[0].reports[0]
        result = qos.estimate_mos(report, 8000, 20.0)
        self.assertAlmostEqual(result["jitter_ms"], 10.0)
        self.assertAlmostEqual(result["loss_percent"], 0.0)
        self.assertGreaterEqual(result["mos_lq"], 1.0)
        self.assertLessEqual(result["mos_lq"], 4.5)

    def test_loss_reduces_mos(self):
        clean = qos.parse_rtcp(receiver_report(fraction=0, lsr=0, dlsr=0))[0].reports[0]
        lossy = qos.parse_rtcp(receiver_report(fraction=64, lsr=0, dlsr=0))[0].reports[0]
        self.assertGreater(qos.estimate_mos(clean, 8000, 20.0)["mos_lq"],
                           qos.estimate_mos(lossy, 8000, 20.0)["mos_lq"])

    def test_non_positive_clock_rate_is_rejected(self):
        report = qos.parse_rtcp(receiver_report())[0].reports[0]
        with self.assertRaises(ValueError):
            qos.estimate_mos(report, 0, 20.0)
        with self.assertRaises(ValueError):
            qos.decode(receiver_report(), -1)


class SrtcpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("cryptography package is not installed")

    def test_rfc3711_srtcp_kdf_vectors(self):
        # Independent AES-CM/SRTCP key derivation vector used by established
        # SRTP implementations: master key/salt from RFC 3711 Appendix B.3,
        # with SRTCP labels 0x03, 0x04 and 0x05.
        key = bytes.fromhex("e1f97a0d3e018be0d64fa32c06de4139")
        salt = bytes.fromhex("0ec675ad498afeebb6960b3aabe6")
        self.assertEqual(qos._srtcp_kdf(key, salt, 0x03, 16).hex(),
                         "4c1aa45a81f73d61c800bbb00fbb1eaa")
        self.assertEqual(qos._srtcp_kdf(key, salt, 0x04, 20).hex(),
                         "8d54534feb49ae8e7993a6bd0b844fc323a93dfd")
        self.assertEqual(qos._srtcp_kdf(key, salt, 0x05, 14).hex(),
                         "9581c7ad87b3e530bf3e4454a8b3")

    def test_authenticate_and_decrypt(self):
        material = bytes(range(30))
        inline = base64.b64encode(material).decode("ascii")
        plain = receiver_report(fraction=8, jitter=40)
        packet = make_srtcp(plain, inline, index=23)
        decoded, index, encrypted = qos.decrypt_srtcp(packet, inline)
        self.assertEqual(decoded, plain)
        self.assertEqual(index, 23)
        self.assertTrue(encrypted)

    def test_authentication_failure(self):
        material = bytes(range(30))
        inline = base64.b64encode(material).decode("ascii")
        packet = bytearray(make_srtcp(receiver_report(), inline))
        packet[-1] ^= 0x01
        with self.assertRaisesRegex(ValueError, "authentication"):
            qos.decrypt_srtcp(bytes(packet), inline)

    def test_invalid_kdf_label_is_rejected(self):
        key = bytes(range(16))
        salt = bytes(range(14))
        with self.assertRaises(ValueError):
            qos._srtcp_kdf(key, salt, 0x06, 16)

    def test_sdes_material_requires_exact_key_and_salt_length(self):
        with self.assertRaises(ValueError):
            qos._sdes_material(base64.b64encode(bytes(range(31))).decode("ascii"))


if __name__ == "__main__":
    unittest.main()

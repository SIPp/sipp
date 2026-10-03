#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import argparse
import base64
import importlib.util
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sipp_rtcp_qos", ROOT / "tools" / "sipp_rtcp_qos.py")
qos = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = qos
spec.loader.exec_module(qos)


def report_block(*, fraction=64, lost=3, highest=0x00010002, jitter=80,
                 lsr=0x00010000, dlsr=0x00010000):
    lost24 = lost & 0xFFFFFF
    return (
        struct.pack("!I", 0x11223344)
        + bytes([fraction])
        + lost24.to_bytes(3, "big")
        + struct.pack("!IIII", highest, jitter, lsr, dlsr)
    )


def receiver_report(**kwargs):
    block = report_block(**kwargs)
    return struct.pack("!BBH", 0x81, 201, 7) + struct.pack("!I", 0x55667788) + block


def sender_report():
    sender_info = struct.pack("!IIIII", 0xE0000001, 0x80000000, 1234, 55, 8800)
    return struct.pack("!BBH", 0x80, 200, 6) + struct.pack("!I", 0xAABBCCDD) + sender_info


def padded_receiver_report():
    packet = bytearray(receiver_report())
    packet[0] |= 0x20
    struct.pack_into("!H", packet, 2, 8)
    packet.extend(b"\x00\x00\x00\x04")
    return bytes(packet)


class RtcpParserTests(unittest.TestCase):
    def test_receiver_report(self):
        packet = qos.parse_rtcp(receiver_report())[0]
        self.assertEqual(packet.packet_type, 201)
        self.assertEqual(packet.sender_ssrc, 0x55667788)
        report = packet.reports[0]
        self.assertEqual(report.ssrc, 0x11223344)
        self.assertEqual(report.cumulative_lost, 3)
        self.assertAlmostEqual(report.interval_loss_percent, 25.0)

    def test_sender_report_and_compound_packet(self):
        packets = qos.parse_rtcp(sender_report() + receiver_report())
        self.assertEqual([packet.packet_type for packet in packets], [200, 201])
        self.assertEqual(packets[0].sender_ssrc, 0xAABBCCDD)
        self.assertEqual(len(packets[1].reports), 1)

    def test_final_packet_padding(self):
        packets = qos.parse_rtcp(sender_report() + padded_receiver_report())
        self.assertEqual([packet.packet_type for packet in packets], [200, 201])
        self.assertEqual(packets[1].reports[0].cumulative_lost, 3)

    def test_rejects_padding_before_final_compound_packet(self):
        with self.assertRaisesRegex(ValueError, "padding"):
            qos.parse_rtcp(padded_receiver_report() + sender_report())

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

    def test_endpoint_parser_rejects_unbracketed_ipv6(self):
        self.assertEqual(qos._host_port("[2001:db8::1]:9001"), ("2001:db8::1", 9001))
        with self.assertRaises(argparse.ArgumentTypeError):
            qos._host_port("2001:db8::1:9001")


class QosTests(unittest.TestCase):
    def test_rtt_requires_known_local_ssrc(self):
        report = qos.parse_rtcp(receiver_report())[0].reports[0]
        self.assertIsNone(qos.rtt_ms(report, 0x00030000))
        self.assertAlmostEqual(
            qos.rtt_ms(report, 0x00030000, local_ssrcs={0x11223344}), 1000.0)
        self.assertIsNone(qos.rtt_ms(report, 0x00030000, local_ssrcs={0x99999999}))

    def test_rtt_sanity_limit_rejects_absurd_value(self):
        report = qos.parse_rtcp(receiver_report(lsr=1, dlsr=0))[0].reports[0]
        self.assertIsNone(qos.rtt_ms(report, 0x10000000,
                                     local_ssrcs={0x11223344}, max_rtt_ms=10_000))

    def test_missing_rtt_returns_null_conversational_mos(self):
        report = qos.parse_rtcp(receiver_report(fraction=0, lsr=0, dlsr=0))[0].reports[0]
        result = qos.estimate_mos(report, 8000, None, loss_percent=0.0)
        self.assertIsNone(result["rtt_ms"])
        self.assertIsNone(result["r_factor"])
        self.assertIsNone(result["mos_cq"])

    def test_g107_equipment_impairment_and_delay(self):
        report = qos.parse_rtcp(receiver_report(fraction=0, jitter=80))[0].reports[0]
        result = qos.estimate_mos(report, 8000, 100.0, loss_percent=1.0, ie=0.0, bpl=25.1)
        expected_ie_eff = 95.0 / 26.1
        expected_r = 93.2 - (0.024 * 50.0) - expected_ie_eff
        self.assertAlmostEqual(result["jitter_ms"], 10.0)
        self.assertAlmostEqual(result["ie_eff"], expected_ie_eff, places=6)
        self.assertAlmostEqual(result["r_factor"], expected_r, places=6)
        self.assertGreater(result["mos_cq"], 1.0)

    def test_observed_cumulative_loss_is_used_after_baseline(self):
        state = qos.QosState()
        first = qos.parse_rtcp(receiver_report(fraction=26, lost=10, highest=1000))[0].reports[0]
        second = qos.parse_rtcp(receiver_report(fraction=0, lost=15, highest=1100))[0].reports[0]
        loss1, source1 = state.loss_percent(first)
        loss2, source2 = state.loss_percent(second)
        self.assertAlmostEqual(loss1, first.interval_loss_percent)
        self.assertEqual(source1, "interval")
        self.assertAlmostEqual(loss2, 5.0)
        self.assertEqual(source2, "observed-cumulative")

    def test_non_positive_clock_rate_is_rejected(self):
        report = qos.parse_rtcp(receiver_report())[0].reports[0]
        with self.assertRaises(ValueError):
            qos.estimate_mos(report, 0, 20.0)
        with self.assertRaises(ValueError):
            qos.decode(receiver_report(), -1)


class SrtcpTests(unittest.TestCase):
    MASTER = bytes.fromhex("e1f97a0d3e018be0d64fa32c06de4139")
    SALT = bytes.fromhex("0ec675ad498afeebb6960b3aabe6")
    INLINE = base64.b64encode(MASTER + SALT).decode("ascii")
    PLAIN = bytes.fromhex(
        "81c9000755667788112233440800000300010002000000280001000000010000")
    # Fixed packet generated independently with OpenSSL AES-128-CTR using the
    # RFC 3711 Appendix B.3 SRTCP KDF outputs and index 23.
    PACKET = bytes.fromhex(
        "81c9000755667788354b3b889f8141e085dd112ab85e6360fea519b7a47e02a9"
        "80000017400f4a11fbd5a1c3e21a")

    def test_rfc3711_srtcp_kdf_vectors(self):
        self.assertEqual(qos._srtcp_kdf(self.MASTER, self.SALT, 0x03, 16).hex(),
                         "4c1aa45a81f73d61c800bbb00fbb1eaa")
        self.assertEqual(qos._srtcp_kdf(self.MASTER, self.SALT, 0x04, 20).hex(),
                         "8d54534feb49ae8e7993a6bd0b844fc323a93dfd")
        self.assertEqual(qos._srtcp_kdf(self.MASTER, self.SALT, 0x05, 14).hex(),
                         "9581c7ad87b3e530bf3e4454a8b3")

    def test_fixed_srtcp_vector_authenticates_and_decrypts(self):
        decoded, index, encrypted = qos.SrtcpContext(self.INLINE).decrypt(self.PACKET)
        self.assertEqual(decoded, self.PLAIN)
        self.assertEqual(index, 23)
        self.assertTrue(encrypted)

    def test_replay_is_rejected(self):
        context = qos.SrtcpContext(self.INLINE)
        context.decrypt(self.PACKET)
        with self.assertRaisesRegex(ValueError, "replay"):
            context.decrypt(self.PACKET)

    def test_authentication_failure(self):
        packet = bytearray(self.PACKET)
        packet[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "authentication"):
            qos.SrtcpContext(self.INLINE).decrypt(bytes(packet))

    def test_inline_prefix_is_accepted_but_mki_lifetime_is_rejected(self):
        self.assertEqual(qos._sdes_material("inline:" + self.INLINE), (self.MASTER, self.SALT))
        with self.assertRaisesRegex(ValueError, "lifetime/MKI"):
            qos._sdes_material("inline:" + self.INLINE + "|2^20")
        with self.assertRaisesRegex(ValueError, "lifetime/MKI"):
            qos._sdes_material("inline:" + self.INLINE + "|1:4")

    def test_secret_file_and_env_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "key"
            path.write_text("inline:" + self.INLINE + "\n", encoding="utf-8")
            self.assertEqual(qos._read_secret(inline=None, file_path=str(path), env_name=None),
                             "inline:" + self.INLINE)
        os.environ["SIPP_TEST_SRTCP"] = self.INLINE
        try:
            self.assertEqual(qos._read_secret(inline=None, file_path=None,
                                              env_name="SIPP_TEST_SRTCP"), self.INLINE)
        finally:
            del os.environ["SIPP_TEST_SRTCP"]


class ListenerHelpersTests(unittest.TestCase):
    def test_rate_limiter_zero_disables_limit(self):
        limiter = qos.OutputRateLimiter(0)
        self.assertTrue(all(limiter.allow() for _ in range(100)))

    def test_peer_resolution_includes_port(self):
        peers = qos._resolve_peer(("127.0.0.1", 9001))
        self.assertIn(("127.0.0.1", 9001), peers)


if __name__ == "__main__":
    unittest.main()

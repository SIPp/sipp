#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import argparse
import base64
import contextlib
import importlib.util
import io
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
spec = importlib.util.spec_from_file_location("sipp_rtcp_qos", ROOT / "tools" / "sipp_rtcp_qos.py")
qos = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = qos
spec.loader.exec_module(qos)


def report_block(*, ssrc=0x11223344, fraction=64, lost=3,
                 highest=0x00010002, jitter=80,
                 lsr=0x00010000, dlsr=0x00010000):
    lost24 = lost & 0xFFFFFF
    return (
        struct.pack("!I", ssrc)
        + bytes([fraction])
        + lost24.to_bytes(3, "big")
        + struct.pack("!IIII", highest, jitter, lsr, dlsr)
    )


def receiver_report(*, sender_ssrc=0x55667788, **kwargs):
    block = report_block(**kwargs)
    return struct.pack("!BBH", 0x81, 201, 7) + struct.pack("!I", sender_ssrc) + block


def sender_report(*, with_report=False, sender_ssrc=0xAABBCCDD, **kwargs):
    sender_info = struct.pack("!IIIII", 0xE0000001, 0x80000000, 1234, 55, 8800)
    if not with_report:
        return struct.pack("!BBH", 0x80, 200, 6) + struct.pack("!I", sender_ssrc) + sender_info
    block = report_block(**kwargs)
    return struct.pack("!BBH", 0x81, 200, 12) + struct.pack("!I", sender_ssrc) + sender_info + block


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

    def test_sender_report_with_report_block(self):
        packet = qos.parse_rtcp(sender_report(
            with_report=True, fraction=32, lost=7, highest=12345))[0]
        self.assertEqual(packet.packet_type, 200)
        self.assertEqual(packet.sender_ssrc, 0xAABBCCDD)
        self.assertEqual(len(packet.reports), 1)
        self.assertEqual(packet.reports[0].ssrc, 0x11223344)
        self.assertEqual(packet.reports[0].cumulative_lost, 7)
        self.assertEqual(packet.reports[0].highest_sequence, 12345)
        self.assertAlmostEqual(packet.reports[0].interval_loss_percent, 12.5)

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
        self.assertEqual(qos.parse_endpoint("[2001:db8::1]:9001"), ("2001:db8::1", 9001))
        with self.assertRaises(argparse.ArgumentTypeError):
            qos.parse_endpoint("2001:db8::1:9001")


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

    def test_r_to_mos_mapping(self):
        self.assertEqual(qos._mos_from_r(-1.0), 1.0)
        self.assertEqual(qos._mos_from_r(0.0), 1.0)
        self.assertAlmostEqual(qos._mos_from_r(80.0), 4.024, places=3)
        self.assertEqual(qos._mos_from_r(100.0), 4.5)
        self.assertEqual(qos._mos_from_r(120.0), 4.5)

    def test_delay_impairment_knee_at_177_3_ms(self):
        report = qos.parse_rtcp(receiver_report(fraction=0, jitter=0))[0].reports[0]
        at_knee = qos.estimate_mos(report, 8000, 354.6, loss_percent=0.0)
        above_knee = qos.estimate_mos(report, 8000, 400.0, loss_percent=0.0)
        self.assertAlmostEqual(at_knee["r_factor"], 93.2 - 0.024 * 177.3, places=6)
        expected_above = 93.2 - 0.024 * 200.0 - 0.11 * (200.0 - 177.3)
        self.assertAlmostEqual(above_knee["r_factor"], expected_above, places=6)
        self.assertLess(above_knee["r_factor"], at_knee["r_factor"])

    def test_loss_state_is_per_reporter_and_source(self):
        state = qos.QosState()
        first = qos.parse_rtcp(receiver_report(lost=10, highest=1000))[0].reports[0]
        second = qos.parse_rtcp(receiver_report(lost=20, highest=1100))[0].reports[0]
        loss1, source1 = state.loss_percent(0xAAAABBBB, first)
        loss2, source2 = state.loss_percent(0xCCCCDDDD, second)
        self.assertAlmostEqual(loss1, first.interval_loss_percent)
        self.assertAlmostEqual(loss2, second.interval_loss_percent)
        self.assertEqual(source1, "interval")
        self.assertEqual(source2, "interval")

    def test_loss_baseline_rolls_each_report(self):
        state = qos.QosState()
        first = qos.parse_rtcp(receiver_report(fraction=0, lost=0, highest=1000))[0].reports[0]
        second = qos.parse_rtcp(receiver_report(fraction=0, lost=1, highest=1100))[0].reports[0]
        third = qos.parse_rtcp(receiver_report(fraction=0, lost=11, highest=1200))[0].reports[0]
        self.assertEqual(state.loss_percent(0x55667788, first)[1], "interval")
        loss2, source2 = state.loss_percent(0x55667788, second)
        loss3, source3 = state.loss_percent(0x55667788, third)
        self.assertAlmostEqual(loss2, 1.0)
        self.assertAlmostEqual(loss3, 10.0)
        self.assertEqual(source2, "observed-delta")
        self.assertEqual(source3, "observed-delta")

    def test_loss_state_is_bounded(self):
        state = qos.QosState(max_entries=2)
        report = qos.parse_rtcp(receiver_report())[0].reports[0]
        state.loss_percent(1, report)
        state.loss_percent(2, report)
        state.loss_percent(3, report)
        self.assertEqual(len(state._baseline), 2)
        self.assertNotIn((1, report.ssrc), state._baseline)

    def test_non_positive_clock_rate_is_rejected(self):
        report = qos.parse_rtcp(receiver_report())[0].reports[0]
        with self.assertRaises(ValueError):
            qos.estimate_mos(report, 0, 20.0)
        with self.assertRaises(ValueError):
            qos.decode(receiver_report(), -1)


@unittest.skipUnless(importlib.util.find_spec("cryptography"), "needs the cryptography package")
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

    def test_empty_secret_sources_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "empty"):
            qos._read_secret(inline="   ", file_path=None, env_name=None)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "empty-key"
            path.write_text("\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "empty"):
                qos._read_secret(inline=None, file_path=str(path), env_name=None)
        os.environ["SIPP_TEST_EMPTY_SRTCP"] = ""
        try:
            with self.assertRaisesRegex(ValueError, "empty"):
                qos._read_secret(inline=None, file_path=None, env_name="SIPP_TEST_EMPTY_SRTCP")
        finally:
            del os.environ["SIPP_TEST_EMPTY_SRTCP"]


class ListenerHelpersTests(unittest.TestCase):
    def test_non_finite_options_are_rejected(self):
        for option in ("--bpl", "--max-rtt-ms", "--rate-limit", "--ie"):
            with self.subTest(option=option), self.assertRaises(SystemExit), \
                    contextlib.redirect_stderr(io.StringIO()):
                qos.main(["--hex", "00", option, "nan"])

    def test_listener_reports_its_address_and_stops_on_ctrl_c(self):
        sock = mock.MagicMock()
        sock.__enter__.return_value = sock
        sock.getsockname.return_value = ("127.0.0.1", 9001)
        sock.recvfrom.side_effect = KeyboardInterrupt
        err = io.StringIO()
        with mock.patch.object(qos, "_bind_udp", return_value=sock), contextlib.redirect_stderr(err):
            self.assertEqual(qos.main(["--listen", "127.0.0.1:9001"]), 0)
        self.assertIn("listening on 127.0.0.1:9001", err.getvalue())

    def test_rate_limiter_zero_disables_limit(self):
        limiter = qos.OutputRateLimiter(0)
        self.assertTrue(all(limiter.allow() for _ in range(100)))

    def test_fractional_rate_limiter_has_one_token_capacity(self):
        limiter = qos.OutputRateLimiter(0.5)
        self.assertEqual(limiter.capacity, 1.0)
        self.assertTrue(limiter.allow())
        self.assertFalse(limiter.allow())
        limiter.updated -= 2.0
        self.assertTrue(limiter.allow())

    def test_peer_resolution_includes_port(self):
        peers = qos._resolve_peer(("127.0.0.1", 9001))
        self.assertIn(("127.0.0.1", 9001), peers)

    def test_ipv4_mapped_ipv6_peer_is_normalized(self):
        self.assertEqual(qos._normalize_ip("::ffff:192.0.2.10"), "192.0.2.10")
        self.assertEqual(qos._normalize_ip("2001:db8::10"), "2001:db8::10")


if __name__ == "__main__":
    unittest.main()

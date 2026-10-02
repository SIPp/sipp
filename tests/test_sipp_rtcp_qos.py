#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import importlib.util
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sipp_rtcp_qos", ROOT / "tools" / "sipp_rtcp_qos.py")
qos = importlib.util.module_from_spec(spec)
assert spec and spec.loader
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


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sipp_impair", ROOT / "tools" / "sipp_impair.py")
impair = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = impair
spec.loader.exec_module(impair)


class FakeSocket:
    def __init__(self):
        self.sent = []

    def sendto(self, data, target):
        self.sent.append((data, target))
        return len(data)


class ImpairmentTests(unittest.TestCase):
    def test_fixed_delay(self):
        sock = FakeSocket()
        engine = impair.ImpairmentEngine(impair.Profile(delay_ms=100), seed=1)
        engine.submit(sock, ("127.0.0.1", 9000), b"x", 1.0)
        engine.flush(1.099)
        self.assertEqual(sock.sent, [])
        engine.flush(1.101)
        self.assertEqual(len(sock.sent), 1)

    def test_full_loss(self):
        sock = FakeSocket()
        engine = impair.ImpairmentEngine(impair.Profile(loss_percent=100), seed=1)
        engine.submit(sock, ("127.0.0.1", 9000), b"x", 1.0)
        engine.flush(2.0)
        self.assertEqual(sock.sent, [])
        self.assertEqual(engine.counters.dropped, 1)

    def test_duplication(self):
        sock = FakeSocket()
        engine = impair.ImpairmentEngine(impair.Profile(duplicate_percent=100), seed=1)
        engine.submit(sock, ("127.0.0.1", 9000), b"x", 1.0)
        engine.flush(2.0)
        self.assertEqual(len(sock.sent), 2)
        self.assertEqual(engine.counters.duplicated, 1)

    def test_reordering_inverts_adjacent_packets(self):
        sock = FakeSocket()
        profile = impair.Profile(reorder_percent=100, reorder_delay_ms=40)
        engine = impair.ImpairmentEngine(profile, seed=1)
        engine.submit(sock, ("127.0.0.1", 9000), b"first", 1.000)
        engine.submit(sock, ("127.0.0.1", 9000), b"second", 1.010)
        engine.flush(2.0)
        self.assertEqual([data for data, _ in sock.sent], [b"second", b"first"])
        self.assertEqual(engine.counters.reordered, 1)

    def test_reorder_hold_expires_without_losing_packet(self):
        sock = FakeSocket()
        profile = impair.Profile(reorder_percent=100, reorder_delay_ms=40)
        engine = impair.ImpairmentEngine(profile, seed=1)
        engine.submit(sock, ("127.0.0.1", 9000), b"only", 1.0)
        engine.flush(1.039)
        self.assertEqual(sock.sent, [])
        engine.flush(1.041)
        self.assertEqual([data for data, _ in sock.sent], [b"only"])
        self.assertEqual(engine.counters.reordered, 0)

    def test_burst_loss(self):
        sock = FakeSocket()
        profile = impair.Profile(burst_start_percent=100, burst_length=3)
        engine = impair.ImpairmentEngine(profile, seed=1)
        for i in range(3):
            engine.submit(sock, ("127.0.0.1", 9000), bytes([i]), 1.0)
        self.assertEqual(engine.counters.burst_dropped, 3)
        self.assertEqual(len(engine.queue), 0)

    def test_profile_validation(self):
        with self.assertRaises(ValueError):
            impair.Profile(loss_percent=101).validate()
        with self.assertRaises(ValueError):
            impair.Profile(jitter_ms=-1).validate()
        with self.assertRaises(ValueError):
            impair.Profile(reorder_percent=1, reorder_delay_ms=0).validate()

    def test_endpoint_parser_accepts_ipv4_and_bracketed_ipv6(self):
        self.assertEqual(impair.parse_endpoint("127.0.0.1:9000"), ("127.0.0.1", 9000))
        self.assertEqual(impair.parse_endpoint("[2001:db8::1]:9000"), ("2001:db8::1", 9000))


if __name__ == "__main__":
    unittest.main()

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


if __name__ == "__main__":
    unittest.main()

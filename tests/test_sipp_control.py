#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sipp_control", ROOT / "tools" / "sipp_control.py")
control = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = control
spec.loader.exec_module(control)


class ControlTests(unittest.TestCase):
    def test_hotkeys(self):
        self.assertEqual(control.build_control("pause"), "p")
        self.assertEqual(control.build_control("quit-now"), "Q")

    def test_command_mode(self):
        self.assertEqual(control.build_control("rate", 250.5), "cset rate 250.5")
        self.assertEqual(control.build_control("users", 100), "cset users 100")

    def test_rejects_unsafe_or_invalid_actions(self):
        with self.assertRaises(ValueError):
            control.build_control("raw", "Q")
        with self.assertRaises(ValueError):
            control.build_control("limit", 1.5)
        with self.assertRaises(ValueError):
            control.build_control("rate", float("inf"))
        with self.assertRaises(ValueError):
            control.build_control("rate", -1)
        with self.assertRaises(ValueError):
            control.build_control("users", -1)
        with self.assertRaises(ValueError):
            control.build_control("limit", -1)

    def test_zero_is_valid(self):
        self.assertEqual(control.build_control("rate", 0), "cset rate 0")
        self.assertEqual(control.build_control("users", 0), "cset users 0")
        self.assertEqual(control.build_control("limit", 0), "cset limit 0")

    def test_statistics_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "stats.csv"
            path.write_text("CallRate(C);SuccessfulCall(C)\n42.5;100\n", encoding="utf-8")
            snapshot = control.read_stat(path)
            self.assertEqual(snapshot["CallRate(C)"], 42.5)
            self.assertEqual(snapshot["SuccessfulCall(C)"], 100.0)


if __name__ == "__main__":
    unittest.main()

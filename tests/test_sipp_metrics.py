#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


metrics = load("sipp_metrics", ROOT / "tools" / "sipp_metrics.py")
otlp = load("sipp_otlp", ROOT / "tools" / "sipp_otlp.py")


class MetricsTests(unittest.TestCase):
    def test_reader_uses_latest_complete_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "uac_1.csv"
            path.write_text(
                "ElapsedTime(C);CallRate(C);SuccessfulCall(C);Label\n"
                "1;10;8;ignored\n"
                "2;12.5;11;ignored\n",
                encoding="utf-8",
            )
            snap = metrics.StatFileReader(path).read()
            self.assertEqual(snap.values["ElapsedTime(C)"], 2.0)
            self.assertEqual(snap.values["CallRate(C)"], 12.5)
            self.assertNotIn("Label", snap.values)

    def test_stat_discovery_ignores_rtt_trace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stat = root / "scenario.csv"
            rtt = root / "scenario_123_rtt.csv"
            stat.write_text("A\n1\n", encoding="utf-8")
            rtt.write_text("B\n2\n", encoding="utf-8")
            now = time.time()
            os.utime(stat, (now - 10, now - 10))
            os.utime(rtt, (now, now))
            self.assertEqual(metrics.find_latest_stat_file(root), stat)

    def test_prometheus_names_are_valid(self):
        self.assertEqual(metrics.metric_name("SuccessfulCall(C)"), "sipp_successfulcall_c")
        self.assertEqual(metrics.metric_name("1xx response"), "sipp_field_1xx_response")

    def test_otlp_contains_gauges(self):
        payload = otlp.build_otlp({"CallRate(C)": 42.0}, 1.5, "loadtest")
        resource = payload["resourceMetrics"][0]
        point = resource["scopeMetrics"][0]["metrics"][0]["gauge"]["dataPoints"][0]
        self.assertEqual(point["asDouble"], 42.0)
        self.assertEqual(point["timeUnixNano"], "1500000000")

    def test_otlp_de_duplicates_sanitized_names(self):
        payload = otlp.build_otlp({"A-B": 1.0, "A B": 2.0}, 1.0, "loadtest")
        names = [m["name"] for m in payload["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]]
        self.assertEqual(names, ["sipp_a_b", "sipp_a_b_2"])

    def test_header_validation(self):
        self.assertEqual(otlp.parse_headers(["Authorization=Bearer token"]),
                         {"Authorization": "Bearer token"})
        with self.assertRaises(ValueError):
            otlp.parse_headers(["=value"])
        with self.assertRaises(ValueError):
            otlp.parse_headers(["X-Test=value\nInjected: true"])


if __name__ == "__main__":
    unittest.main()

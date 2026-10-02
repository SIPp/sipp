#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sipp_report", ROOT / "tools" / "sipp_report.py")
report = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = report
spec.loader.exec_module(report)


class ReportTests(unittest.TestCase):
    def test_threshold_parser(self):
        threshold = report.Threshold.parse("SuccessfulCall(C)>=1000")
        self.assertEqual(threshold.column, "SuccessfulCall(C)")
        self.assertEqual(threshold.operator, ">=")
        self.assertEqual(threshold.target, 1000.0)

    def test_rejects_empty_threshold_column(self):
        with self.assertRaises(ValueError):
            report.Threshold.parse("   >=1")

    def test_evaluation_and_junit(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "run.csv"
            path.write_text(
                "SuccessfulCall(C);FailedCall(C);CallRate(C)\n1000;2;250.5\n",
                encoding="utf-8",
            )
            stat = report.StatResult(path)
            results = [
                stat.evaluate(report.Threshold.parse("SuccessfulCall(C)>=1000")),
                stat.evaluate(report.Threshold.parse("FailedCall(C)==0")),
            ]
            self.assertTrue(results[0].passed)
            self.assertFalse(results[1].passed)
            xml = report.junit_xml(results, str(path))
            self.assertIn('tests="2"', xml)
            self.assertIn('failures="1"', xml)
            self.assertIn("ThresholdFailure", xml)

    def test_missing_column_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "run.csv"
            path.write_text("CallRate(C)\n10\n", encoding="utf-8")
            result = report.StatResult(path).evaluate(report.Threshold.parse("NoSuchColumn>0"))
            self.assertFalse(result.passed)
            self.assertIsNone(result.actual)

    def test_duplicate_columns_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "run.csv"
            path.write_text("CallRate(C);CallRate(C)\n10;20\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                report.StatResult(path)

    def test_junit_escapes_column_names(self):
        threshold = report.Threshold("A&B<1", ">", 0)
        result = report.ThresholdResult(threshold, 1.0, True, "A&B<1: 1 > 0")
        xml = report.junit_xml([result], "source&file")
        self.assertIn("A&amp;B&lt;1", xml)
        self.assertIn("source&amp;file", xml)


if __name__ == "__main__":
    unittest.main()

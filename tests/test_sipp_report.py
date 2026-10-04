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

    def test_times_are_read_as_seconds(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "run.csv"
            # The columns and format SIPp writes, with a trailing delimiter
            path.write_text(
                "StartTime;ElapsedTime(P);ResponseTime1(C);CallLength(C);Note;\n"
                "2026-10-02\t08:45:55.000\t+0000;00:01:05;00:00:00:012500;01:00:00:000000;abc;\n",
                encoding="utf-8",
            )
            stat = report.StatResult(path)
            self.assertEqual(stat.values["ElapsedTime(P)"], 65.0)
            self.assertAlmostEqual(stat.values["ResponseTime1(C)"], 0.0125)
            self.assertEqual(stat.values["CallLength(C)"], 3600.0)
            self.assertTrue(stat.evaluate(report.Threshold.parse("ResponseTime1(C)<0.05")).passed)
            self.assertFalse(stat.evaluate(report.Threshold.parse("CallLength(C)<60")).passed)

    def test_text_column_is_reported_as_not_a_number(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "run.csv"
            path.write_text("Note;CallRate(C)\nabc;10\n", encoding="utf-8")
            stat = report.StatResult(path)
            self.assertIn("not a number", stat.evaluate(report.Threshold.parse("Note>0")).message)
            self.assertIn("not found", stat.evaluate(report.Threshold.parse("Nope>0")).message)

    def test_only_the_last_row_is_used(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "run.csv"
            path.write_text("CallRate(C)\n1\n2\n3\n", encoding="utf-8")
            self.assertEqual(report.StatResult(path).values["CallRate(C)"], 3.0)

    def test_threshold_file_accepts_several_bounds_for_a_column(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "t.json"
            path.write_text('{"CallRate(C)": [">=1", "<=5"], "FailedCall(C)": "==0"}', encoding="utf-8")
            thresholds = report.load_threshold_file(path)
            self.assertEqual([(t.column, t.operator, t.target) for t in thresholds],
                             [("CallRate(C)", ">=", 1.0), ("CallRate(C)", "<=", 5.0), ("FailedCall(C)", "==", 0.0)])
            path.write_text('{"CallRate(C)": [1]}', encoding="utf-8")
            with self.assertRaises(ValueError):
                report.load_threshold_file(path)

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

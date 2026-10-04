#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Evaluate SIPp -trace_stat results against CI-friendly thresholds."""

from __future__ import annotations

import argparse
import csv
import json
import math
import operator
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Set


_THRESHOLD_RE = re.compile(r"^\s*(.+?)\s*(<=|>=|==|!=|<|>)\s*([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)\s*$")
# SIPp writes elapsed times, response times and call lengths as HH:MM:SS or
# HH:MM:SS:UUUUUU (microseconds); they are read as seconds.
_TIME_RE = re.compile(r"^(\d+):(\d{2}):(\d{2})(?::(\d{1,6}))?$")
_OPS: Dict[str, Callable[[float, float], bool]] = {
    "<": operator.lt,
    "<=": operator.le,
    ">": operator.gt,
    ">=": operator.ge,
    "==": operator.eq,
    "!=": operator.ne,
}


@dataclass(frozen=True)
class Threshold:
    column: str
    operator: str
    target: float

    @classmethod
    def parse(cls, text: str) -> "Threshold":
        match = _THRESHOLD_RE.match(text)
        if not match:
            raise ValueError(f"invalid threshold {text!r}; expected COLUMN<OP>NUMBER")
        column, op, target = match.groups()
        column = column.strip()
        if not column:
            raise ValueError("threshold column cannot be empty")
        return cls(column, op, float(target))


@dataclass(frozen=True)
class ThresholdResult:
    threshold: Threshold
    actual: Optional[float]
    passed: bool
    message: str


def _parse_value(raw: str) -> Optional[float]:
    """A number, or an HH:MM:SS[:UUUUUU] time as seconds; None for any other text."""
    raw = raw.strip()
    match = _TIME_RE.match(raw)
    if match:
        hours, minutes, seconds, micros = match.groups()
        return int(hours) * 3600 + int(minutes) * 60 + int(seconds) + int((micros or "0").ljust(6, "0")) / 1e6
    try:
        value = float(raw)
    except ValueError:
        return None
    return value if math.isfinite(value) else None


class StatResult:
    def __init__(self, path: Path, delimiter: str = ";") -> None:
        self.path = path
        self.delimiter = delimiter
        self.values: Dict[str, float] = {}
        self.text_columns: Set[str] = set()
        self._read_latest()

    def _read_latest(self) -> None:
        header: Optional[List[str]] = None
        data: Optional[List[str]] = None
        # Only the header and the last row are kept: a long run with -fd 1s has many rows.
        with self.path.open("r", encoding="utf-8", newline="") as handle:
            for row in csv.reader(handle, delimiter=self.delimiter):
                if not any(v.strip() for v in row):
                    continue
                if header is None:
                    header = [value.strip() for value in row]
                else:
                    data = row
        if header is None or data is None:
            raise ValueError(f"{self.path} has no complete statistics row")
        if len(data) < len(header):
            raise ValueError(f"{self.path} ends with an incomplete statistics row")
        named = [name for name in header if name]
        if len(named) != len(set(named)):
            raise ValueError(f"{self.path} contains duplicate statistics column names")
        for name, raw in zip(header, data):
            if not name:
                continue
            value = _parse_value(raw)
            if value is None:
                self.text_columns.add(name)
            else:
                self.values[name] = value

    def evaluate(self, threshold: Threshold) -> ThresholdResult:
        actual = self.values.get(threshold.column)
        if actual is None:
            reason = "is not a number or a time" if threshold.column in self.text_columns else "not found"
            return ThresholdResult(threshold, None, False, f"column {threshold.column!r} {reason}")
        passed = _OPS[threshold.operator](actual, threshold.target)
        message = f"{threshold.column}: {actual:g} {threshold.operator} {threshold.target:g}"
        return ThresholdResult(threshold, actual, passed, message)


def load_threshold_file(path: Path) -> List[Threshold]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("threshold file must be a JSON object")
    result: List[Threshold] = []
    for column, conditions in data.items():
        # A list gives several bounds on one column: ["<=5", ">=1"]
        if isinstance(conditions, str):
            conditions = [conditions]
        if not isinstance(column, str) or not isinstance(conditions, list) or not all(
                isinstance(condition, str) for condition in conditions):
            raise ValueError("threshold file keys must be strings and values strings or lists of strings")
        result.extend(Threshold.parse(f"{column}{condition}") for condition in conditions)
    return result


def result_json(results: List[ThresholdResult]) -> str:
    return json.dumps(
        {
            "passed": all(result.passed for result in results),
            "assertions": [
                {
                    "column": result.threshold.column,
                    "operator": result.threshold.operator,
                    "target": result.threshold.target,
                    "actual": result.actual,
                    "passed": result.passed,
                    "message": result.message,
                }
                for result in results
            ],
        },
        sort_keys=True,
        indent=2,
    )


def junit_xml(results: List[ThresholdResult], source: str) -> str:
    suite = ET.Element(
        "testsuite",
        name="sipp.thresholds",
        tests=str(len(results)),
        failures=str(sum(not result.passed for result in results)),
    )
    props = ET.SubElement(suite, "properties")
    ET.SubElement(props, "property", name="source", value=source)
    for result in results:
        case = ET.SubElement(suite, "testcase", classname="sipp.threshold", name=result.threshold.column)
        ET.SubElement(case, "system-out").text = result.message
        if not result.passed:
            failure = ET.SubElement(case, "failure", message=result.message, type="ThresholdFailure")
            failure.text = result.message
    return ET.tostring(suite, encoding="unicode") + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Assert thresholds against SIPp -trace_stat output")
    parser.add_argument("stat_file", type=Path)
    parser.add_argument("--delimiter", default=";")
    parser.add_argument("--threshold", action="append", default=[], metavar="EXPR",
                        help="repeatable expression such as 'SuccessfulCall(C)>=1000'")
    parser.add_argument("--threshold-file", type=Path, help="JSON object mapping column names to expressions")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    parser.add_argument("--json-out", type=Path, help="write JSON report to this path")
    parser.add_argument("--junit-out", type=Path, help="write JUnit XML report to this path")
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        thresholds = [Threshold.parse(text) for text in args.threshold]
        if args.threshold_file:
            thresholds.extend(load_threshold_file(args.threshold_file))
        if not thresholds:
            raise ValueError("at least one --threshold or --threshold-file is required")
        stat = StatResult(args.stat_file, args.delimiter)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"sipp_report: {exc}")
        return 2

    results = [stat.evaluate(threshold) for threshold in thresholds]
    json_text = result_json(results)
    if args.json:
        print(json_text)
    else:
        for result in results:
            print(("PASS" if result.passed else "FAIL") + "  " + result.message)
    try:
        if args.json_out:
            args.json_out.write_text(json_text + "\n", encoding="utf-8")
        if args.junit_out:
            args.junit_out.write_text(junit_xml(results, str(args.stat_file)), encoding="utf-8")
    except OSError as exc:
        print(f"sipp_report: cannot write report: {exc}")
        return 2
    return 0 if all(result.passed for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

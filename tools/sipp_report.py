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
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple


_THRESHOLD_RE = re.compile(r"^\s*(.+?)\s*(<=|>=|==|!=|<|>)\s*([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)\s*$")
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
        return cls(column.strip(), op, float(target))


@dataclass(frozen=True)
class ThresholdResult:
    threshold: Threshold
    actual: Optional[float]
    passed: bool
    message: str


class StatResult:
    def __init__(self, path: Path, delimiter: str = ";") -> None:
        self.path = path
        self.delimiter = delimiter
        self.values = self._read_latest()

    def _read_latest(self) -> Dict[str, float]:
        with self.path.open("r", encoding="utf-8", newline="") as handle:
            rows = [row for row in csv.reader(handle, delimiter=self.delimiter) if any(v.strip() for v in row)]
        if len(rows) < 2:
            raise ValueError(f"{self.path} has no complete statistics row")
        header = [value.strip() for value in rows[0]]
        data = rows[-1]
        if len(data) < len(header):
            raise ValueError(f"{self.path} ends with an incomplete statistics row")
        result: Dict[str, float] = {}
        for name, raw in zip(header, data):
            try:
                value = float(raw.strip())
            except ValueError:
                continue
            if math.isfinite(value):
                result[name] = value
        return result

    def evaluate(self, threshold: Threshold) -> ThresholdResult:
        actual = self.values.get(threshold.column)
        if actual is None:
            return ThresholdResult(threshold, None, False, f"column {threshold.column!r} not found or not numeric")
        passed = _OPS[threshold.operator](actual, threshold.target)
        message = f"{threshold.column}: {actual:g} {threshold.operator} {threshold.target:g}"
        return ThresholdResult(threshold, actual, passed, message)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Assert thresholds against SIPp -trace_stat output")
    parser.add_argument("stat_file", type=Path)
    parser.add_argument("--delimiter", default=";")
    parser.add_argument("--threshold", action="append", default=[], metavar="EXPR",
                        help="repeatable expression such as 'SuccessfulCall(C)>=1000'")
    parser.add_argument("--threshold-file", type=Path, help="JSON object mapping column names to expressions")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    return parser


def load_threshold_file(path: Path) -> List[Threshold]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("threshold file must be a JSON object")
    result: List[Threshold] = []
    for column, condition in data.items():
        if not isinstance(column, str) or not isinstance(condition, str):
            raise ValueError("threshold file keys and values must be strings")
        result.append(Threshold.parse(f"{column}{condition}"))
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
    )


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
    if args.json:
        print(result_json(results))
    else:
        for result in results:
            print(("PASS" if result.passed else "FAIL") + "  " + result.message)
    return 0 if all(result.passed for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

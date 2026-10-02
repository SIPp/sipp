#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Read SIPp -trace_stat CSV output as a live metrics snapshot.

The reader intentionally uses only the Python standard library so it can be
installed next to the SIPp binary without adding runtime dependencies.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Optional


_NUMBER_RE = re.compile(r"^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$")


def _number(value: str) -> Optional[float]:
    value = value.strip()
    if not value or not _NUMBER_RE.match(value):
        return None
    try:
        result = float(value)
    except ValueError:
        return None
    return result if math.isfinite(result) else None


@dataclass(frozen=True)
class MetricsSnapshot:
    source: str
    collected_at: float
    values: Dict[str, float]

    def as_json(self) -> str:
        return json.dumps(
            {
                "source": self.source,
                "collected_at": self.collected_at,
                "metrics": self.values,
            },
            sort_keys=True,
        )


class StatFileReader:
    """Return the latest complete row from a SIPp statistics CSV file."""

    def __init__(self, path: Path, delimiter: str = ";") -> None:
        self.path = path
        self.delimiter = delimiter

    def read(self) -> MetricsSnapshot:
        try:
            with self.path.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.reader(handle, delimiter=self.delimiter))
        except OSError as exc:
            raise RuntimeError(f"cannot read {self.path}: {exc}") from exc

        rows = [row for row in rows if any(field.strip() for field in row)]
        if len(rows) < 2:
            raise RuntimeError(f"{self.path} has no complete statistics row")

        header = [field.strip() for field in rows[0]]
        data = rows[-1]
        if len(data) < len(header):
            raise RuntimeError(f"{self.path} ends with an incomplete statistics row")

        values: Dict[str, float] = {}
        duplicate_count: Dict[str, int] = {}
        for name, raw in zip(header, data):
            value = _number(raw)
            if value is None:
                continue
            key = name or "unnamed"
            if key in values:
                duplicate_count[key] = duplicate_count.get(key, 1) + 1
                key = f"{key}_{duplicate_count[key]}"
            values[key] = value

        return MetricsSnapshot(str(self.path), time.time(), values)


def find_latest_stat_file(directory: Path) -> Path:
    candidates = list(directory.glob("*_*.csv"))
    if not candidates:
        candidates = list(directory.glob("*.csv"))
    candidates = [p for p in candidates if p.is_file()]
    if not candidates:
        raise RuntimeError(f"no CSV statistics file found in {directory}")
    return max(candidates, key=lambda p: p.stat().st_mtime_ns)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Expose SIPp -trace_stat metrics")
    parser.add_argument("--stat-file", type=Path, help="SIPp statistics CSV file")
    parser.add_argument("--stat-dir", type=Path, default=Path("."), help="directory used to discover the latest CSV")
    parser.add_argument("--delimiter", default=";", help="statistics delimiter (default: ;)")
    parser.add_argument("--watch", type=float, metavar="SECONDS", help="print JSON snapshots repeatedly")
    return parser


def _reader_from_args(args: argparse.Namespace) -> StatFileReader:
    path = args.stat_file or find_latest_stat_file(args.stat_dir)
    return StatFileReader(path, args.delimiter)


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    reader = _reader_from_args(args)
    interval = args.watch
    while True:
        try:
            print(reader.read().as_json(), flush=True)
        except RuntimeError as exc:
            print(json.dumps({"error": str(exc)}), flush=True)
            if not interval:
                return 1
        if not interval:
            return 0
        time.sleep(max(interval, 0.05))


if __name__ == "__main__":
    raise SystemExit(main())

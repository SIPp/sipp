#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Read SIPp -trace_stat CSV output and expose live metrics.

The exporter intentionally uses only the Python standard library so it can be
installed next to the SIPp binary without adding runtime dependencies.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Iterable, Optional


_NUMBER_RE = re.compile(r"^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$")
_METRIC_RE = re.compile(r"[^a-zA-Z0-9_:]")


def _number(value: str) -> Optional[float]:
    value = value.strip()
    if not value or not _NUMBER_RE.match(value):
        return None
    try:
        result = float(value)
    except ValueError:
        return None
    return result if math.isfinite(result) else None


def metric_name(column: str) -> str:
    name = _METRIC_RE.sub("_", column.strip()).strip("_").lower()
    if not name:
        name = "unnamed"
    if name[0].isdigit():
        name = "field_" + name
    return "sipp_" + name


@dataclass(frozen=True)
class MetricsSnapshot:
    source: str
    collected_at: float
    values: Dict[str, float]

    def as_json(self) -> str:
        return json.dumps(
            {"source": self.source, "collected_at": self.collected_at, "metrics": self.values},
            sort_keys=True,
        )

    def as_prometheus(self) -> str:
        lines = ["# HELP sipp_exporter_up Whether the SIPp statistics file was readable.",
                 "# TYPE sipp_exporter_up gauge", "sipp_exporter_up 1"]
        seen: Dict[str, int] = {}
        for column, value in self.values.items():
            name = metric_name(column)
            if name in seen:
                seen[name] += 1
                name = f"{name}_{seen[name]}"
            else:
                seen[name] = 1
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name} {value:.17g}")
        lines.extend([
            "# TYPE sipp_exporter_last_scrape_timestamp_seconds gauge",
            f"sipp_exporter_last_scrape_timestamp_seconds {self.collected_at:.6f}",
        ])
        return "\n".join(lines) + "\n"


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
    # -trace_rtt writes <scenario>_<pid>_rtt.csv.  Do not accidentally
    # select that file when --stat-dir is intended to discover -trace_stat.
    candidates = [
        p for p in directory.glob("*.csv")
        if p.is_file() and not p.name.endswith("_rtt.csv")
    ]
    if not candidates:
        raise RuntimeError(f"no SIPp statistics CSV file found in {directory}")
    return max(candidates, key=lambda p: p.stat().st_mtime_ns)


class SnapshotStore:
    def __init__(self, reader: StatFileReader) -> None:
        self.reader = reader
        self.lock = threading.Lock()
        self.snapshot: Optional[MetricsSnapshot] = None
        self.error: Optional[str] = None

    def refresh(self) -> None:
        try:
            snapshot = self.reader.read()
        except RuntimeError as exc:
            with self.lock:
                self.error = str(exc)
            return
        with self.lock:
            self.snapshot = snapshot
            self.error = None

    def render_prometheus(self) -> str:
        self.refresh()
        with self.lock:
            if self.snapshot is None:
                return "# TYPE sipp_exporter_up gauge\nsipp_exporter_up 0\n"
            text = self.snapshot.as_prometheus()
            if self.error:
                text = text.replace("sipp_exporter_up 1", "sipp_exporter_up 0", 1)
            return text

    def render_json(self) -> str:
        self.refresh()
        with self.lock:
            if self.snapshot is None:
                return json.dumps({"error": self.error or "no snapshot"})
            payload = json.loads(self.snapshot.as_json())
            if self.error:
                payload["error"] = self.error
            return json.dumps(payload, sort_keys=True)


class MetricsHandler(BaseHTTPRequestHandler):
    store: SnapshotStore

    def do_GET(self) -> None:
        if self.path == "/metrics":
            body = self.store.render_prometheus().encode()
            ctype = "text/plain; version=0.0.4; charset=utf-8"
        elif self.path in ("/", "/v1/metrics"):
            body = self.store.render_json().encode()
            ctype = "application/json"
        elif self.path == "/healthz":
            self.store.refresh()
            ok = self.store.snapshot is not None and self.store.error is None
            body = (b"ok\n" if ok else b"unhealthy\n")
            self.send_response(200 if ok else 503)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def serve(store: SnapshotStore, listen: str, port: int) -> None:
    handler = type("SippMetricsHandler", (MetricsHandler,), {"store": store})
    ThreadingHTTPServer((listen, port), handler).serve_forever()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Expose SIPp -trace_stat metrics")
    parser.add_argument("--stat-file", type=Path, help="SIPp statistics CSV file")
    parser.add_argument("--stat-dir", type=Path, default=Path("."), help="directory used to discover the latest CSV")
    parser.add_argument("--delimiter", default=";", help="statistics delimiter (default: ;)")
    parser.add_argument("--watch", type=float, metavar="SECONDS", help="print JSON snapshots repeatedly")
    parser.add_argument("--listen", default="127.0.0.1", help="HTTP listen address")
    parser.add_argument("--port", type=int, default=9876, help="HTTP listen port")
    parser.add_argument("--serve", action="store_true", help="serve /metrics, /v1/metrics and /healthz")
    return parser


def _reader_from_args(args: argparse.Namespace) -> StatFileReader:
    path = args.stat_file or find_latest_stat_file(args.stat_dir)
    return StatFileReader(path, args.delimiter)


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    reader = _reader_from_args(args)
    if args.serve:
        serve(SnapshotStore(reader), args.listen, args.port)
        return 0
    while True:
        try:
            print(reader.read().as_json(), flush=True)
        except RuntimeError as exc:
            print(json.dumps({"error": str(exc)}), flush=True)
            if not args.watch:
                return 1
        if not args.watch:
            return 0
        time.sleep(max(args.watch, 0.05))


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Push SIPp trace_stat snapshots to an OTLP/HTTP JSON endpoint."""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from sipp_metrics import MetricsSnapshot, SnapshotStore, add_source_arguments, reader_from_args

# HTTP field names are RFC 9110 tokens.
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
# OTLP AggregationTemporality
_CUMULATIVE = 2
HEADERS_ENV = "OTEL_EXPORTER_OTLP_HEADERS"


def _nanos(timestamp: float) -> str:
    return str(int(timestamp * 1_000_000_000))


def build_otlp(snapshot: MetricsSnapshot, service_name: str) -> dict:
    # Points carry the time SIPp wrote the row, not the time of the push.
    time_unix_nano = _nanos(snapshot.row_time)
    metrics = []
    for series in snapshot.series():
        point = {"asDouble": series.value, "timeUnixNano": time_unix_nano}
        metric: dict = {"name": series.name, "description": f"SIPp statistics column {series.column}"}
        if series.seconds:
            metric["unit"] = "s"
        if series.counter:
            if snapshot.start_time is not None:
                point["startTimeUnixNano"] = _nanos(snapshot.start_time)
            metric["sum"] = {
                "dataPoints": [point],
                "aggregationTemporality": _CUMULATIVE,
                "isMonotonic": True,
            }
        else:
            metric["gauge"] = {"dataPoints": [point]}
        metrics.append(metric)
    return {
        "resourceMetrics": [
            {
                "resource": {
                    "attributes": [
                        {
                            "key": "service.name",
                            "value": {"stringValue": service_name},
                        },
                        {
                            "key": "telemetry.sdk.name",
                            "value": {"stringValue": "sipp-trace-stat"},
                        },
                    ]
                },
                "scopeMetrics": [
                    {
                        "scope": {"name": "sipp.metrics", "version": "1"},
                        "metrics": metrics,
                    }
                ],
            }
        ]
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would send the headers, such as Authorization, elsewhere."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def push(endpoint: str, payload: dict, timeout: float, headers: Dict[str, str]) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode()
    request = urllib.request.Request(endpoint, data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    for name, value in headers.items():
        request.add_header(name, value)
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        exc.close()
        status = exc.code
    if status < 200 or status >= 300:
        raise RuntimeError(f"OTLP endpoint returned HTTP {status}")


def _header(name: str, value: str) -> tuple[str, str]:
    name = name.strip()
    if not name:
        raise ValueError("OTLP header name cannot be empty")
    if not _HEADER_NAME_RE.match(name):
        raise ValueError(f"invalid OTLP header name {name!r}")
    if "\r" in value or "\n" in value:
        raise ValueError("OTLP header contains a newline")
    return name, value.strip()


def parse_headers(items: Iterable[str]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"invalid header {item!r}; expected NAME=VALUE")
        name, value = _header(*item.split("=", 1))
        result[name] = value
    return result


def read_header_file(path: Path) -> Dict[str, str]:
    """NAME=VALUE lines; blank lines and lines starting with # are skipped."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return parse_headers(line for line in lines if line.strip() and not line.lstrip().startswith("#"))


def parse_env_headers(text: str) -> Dict[str, str]:
    """The OTEL_EXPORTER_OTLP_HEADERS format: comma-separated, percent-encoded NAME=VALUE."""
    items: List[str] = [urllib.parse.unquote(item) for item in text.split(",") if item.strip()]
    return parse_headers(items)


class OtlpExporter:
    def __init__(self, store: SnapshotStore, endpoint: str, timeout: float,
                 headers: Dict[str, str], service_name: str) -> None:
        self.store = store
        self.endpoint = endpoint
        self.timeout = timeout
        self.headers = headers
        self.service_name = service_name
        self.last_row_time: Optional[float] = None
        self.last_message: Optional[str] = None

    def _report(self, message: str) -> None:
        # Repeated messages, such as a stale file after the run, are printed once.
        if message != self.last_message:
            print(f"sipp_otlp: {message}", flush=True)
        self.last_message = message

    def run_once(self) -> bool:
        """Push the newest row if it was not pushed yet; False on any failure."""
        snapshot, error, stale, now = self.store.refresh()
        if snapshot is None:
            self._report(str(error))
            return False
        if stale:
            self._report(f"{snapshot.source}: last row is {snapshot.age(now):.0f}s old, not exported")
            return False
        if snapshot.row_time == self.last_row_time:
            return True
        try:
            push(self.endpoint, build_otlp(snapshot, self.service_name), self.timeout, self.headers)
        except (OSError, ValueError, RuntimeError, http.client.HTTPException) as exc:
            self._report(str(exc))
            return False
        self.last_row_time = snapshot.row_time
        self.last_message = None
        return True


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Push SIPp statistics with OTLP/HTTP JSON")
    add_source_arguments(parser)
    parser.add_argument("--endpoint", default="http://127.0.0.1:4318/v1/metrics")
    parser.add_argument("--service-name", default="sipp")
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--header", action="append", default=[], metavar="NAME=VALUE",
                        help="extra HTTP header; visible in the process list, see --header-file")
    parser.add_argument("--header-file", type=Path, metavar="FILE",
                        help=f"read NAME=VALUE header lines from FILE (also read: ${HEADERS_ENV})")
    parser.add_argument("--once", action="store_true")
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.interval <= 0:
        parser.error("--interval must be positive")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if len(args.delimiter) != 1:
        parser.error("--delimiter must be exactly one character")
    if args.stale_after < 0:
        parser.error("--stale-after cannot be negative")
    if urllib.parse.urlsplit(args.endpoint).scheme not in ("http", "https"):
        parser.error("--endpoint must be an http:// or https:// URL")
    # Later sources win: the environment, then --header-file, then --header.
    try:
        headers = parse_env_headers(os.environ.get(HEADERS_ENV, ""))
        if args.header_file:
            headers.update(read_header_file(args.header_file))
        headers.update(parse_headers(args.header))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        parser.error(str(exc))
    store = SnapshotStore(reader_from_args(args), args.stale_after)
    exporter = OtlpExporter(store, args.endpoint, args.timeout, headers, args.service_name)

    if not args.once:
        print(f"sipp_otlp: pushing to {args.endpoint} every {args.interval:g} s", file=sys.stderr, flush=True)
    try:
        while True:
            ok = exporter.run_once()
            if args.once:
                return 0 if ok else 1
            time.sleep(max(args.interval, 0.1))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

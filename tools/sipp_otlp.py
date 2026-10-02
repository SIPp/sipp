#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Push SIPp trace_stat snapshots to an OTLP/HTTP JSON endpoint."""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict

from sipp_metrics import StatFileReader, find_latest_stat_file, metric_name


def build_otlp(values: Dict[str, float], timestamp: float, service_name: str) -> dict:
    time_unix_nano = str(int(timestamp * 1_000_000_000))
    metrics = []
    for column, value in values.items():
        metrics.append(
            {
                "name": metric_name(column),
                "gauge": {
                    "dataPoints": [
                        {
                            "asDouble": value,
                            "timeUnixNano": time_unix_nano,
                        }
                    ]
                },
            }
        )
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


def push(endpoint: str, payload: dict, timeout: float, headers: Dict[str, str]) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode()
    request = urllib.request.Request(endpoint, data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    for name, value in headers.items():
        request.add_header(name, value)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status < 200 or response.status >= 300:
            raise RuntimeError(f"OTLP endpoint returned HTTP {response.status}")


def parse_headers(items: list[str]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"invalid header {item!r}; expected NAME=VALUE")
        name, value = item.split("=", 1)
        result[name.strip()] = value.strip()
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Push SIPp statistics with OTLP/HTTP JSON")
    parser.add_argument("--stat-file", type=Path)
    parser.add_argument("--stat-dir", type=Path, default=Path("."))
    parser.add_argument("--delimiter", default=";")
    parser.add_argument("--endpoint", default="http://127.0.0.1:4318/v1/metrics")
    parser.add_argument("--service-name", default="sipp")
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--header", action="append", default=[], metavar="NAME=VALUE")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    try:
        headers = parse_headers(args.header)
    except ValueError as exc:
        parser.error(str(exc))
    path = args.stat_file or find_latest_stat_file(args.stat_dir)
    reader = StatFileReader(path, args.delimiter)

    while True:
        snapshot = reader.read()
        payload = build_otlp(snapshot.values, snapshot.collected_at, args.service_name)
        try:
            push(args.endpoint, payload, args.timeout, headers)
        except (OSError, RuntimeError, urllib.error.URLError) as exc:
            print(f"sipp_otlp: {exc}")
            if args.once:
                return 1
        if args.once:
            return 0
        time.sleep(max(args.interval, 0.1))


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Read SIPp -trace_stat CSV output and expose live metrics.

The exporter intentionally uses only the Python standard library so it can be
installed next to the SIPp binary without adding runtime dependencies.  The
values of a row are parsed by sipp_report.StatResult, so numbers and the
HH:MM:SS[:UUUUUU] time columns are read the same way as by the CI report tool.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from stat import S_ISREG
from typing import Callable, Dict, Iterable, List, Optional

from sipp_endpoint import format_endpoint
from sipp_report import StatResult


_METRIC_RE = re.compile(r"[^a-zA-Z0-9_:]+")
# Repartition columns are named like ResponseTimeRepartition1_<10 and _>=200.
_COMPARISONS = (("<=", "_le_"), (">=", "_ge_"), ("<", "_lt_"), (">", "_gt_"))
# -trace_stat writes <scenario>_<pid>_.csv; -trace_counts, -trace_error_codes
# and -trace_rtt write <scenario>_<pid>_counts.csv, ..._error_codes.csv and
# ..._rtt.csv, which this pattern does not match.
_STAT_NAME_RE = re.compile(r"^(?P<scenario>.+)_(?P<pid>\d+)_\.csv$")
_SUFFIX_RE = re.compile(r"^(?P<base>.*?)\((?P<kind>[PC])\)$")
# Columns whose (C) value is a running average, not a cumulative count.
_AVERAGE_RE = re.compile(r"^(CallRate|ResponseTime(?!Repartition)|CallLength(?!Repartition))")
# Columns written as HH:MM:SS[:UUUUUU] and exported in seconds.
_TIME_COLUMN_RE = re.compile(r"^(ElapsedTime|ResponseTime(?!Repartition)|CallLength(?!Repartition))")
STAT_TAIL_CHUNK = 8192
DEFAULT_STALE_AFTER = 120.0


def metric_name(column: str) -> str:
    name = column.strip()
    for text, word in _COMPARISONS:
        name = name.replace(text, word)
    name = re.sub("_+", "_", _METRIC_RE.sub("_", name)).strip("_").lower()
    if not name:
        name = "unnamed"
    if name[0].isdigit():
        name = "field_" + name
    return "sipp_" + name


@dataclass(frozen=True)
class Series:
    """One exported column.  Counters are named without the _total suffix."""

    column: str
    name: str
    counter: bool
    seconds: bool
    value: float


def describe_column(column: str) -> tuple[str, bool, bool]:
    """Return the metric name, whether it is a counter and whether it is in seconds.

    (C) columns are cumulative since SIPp started and are counters, except the
    running averages (CallRate, ResponseTime, CallLength and their StDev).
    (P) columns cover the last -fd period only and get a _period suffix.
    TotalCallCreated has neither suffix and is a counter too.
    """
    match = _SUFFIX_RE.match(column.strip())
    base = match.group("base") if match else column.strip()
    kind = match.group("kind") if match else ""
    seconds = bool(_TIME_COLUMN_RE.match(base))
    # TotalCallCreated has no suffix, but only grows
    counter = (kind == "C" and not _AVERAGE_RE.match(base)) or base == "TotalCallCreated"
    name = metric_name(base)
    if kind == "P":
        name += "_period"
    if seconds:
        name += "_seconds"
    return name, counter, seconds


def _epoch(raw: Optional[str]) -> Optional[float]:
    """The epoch from a SIPp date column: 'YYYY-MM-DD<TAB>HH:MM:SS.us<TAB>epoch'."""
    if not raw or not raw.split():
        return None
    try:
        return float(raw.split()[-1])
    except ValueError:
        return None


def _parse_csv_line(raw: bytes, delimiter: str) -> List[str]:
    return next(csv.reader([raw.decode("utf-8")], delimiter=delimiter), [])


def _latest_complete_row(handle, data_start: int, field_count: int, delimiter: str) -> Optional[bytes]:
    """Read backwards until the newest complete statistics row is found.

    SIPp may be writing the last row while it is read; a row with fewer fields
    than the header is skipped and the previous one is used.
    """
    handle.seek(0, 2)
    pos = handle.tell()
    carry = b""

    while pos > data_start:
        start = max(data_start, pos - STAT_TAIL_CHUNK)
        handle.seek(start)
        data = handle.read(pos - start) + carry
        lines = data.splitlines()

        if start > data_start:
            carry = lines[0] if lines else data
            candidates = lines[1:]
        else:
            carry = b""
            candidates = lines

        for raw in reversed(candidates):
            if raw.strip() and len(_parse_csv_line(raw, delimiter)) >= field_count:
                return raw
        pos = start

    return None


class _RowView:
    """The header and one row, opened by StatResult like the file they come from.

    StatResult reads every row of a file; a long run with -fd 1s has many, and
    the exporter reads the file on every scrape, so only the tail is handed over.
    """

    def __init__(self, path: Path, text: str) -> None:
        self.path = path
        self.text = text

    def open(self, *args: object, **kwargs: object) -> io.StringIO:
        return io.StringIO(self.text)

    def __str__(self) -> str:
        return str(self.path)


@dataclass(frozen=True)
class MetricsSnapshot:
    source: str
    collected_at: float
    row_time: float
    start_time: Optional[float]
    values: Dict[str, float]

    def age(self, now: float) -> float:
        return max(0.0, now - self.row_time)

    def series(self) -> List[Series]:
        result: List[Series] = []
        seen: Dict[str, int] = {}
        for column, value in self.values.items():
            name, counter, seconds = describe_column(column)
            if name in seen:
                seen[name] += 1
                name = f"{name}_{seen[name]}"
            else:
                seen[name] = 1
            result.append(Series(column, name, counter, seconds, value))
        return result

    def as_dict(self, now: float, stale: bool) -> dict:
        return {
            "source": self.source,
            "collected_at": self.collected_at,
            "row_time": self.row_time,
            "row_age_seconds": self.age(now),
            "stale": stale,
            "metrics": self.values,
        }


class StatFileReader:
    """Return the latest complete row of a SIPp statistics file.

    With a directory the newest <scenario>_<pid>_.csv is looked up again on
    every read, so a restarted SIPp (new pid, new file) is picked up.
    """

    def __init__(self, path: Optional[Path] = None, delimiter: str = ";",
                 directory: Optional[Path] = None, scenario: Optional[str] = None) -> None:
        if (path is None) == (directory is None):
            raise ValueError("give either a statistics file or a directory")
        self.path = path
        self.directory = directory
        self.scenario = scenario
        self.delimiter = delimiter

    def resolve(self) -> Path:
        if self.path is not None:
            return self.path
        assert self.directory is not None
        return find_latest_stat_file(self.directory, self.scenario, self.delimiter)

    def read(self) -> MetricsSnapshot:
        path = self.resolve()
        try:
            with path.open("rb") as handle:
                header_raw = handle.readline()
                header = [field.strip() for field in _parse_csv_line(header_raw, self.delimiter)]
                row_raw = _latest_complete_row(handle, handle.tell(), len(header), self.delimiter)
                mtime = path.stat().st_mtime
            if not header or row_raw is None:
                raise RuntimeError(f"{path} has no complete statistics row")
            text = header_raw.decode("utf-8").rstrip("\r\n") + "\n" + row_raw.decode("utf-8") + "\n"
            stat = StatResult(_RowView(path, text), self.delimiter)  # type: ignore[arg-type]
            raw = dict(zip(header, _parse_csv_line(row_raw, self.delimiter)))
        except RuntimeError:
            raise
        except (OSError, UnicodeDecodeError, csv.Error, ValueError) as exc:
            raise RuntimeError(f"cannot read {path}: {exc}") from exc
        # CurrentTime is when SIPp wrote the row; the file time is a fallback
        # for files without it.
        row_time = _epoch(raw.get("CurrentTime"))
        return MetricsSnapshot(
            str(path),
            time.time(),
            row_time if row_time is not None else mtime,
            _epoch(raw.get("StartTime")),
            dict(stat.values),
        )


def _is_stat_file(path: Path, delimiter: str) -> bool:
    """Sniff the header: -trace_stat files start with the StartTime column."""
    try:
        with path.open("rb") as handle:
            first = handle.readline(4096)
    except OSError:
        return False
    return first.startswith(b"StartTime" + delimiter.encode())


def find_latest_stat_file(directory: Path, scenario: Optional[str] = None, delimiter: str = ";") -> Path:
    candidates = []
    for path in directory.glob("*_.csv"):
        match = _STAT_NAME_RE.match(path.name)
        if not match or (scenario is not None and match.group("scenario") != scenario):
            continue
        # A listed file can be removed before it is stat()ed; it is skipped.
        try:
            info = path.stat()
        except OSError:
            continue
        if S_ISREG(info.st_mode) and _is_stat_file(path, delimiter):
            candidates.append((info.st_mtime_ns, path))
    if not candidates:
        raise RuntimeError(f"no SIPp -trace_stat file (<scenario>_<pid>_.csv) found in {directory}")
    return max(candidates, key=lambda item: item[0])[1]


def _format(value: float) -> str:
    return repr(float(value))


def render_prometheus(snapshot: Optional[MetricsSnapshot], now: float, stale: bool) -> str:
    up = snapshot is not None and not stale
    lines = [
        "# HELP sipp_exporter_up Whether the statistics file was read and its last row is recent.",
        "# TYPE sipp_exporter_up gauge",
        f"sipp_exporter_up {int(up)}",
    ]
    if snapshot is None:
        return "\n".join(lines) + "\n"
    lines.extend([
        "# HELP sipp_stat_row_timestamp_seconds When SIPp wrote the last statistics row (CurrentTime).",
        "# TYPE sipp_stat_row_timestamp_seconds gauge",
        f"sipp_stat_row_timestamp_seconds {snapshot.row_time:.6f}",
        "# HELP sipp_stat_row_age_seconds Seconds since SIPp wrote the last statistics row.",
        "# TYPE sipp_stat_row_age_seconds gauge",
        f"sipp_stat_row_age_seconds {snapshot.age(now):.6f}",
    ])
    if stale:
        # The last row of a finished run is not served as if it were live.
        return "\n".join(lines) + "\n"
    for series in snapshot.series():
        name = series.name + ("_total" if series.counter else "")
        kind = "counter" if series.counter else "gauge"
        lines.append(f"# HELP {name} SIPp statistics column {series.column}.")
        lines.append(f"# TYPE {name} {kind}")
        lines.append(f"{name} {_format(series.value)}")
    return "\n".join(lines) + "\n"


def render_json(snapshot: Optional[MetricsSnapshot], error: Optional[str], now: float, stale: bool) -> str:
    if snapshot is None:
        return json.dumps({"error": error})
    return json.dumps(snapshot.as_dict(now, stale), sort_keys=True)


class SnapshotStore:
    def __init__(self, reader: StatFileReader, stale_after: float = DEFAULT_STALE_AFTER,
                 clock: Callable[[], float] = time.time) -> None:
        self.reader = reader
        self.stale_after = stale_after
        self.clock = clock
        self.lock = threading.Lock()

    def refresh(self) -> tuple[Optional[MetricsSnapshot], Optional[str], bool, float]:
        """Read the file now; return the snapshot, the error, staleness and the time."""
        now = self.clock()
        with self.lock:
            try:
                snapshot = self.reader.read()
            except (RuntimeError, OSError) as exc:
                # An OSError can still come from searching the directory.
                return None, str(exc), False, now
        stale = self.stale_after > 0 and snapshot.age(now) > self.stale_after
        return snapshot, None, stale, now

    def render_prometheus(self) -> str:
        snapshot, _, stale, now = self.refresh()
        return render_prometheus(snapshot, now, stale)

    def render_json(self) -> str:
        snapshot, error, stale, now = self.refresh()
        return render_json(snapshot, error, now, stale)

    def healthy(self) -> bool:
        snapshot, _, stale, _ = self.refresh()
        return snapshot is not None and not stale


class MetricsHandler(BaseHTTPRequestHandler):
    store: SnapshotStore
    # A client that connects and sends nothing does not hold a thread forever.
    timeout = 10

    def do_GET(self) -> None:
        status = 200
        if self.path == "/metrics":
            body = self.store.render_prometheus().encode()
            ctype = "text/plain; version=0.0.4; charset=utf-8"
        elif self.path in ("/", "/v1/metrics"):
            body = self.store.render_json().encode()
            ctype = "application/json"
        elif self.path == "/healthz":
            ok = self.store.healthy()
            body = b"ok\n" if ok else b"unhealthy\n"
            ctype = "text/plain"
            status = 200 if ok else 503
        else:
            self.send_error(404)
            return
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def make_server(store: SnapshotStore, listen: str, port: int) -> ThreadingHTTPServer:
    handler = type("SippMetricsHandler", (MetricsHandler,), {"store": store})
    return ThreadingHTTPServer((listen, port), handler)


def add_source_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--stat-file", type=Path, help="SIPp statistics file (<scenario>_<pid>_.csv)")
    parser.add_argument("--stat-dir", type=Path, default=Path("."),
                        help="directory searched for the newest <scenario>_<pid>_.csv on every read")
    parser.add_argument("--scenario", help="with --stat-dir, only use files of this scenario name")
    parser.add_argument("--delimiter", default=";", help="statistics delimiter (default: ;)")
    parser.add_argument("--stale-after", type=float, default=DEFAULT_STALE_AFTER, metavar="SECONDS",
                        help="a last row older than this is stale; 0 disables (default: %(default)s)")


def reader_from_args(args: argparse.Namespace) -> StatFileReader:
    if args.stat_file:
        return StatFileReader(args.stat_file, args.delimiter)
    return StatFileReader(None, args.delimiter, directory=args.stat_dir, scenario=args.scenario)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Expose SIPp -trace_stat metrics")
    add_source_arguments(parser)
    parser.add_argument("--watch", type=float, metavar="SECONDS", help="print JSON snapshots repeatedly")
    parser.add_argument("--listen", default="127.0.0.1", help="HTTP listen address")
    parser.add_argument("--port", type=int, default=9876, help="HTTP listen port")
    parser.add_argument("--serve", action="store_true", help="serve /metrics, /v1/metrics and /healthz")
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if len(args.delimiter) != 1:
        parser.error("--delimiter must be exactly one character")
    if args.stale_after < 0:
        parser.error("--stale-after cannot be negative")
    store = SnapshotStore(reader_from_args(args), args.stale_after)
    if args.serve:
        server = make_server(store, args.listen, args.port)
        host, port = server.server_address[:2]
        print(f"sipp_metrics: listening on http://{format_endpoint((host, port))}/metrics", file=sys.stderr, flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return 0
    while True:
        snapshot, error, stale, now = store.refresh()
        print(render_json(snapshot, error, now, stale), flush=True)
        if not args.watch:
            return 0 if snapshot is not None and not stale else 1
        time.sleep(max(args.watch, 0.05))


if __name__ == "__main__":
    raise SystemExit(main())

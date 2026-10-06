#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Small HTTP control plane for SIPp's UDP remote-control socket."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

from sipp_endpoint import format_endpoint
from sipp_report import StatResult


# The '+', '-', '*' and '/' keys change the rate by 1 or 10 times rate_scale,
# or the number of users by the same amount when SIPp runs with -users.
HOTKEYS = {
    "pause": "p",
    "quit": "q",
    "quit-now": "Q",
    "step-up": "+",
    "step-down": "-",
    "step-up-10": "*",
    "step-down-10": "/",
}
COMMANDS = {
    "rate": "set rate {value}",
    "rate-scale": "set rate-scale {value}",
    "users": "set users {value}",
    "limit": "set limit {value}",
}
INTEGER_COMMANDS = {"users", "limit"}
INT_MAX = 2**31 - 1
# SIPp ignores these in the other mode, with only a warning on its own screen.
MODE_ACTIONS = {"rate": {"users"}, "users": {"rate", "limit"}}
# A second 'q' makes SIPp quit immediately; a repeated "quit" within this
# window is taken as a double click and refused.
QUIT_DEBOUNCE = 2.0
# How long to wait for an ICMP port unreachable after sending.
UNREACHABLE_WAIT = 0.05
DASHBOARD = Path(__file__).with_name("sipp_control.html")
# Numeric columns worth showing live; the stat file has many more.
STATUS_COLUMNS = (
    "ElapsedTime(C)",
    "TargetRate",
    "CallRate(P)",
    "CallRate(C)",
    "CurrentCall",
    "TotalCallCreated",
    "SuccessfulCall(P)",
    "SuccessfulCall(C)",
    "FailedCall(P)",
    "FailedCall(C)",
    "Retransmissions(C)",
    "OutOfCallMsgs(C)",
    "DeadCallMsgs(C)",
    "Warnings(C)",
    "FatalErrors(C)",
    "WatchdogMajor(C)",
    "WatchdogMinor(C)",
    "ResponseTime1(C)",
    "CallLength(C)",
)
LOOPBACK_NAMES = ("127.0.0.1", "localhost", "[::1]")
INLINE_RE = re.compile(r"<(script|style)>(.*?)</\1>", re.DOTALL)


class ControlError(Exception):
    """A request that is valid but cannot be carried out now."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def send_control(host: str, port: int, payload: str) -> None:
    """Send one datagram; raise OSError if the port is known to be closed.

    SIPp never answers, so success only means the datagram left. On loopback
    an ICMP port unreachable arrives at once and shows up as
    ConnectionRefusedError on the connected socket.
    """
    family, _, _, _, address = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)[0]
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.connect(address)
        sock.send(payload.encode("utf-8"))
        sock.settimeout(UNREACHABLE_WAIT)
        try:
            sock.recv(1)
        except socket.timeout:
            pass


def _number_text(action: str, value: object) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{action} requires a numeric value")
    try:
        numeric = float(value)
    except OverflowError:
        raise ValueError(f"{action} value is out of range") from None
    if numeric != numeric or numeric in (float("inf"), float("-inf")):
        raise ValueError(f"{action} requires a finite numeric value")
    if numeric < 0:
        raise ValueError(f"{action} requires a non-negative value")
    if action == "rate-scale" and numeric == 0:
        raise ValueError("rate-scale must be greater than 0")
    if numeric > INT_MAX:
        raise ValueError(f"{action} must be at most {INT_MAX}")
    if action in INTEGER_COMMANDS:
        if numeric != int(numeric):
            raise ValueError(f"{action} requires an integer value")
        return str(int(numeric))
    return str(int(numeric)) if numeric == int(numeric) else repr(numeric)


def build_control(action: str, value: Optional[object] = None) -> str:
    if action in HOTKEYS:
        if value is not None:
            raise ValueError(f"{action} does not take a value")
        return HOTKEYS[action]
    template = COMMANDS.get(action)
    if template is None:
        raise ValueError(f"unsupported action {action!r}")
    return "c" + template.format(value=_number_text(action, value))


def find_stat_file(directory: Path, scenario: str) -> Optional[Path]:
    """Newest <scenario>_<pid>_.csv in directory, as SIPp names -trace_stat output."""
    pattern = re.compile(re.escape(scenario) + r"_(\d+)_\.csv")
    try:
        candidates = [path for path in directory.iterdir() if pattern.fullmatch(path.name)]
    except OSError:
        return None
    newest: Optional[Tuple[int, Path]] = None
    for path in candidates:
        try:
            mtime = path.stat().st_mtime_ns
        except OSError:
            continue  # removed since the listing
        if newest is None or mtime > newest[0]:
            newest = (mtime, path)
    return newest[1] if newest else None


def stat_file_pid(path: Path) -> Optional[int]:
    match = re.fullmatch(r".*_(\d+)_\.csv", path.name)
    return int(match.group(1)) if match else None


def pid_running(pid: int) -> Optional[bool]:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return None
    return True


class StatReader:
    """Latest statistics row, read with sipp_report.StatResult.

    The file is re-read only when it changes. SIPp may be part-way through
    writing a row; the previous complete row is kept in that case.
    """

    def __init__(self, stat_file: Optional[Path], stat_dir: Optional[Path], scenario: Optional[str],
                 delimiter: str, stale_after: float) -> None:
        self.stat_file = stat_file
        self.stat_dir = stat_dir
        self.scenario = scenario
        self.delimiter = delimiter
        self.stale_after = stale_after
        self._lock = threading.Lock()
        self._key: Optional[Tuple[str, int, int]] = None
        self._values: Dict[str, float] = {}

    def _path(self) -> Optional[Path]:
        if self.stat_file is not None:
            return self.stat_file
        if self.stat_dir is not None and self.scenario:
            return find_stat_file(self.stat_dir, self.scenario)
        return None

    def snapshot(self) -> Dict[str, object]:
        path = self._path()
        if path is None:
            if self.stat_file is None and self.stat_dir is None:
                return {"error": "no statistics file configured"}
            return {"error": "no statistics file found"}
        result: Dict[str, object] = {"file": str(path)}
        pid = stat_file_pid(path)
        if pid is not None:
            result["pid"] = pid
            result["sipp_running"] = pid_running(pid)
        try:
            info = path.stat()
            key = (str(path), info.st_mtime_ns, info.st_size)
            with self._lock:
                if key != self._key:
                    self._values = self._read(path)
                    self._key = key
                values = dict(self._values)
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            result["error"] = str(exc)
            return result
        age = max(0.0, time.time() - info.st_mtime)
        result["age_seconds"] = round(age, 1)
        result["stale"] = age > self.stale_after or result.get("sipp_running") is False
        result["values"] = values
        return result

    def _read(self, path: Path) -> Dict[str, float]:
        try:
            stat = StatResult(path, self.delimiter)
        except ValueError:
            # Keep the last good row while SIPp is writing the next one.
            if self._key is not None and self._key[0] == str(path):
                return self._values
            raise
        return {name: stat.values[name] for name in STATUS_COLUMNS if name in stat.values}


class ControlState:
    def __init__(self, target: Tuple[str, int], stats: StatReader, mode: Optional[str] = None) -> None:
        self.target = target
        self.stats = stats
        self.mode = mode
        self.started_at = time.time()
        self.last_sent: Optional[dict] = None
        self.pause_toggles = 0
        self._last_quit = float("-inf")
        self._lock = threading.Lock()

    def status(self) -> dict:
        with self._lock:
            last_sent = self.last_sent
            pause_toggles = self.pause_toggles
        return {
            "target": {"host": self.target[0], "port": self.target[1]},
            "mode": self.mode,
            "uptime_seconds": time.time() - self.started_at,
            "last_sent": last_sent,
            "pause_toggles_sent": pause_toggles,
            "statistics": self.stats.snapshot(),
        }

    def control(self, action: str, value: Optional[object]) -> dict:
        payload = build_control(action, value)
        if self.mode and action in MODE_ACTIONS[self.mode]:
            raise ControlError(409, f"SIPp ignores {action} when it runs in {self.mode} mode")
        with self._lock:
            now = time.monotonic()
            if action == "quit" and now - self._last_quit < QUIT_DEBOUNCE:
                raise ControlError(409, "quit was just sent; a second q makes SIPp quit immediately")
            try:
                send_control(self.target[0], self.target[1], payload)
            except OSError as exc:
                raise ControlError(502, f"cannot send to {self.target[0]}:{self.target[1]}: {exc}") from None
            if action == "quit":
                self._last_quit = now
            if action == "pause":
                self.pause_toggles += 1
            self.last_sent = {"action": action, "value": value, "payload": payload, "at": time.time()}
            return dict(self.last_sent)


def inline_hashes(html: str) -> Dict[str, List[str]]:
    """CSP sources for the inline <script> and <style> blocks of the dashboard."""
    result: Dict[str, List[str]] = {"script": [], "style": []}
    for kind, body in INLINE_RE.findall(html):
        digest = base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode("ascii")
        result[kind].append(f"'sha256-{digest}'")
    return result


def content_security_policy(html: str) -> str:
    hashes = inline_hashes(html)
    script = " ".join(hashes["script"]) or "'none'"
    style = " ".join(hashes["style"]) or "'none'"
    return (f"default-src 'none'; connect-src 'self'; script-src {script}; style-src {style}; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def allowed_hosts(listen: str, port: int, extra: Iterable[str] = ()) -> set:
    names = set(LOOPBACK_NAMES) | set(extra)
    if not is_loopback(listen) and listen not in ("0.0.0.0", "::"):
        names.add(f"[{listen}]" if ":" in listen else listen)
    return {f"{name}:{port}".lower() for name in names}


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class ApiHandler(BaseHTTPRequestHandler):
    # Seconds a socket read or write may block; without it a client that stops
    # sending mid-request holds its thread and socket forever.
    timeout = 10
    state: ControlState
    hosts: set
    token: Optional[str] = None
    dashboard: bytes = b""
    csp: str = ""

    def _write(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", self.csp)
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict) -> None:
        self._write(status, json.dumps(payload, sort_keys=True).encode("utf-8"), "application/json")

    def _check_request(self) -> bool:
        """Reject DNS rebinding, cross-site requests and missing tokens."""
        host = self.headers.get("Host", "").strip().lower()
        if host not in self.hosts:
            self._json(403, {"error": "Host header not allowed"})
            return False
        origin = self.headers.get("Origin")
        if origin is not None and urlsplit(origin).netloc.lower() not in self.hosts:
            self._json(403, {"error": "Origin not allowed"})
            return False
        if self.token is not None and self.path.startswith("/api/"):
            given = self.headers.get("Authorization", "")
            if not hmac.compare_digest(given.encode("utf-8"), f"Bearer {self.token}".encode("utf-8")):
                self._json(401, {"error": "missing or wrong token"})
                return False
        return True

    def do_GET(self) -> None:
        if not self._check_request():
            return
        if self.path == "/api/v1/status":
            self._json(200, self.state.status())
        elif self.path == "/healthz":
            self._json(200, {"status": "ok"})
        elif self.path in ("/", "/index.html"):
            self._write(200, self.dashboard, "text/html; charset=utf-8")
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if not self._check_request():
            return
        if self.path != "/api/v1/control":
            self._json(404, {"error": "not found"})
            return
        try:
            ctype = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if ctype != "application/json":
                raise ValueError("Content-Type must be application/json")
            size = int(self.headers.get("Content-Length", "0"))
            if size <= 0 or size > 4096:
                raise ValueError("request body must be between 1 and 4096 bytes")
            request = json.loads(self.rfile.read(size).decode("utf-8"))
            if not isinstance(request, dict):
                raise ValueError("JSON body must be an object")
            result = self.state.control(str(request.get("action", "")), request.get("value"))
        except ControlError as exc:
            self._json(exc.status, {"error": str(exc)})
            return
        except socket.timeout:
            # The rest of the body may still arrive; the connection cannot be reused.
            self.close_connection = True
            self._json(408, {"error": "timed out reading the request body"})
            return
        except (ValueError, UnicodeDecodeError) as exc:
            self._json(400, {"error": str(exc)})
            return
        except Exception as exc:  # never leave the client without an answer
            self._json(500, {"error": f"internal error: {exc.__class__.__name__}"})
            return
        self._json(200, result)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def make_server(state: ControlState, listen: str, port: int, token: Optional[str] = None,
                extra_hosts: Iterable[str] = ()) -> ThreadingHTTPServer:
    html = DASHBOARD.read_text(encoding="utf-8")
    family = socket.AF_INET6 if ":" in listen else socket.AF_INET
    server_class = type("SippControlServer", (ThreadingHTTPServer,), {"address_family": family})
    server = server_class((listen, port), ApiHandler)
    bound_port = server.server_address[1]
    server.RequestHandlerClass = type("SippControlHandler", (ApiHandler,), {
        "state": state,
        "hosts": allowed_hosts(listen, bound_port, extra_hosts),
        "token": token,
        "dashboard": html.encode("utf-8"),
        "csp": content_security_policy(html),
    })
    return server


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="HTTP API and Web UI for SIPp remote control")
    parser.add_argument("--sipp-host", default="127.0.0.1", help="SIPp control address (its -ci)")
    parser.add_argument("--sipp-port", type=int, default=8888, help="SIPp control port (its -cp)")
    parser.add_argument("--mode", choices=sorted(MODE_ACTIONS),
                        help="refuse actions SIPp ignores in this mode (users means SIPp runs with -users)")
    stats = parser.add_mutually_exclusive_group()
    stats.add_argument("--stat-file", type=Path, help="the -trace_stat file, <scenario>_<pid>_.csv")
    stats.add_argument("--stat-dir", type=Path, help="directory to search for the newest <scenario>_<pid>_.csv")
    parser.add_argument("--scenario", help="scenario name used with --stat-dir, e.g. uac for -sf uac.xml")
    parser.add_argument("--delimiter", default=";")
    parser.add_argument("--stale-after", type=float, default=120.0,
                        help="seconds without a stat file update before it is shown as stale "
                             "(keep above -fd, 60 by default)")
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9880)
    parser.add_argument("--allow-remote", action="store_true",
                        help="allow a non-loopback --listen; requires SIPP_CONTROL_TOKEN")
    parser.add_argument("--allow-host", action="append", default=[], metavar="NAME",
                        help="extra Host header name (without port) to accept, repeatable")
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not 1 <= args.sipp_port <= 65535 or not 1 <= args.port <= 65535:
        parser.error("ports must be between 1 and 65535")
    if len(args.delimiter) != 1:
        parser.error("delimiter must be exactly one character")
    if args.stat_dir is not None and not args.scenario:
        parser.error("--stat-dir requires --scenario")
    if args.stale_after <= 0:
        parser.error("--stale-after must be positive")
    token = os.environ.get("SIPP_CONTROL_TOKEN") or None
    if not is_loopback(args.listen):
        if not args.allow_remote:
            parser.error(f"refusing to listen on non-loopback {args.listen} without --allow-remote")
        if token is None:
            parser.error("--allow-remote requires a token in the SIPP_CONTROL_TOKEN environment variable")
    stats = StatReader(args.stat_file, args.stat_dir, args.scenario, args.delimiter, args.stale_after)
    state = ControlState((args.sipp_host, args.sipp_port), stats, args.mode)
    try:
        server = make_server(state, args.listen, args.port, token, args.allow_host)
    except OSError as exc:
        print(f"sipp_control: {exc}")
        return 2
    host, port = server.server_address[:2]
    print(f"sipp_control: listening on http://{format_endpoint((host, port))}/, "
          f"sending to SIPp at {format_endpoint((args.sipp_host, args.sipp_port))}", file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

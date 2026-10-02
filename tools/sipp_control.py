#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Small HTTP control plane for SIPp's UDP remote-control socket."""

from __future__ import annotations

import argparse
import csv
import json
import math
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Optional, Tuple


HOTKEYS = {"pause": "p", "quit": "q", "quit-now": "Q", "rate-up": "+", "rate-down": "-", "rate-up-10x": "*", "rate-down-10x": "/"}
COMMANDS = {"rate": "set rate {value}", "rate-scale": "set rate-scale {value}", "users": "set users {value}", "limit": "set limit {value}"}
DASHBOARD = Path(__file__).with_name("sipp_control.html")


def send_control(host: str, port: int, payload: str, timeout: float = 1.0) -> None:
    data = payload.encode("utf-8")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(data, (host, port))


def build_control(action: str, value: Optional[object] = None) -> str:
    if action in HOTKEYS:
        if value is not None:
            raise ValueError(f"{action} does not take a value")
        return HOTKEYS[action]
    template = COMMANDS.get(action)
    if template is None:
        raise ValueError(f"unsupported action {action!r}")
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise ValueError(f"{action} requires a finite numeric value")
    if action in {"users", "limit"} and int(value) != float(value):
        raise ValueError(f"{action} requires an integer value")
    text = str(int(value)) if int(value) == float(value) else str(float(value))
    return "c" + template.format(value=text)


def read_stat(path: Optional[Path], delimiter: str = ";") -> Dict[str, object]:
    if path is None:
        return {}
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            rows = [row for row in csv.reader(handle, delimiter=delimiter) if any(v.strip() for v in row)]
    except OSError as exc:
        return {"stat_error": str(exc)}
    if len(rows) < 2 or len(rows[-1]) < len(rows[0]):
        return {"stat_error": "no complete statistics row"}
    result: Dict[str, object] = {}
    for name, raw in zip(rows[0], rows[-1]):
        raw = raw.strip()
        try:
            number = float(raw)
            result[name.strip()] = number if math.isfinite(number) else raw
        except ValueError:
            result[name.strip()] = raw
    return result


class ControlState:
    def __init__(self, target: Tuple[str, int], stat_file: Optional[Path], delimiter: str) -> None:
        self.target = target
        self.stat_file = stat_file
        self.delimiter = delimiter
        self.started_at = time.time()
        self.last_action: Optional[dict] = None

    def status(self) -> dict:
        return {
            "target": {"host": self.target[0], "port": self.target[1]},
            "uptime_seconds": time.time() - self.started_at,
            "last_action": self.last_action,
            "statistics": read_stat(self.stat_file, self.delimiter),
        }

    def control(self, action: str, value: Optional[object]) -> dict:
        payload = build_control(action, value)
        send_control(self.target[0], self.target[1], payload)
        self.last_action = {"action": action, "value": value, "payload": payload, "at": time.time()}
        return self.last_action


class ApiHandler(BaseHTTPRequestHandler):
    state: ControlState

    def _write(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict) -> None:
        self._write(status, json.dumps(payload, sort_keys=True).encode("utf-8"), "application/json")

    def do_GET(self) -> None:
        if self.path == "/api/v1/status":
            self._json(200, self.state.status())
        elif self.path == "/healthz":
            self._json(200, {"status": "ok"})
        elif self.path in ("/", "/index.html"):
            try:
                body = DASHBOARD.read_bytes()
            except OSError as exc:
                self._json(500, {"error": f"cannot read dashboard: {exc}"})
                return
            self._write(200, body, "text/html; charset=utf-8")
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        if self.path != "/api/v1/control":
            self.send_error(404)
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
        except (ValueError, json.JSONDecodeError, OSError) as exc:
            self._json(400, {"error": str(exc)})
            return
        self._json(200, result)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def serve(state: ControlState, listen: str, port: int) -> None:
    handler = type("SippControlHandler", (ApiHandler,), {"state": state})
    ThreadingHTTPServer((listen, port), handler).serve_forever()


def main() -> int:
    parser = argparse.ArgumentParser(description="HTTP API and Web UI for SIPp remote control")
    parser.add_argument("--sipp-host", default="127.0.0.1")
    parser.add_argument("--sipp-port", type=int, default=8888)
    parser.add_argument("--stat-file", type=Path)
    parser.add_argument("--delimiter", default=";")
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9880)
    args = parser.parse_args()
    if not 1 <= args.sipp_port <= 65535 or not 1 <= args.port <= 65535:
        parser.error("ports must be between 1 and 65535")
    serve(ControlState((args.sipp_host, args.sipp_port), args.stat_file, args.delimiter), args.listen, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

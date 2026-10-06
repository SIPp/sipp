#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import http.client
import importlib.util
import io
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# sipp_control imports sipp_report from its own directory.
sys.path.insert(0, str(ROOT / "tools"))
spec = importlib.util.spec_from_file_location("sipp_control", ROOT / "tools" / "sipp_control.py")
control = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = control
spec.loader.exec_module(control)

# Columns and formats as SIPp writes them with -trace_stat, trailing delimiter included.
STAT_HEADER = (
    "StartTime;LastResetTime;CurrentTime;ElapsedTime(P);ElapsedTime(C);TargetRate;CallRate(P);CallRate(C);"
    "IncomingCall(P);IncomingCall(C);OutgoingCall(P);OutgoingCall(C);TotalCallCreated;CurrentCall;"
    "SuccessfulCall(P);SuccessfulCall(C);FailedCall(P);FailedCall(C);Retransmissions(P);Retransmissions(C);"
    "ResponseTime1(P);ResponseTime1(C);CallLength(P);CallLength(C);\n"
)
STAT_ROW = (
    "2026-10-02\t08:45:55.000000\t1791017155.000000;2026-10-02\t08:46:{s:02d}.000000\t1791017160.000000;"
    "2026-10-02\t08:46:{s:02d}.000000\t1791017160.000000;00:00:01:000000;00:00:{s:02d}:000000;"
    "{rate:.3f};9.990;10.000;0;0;10;{calls};{calls};2;10;{calls};0;0;0;1;"
    "00:00:00:012000;00:00:00:012500;00:00:01:000000;00:00:01:500000;\n"
)


def stat_row(seconds, rate, calls):
    return STAT_ROW.format(s=seconds, rate=rate, calls=calls)


class ControlTests(unittest.TestCase):
    def test_hotkeys(self):
        self.assertEqual(control.build_control("pause"), "p")
        self.assertEqual(control.build_control("quit-now"), "Q")
        self.assertEqual(control.build_control("step-up-10"), "*")

    def test_command_mode(self):
        self.assertEqual(control.build_control("rate", 250.5), "cset rate 250.5")
        self.assertEqual(control.build_control("users", 100), "cset users 100")
        self.assertEqual(control.build_control("rate-scale", 10), "cset rate-scale 10")

    def test_rejects_unsafe_or_invalid_actions(self):
        for action, value in [
            ("raw", "Q"),
            ("pause", 1),
            ("limit", 1.5),
            ("rate", float("inf")),
            ("rate", "10"),
            ("rate", True),
            ("rate", None),
            ("rate", -1),
            ("users", -1),
            ("limit", -1),
            ("users", 2**31),
            ("rate-scale", 0),
        ]:
            with self.subTest(action=action, value=value):
                with self.assertRaises(ValueError):
                    control.build_control(action, value)

    def test_huge_integer_is_a_value_error(self):
        # float(10**400) raises OverflowError, not ValueError
        with self.assertRaises(ValueError):
            control.build_control("rate", 10**400)

    def test_rate_is_capped(self):
        with self.assertRaises(ValueError):
            control.build_control("rate", 1e308)
        self.assertEqual(control.build_control("rate", control.INT_MAX), f"cset rate {control.INT_MAX}")

    def test_zero_is_valid(self):
        self.assertEqual(control.build_control("rate", 0), "cset rate 0")
        self.assertEqual(control.build_control("users", 0), "cset users 0")
        self.assertEqual(control.build_control("limit", 0), "cset limit 0")


class StatTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def reader(self, path=None, **kwargs):
        return control.StatReader(path, kwargs.get("stat_dir"), kwargs.get("scenario"), ";",
                                  kwargs.get("stale_after", 3600))

    def test_snapshot_keeps_useful_numeric_columns(self):
        path = self.dir / "uac_4242_.csv"
        path.write_text(STAT_HEADER + stat_row(5, 10, 40) + stat_row(6, 20, 50), encoding="utf-8")
        snapshot = self.reader(path).snapshot()
        values = snapshot["values"]
        self.assertEqual(values["TargetRate"], 20.0)
        self.assertEqual(values["SuccessfulCall(C)"], 50.0)
        self.assertEqual(values["ElapsedTime(C)"], 6.0)
        self.assertAlmostEqual(values["ResponseTime1(C)"], 0.0125)
        self.assertEqual(values["CallLength(C)"], 1.5)
        self.assertNotIn("StartTime", values)
        self.assertNotIn("IncomingCall(P)", values)
        self.assertEqual(snapshot["pid"], 4242)
        self.assertNotIn("error", snapshot)

    def test_partial_last_row_keeps_previous_values(self):
        path = self.dir / "uac_1_.csv"
        path.write_text(STAT_HEADER + stat_row(5, 10, 40), encoding="utf-8")
        reader = self.reader(path)
        self.assertEqual(reader.snapshot()["values"]["TargetRate"], 10.0)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(stat_row(6, 20, 50)[:60])
        snapshot = reader.snapshot()
        self.assertNotIn("error", snapshot)
        self.assertEqual(snapshot["values"]["TargetRate"], 10.0)

    def test_without_data_reports_error(self):
        path = self.dir / "uac_1_.csv"
        path.write_text(STAT_HEADER, encoding="utf-8")
        self.assertIn("error", self.reader(path).snapshot())

    def test_finds_newest_file_for_scenario(self):
        old = self.dir / "uac_100_.csv"
        new = self.dir / "uac_200_.csv"
        for path in (old, new, self.dir / "uac_200_rtt.csv", self.dir / "uas_300_.csv"):
            path.write_text(STAT_HEADER + stat_row(1, 1, 1), encoding="utf-8")
        os.utime(old, (1, 1))
        self.assertEqual(control.find_stat_file(self.dir, "uac"), new)
        self.assertIsNone(control.find_stat_file(self.dir, "nope"))

    def test_file_removed_after_listing_is_skipped(self):
        kept = self.dir / "uac_100_.csv"
        gone = self.dir / "uac_200_.csv"
        for path in (kept, gone):
            path.write_text(STAT_HEADER + stat_row(1, 1, 1), encoding="utf-8")
        real_stat = Path.stat

        def stat(path, *args, **kwargs):
            if path.name == gone.name:
                raise FileNotFoundError(path)
            return real_stat(path, *args, **kwargs)

        with unittest.mock.patch.object(Path, "stat", stat):
            self.assertEqual(control.find_stat_file(self.dir, "uac"), kept)

    def test_stale_when_not_updated_or_process_gone(self):
        path = self.dir / "uac_1_.csv"
        path.write_text(STAT_HEADER + stat_row(1, 1, 1), encoding="utf-8")
        os.utime(path, (1, 1))
        self.assertTrue(self.reader(path, stale_after=10).snapshot()["stale"])
        # A pid that cannot exist on Linux (above pid_max)
        dead = self.dir / "uac_99999999_.csv"
        dead.write_text(STAT_HEADER + stat_row(1, 1, 1), encoding="utf-8")
        snapshot = self.reader(dead).snapshot()
        self.assertFalse(snapshot["sipp_running"])
        self.assertTrue(snapshot["stale"])
        own = self.dir / f"uac_{os.getpid()}_.csv"
        own.write_text(STAT_HEADER + stat_row(1, 1, 1), encoding="utf-8")
        self.assertFalse(self.reader(own).snapshot()["stale"])


class UdpSink:
    """A local UDP socket standing in for SIPp's control socket."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(2)
        self.port = self.sock.getsockname()[1]

    def recv(self):
        return self.sock.recv(4096).decode("utf-8")

    def close(self):
        self.sock.close()


def closed_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class UdpTests(unittest.TestCase):
    def test_send_reaches_socket(self):
        sink = UdpSink()
        self.addCleanup(sink.close)
        control.send_control("127.0.0.1", sink.port, "cset rate 5")
        self.assertEqual(sink.recv(), "cset rate 5")

    def test_closed_port_is_reported(self):
        with self.assertRaises(OSError):
            control.send_control("127.0.0.1", closed_udp_port(), "p")


class UdpIpv6Tests(unittest.TestCase):
    def test_send_over_ipv6(self):
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sock.bind(("::1", 0))
        except OSError:
            self.skipTest("no IPv6 loopback")
        self.addCleanup(sock.close)
        sock.settimeout(2)
        control.send_control("::1", sock.getsockname()[1], "cset rate 5")
        self.assertEqual(sock.recv(4096), b"cset rate 5")


class HttpTests(unittest.TestCase):
    token = None
    mode = None

    def setUp(self):
        self.sink = UdpSink()
        self.addCleanup(self.sink.close)
        stats = control.StatReader(None, None, None, ";", 10)
        self.state = control.ControlState(("127.0.0.1", self.sink.port), stats, self.mode)
        self.server = control.make_server(self.state, "127.0.0.1", 0, self.token)
        self.port = self.server.server_address[1]
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        self.addCleanup(conn.close)
        all_headers = {"Host": f"127.0.0.1:{self.port}"}
        if body is not None:
            all_headers["Content-Type"] = "application/json"
            if not isinstance(body, bytes):
                body = json.dumps(body).encode("utf-8")
        all_headers.update(headers or {})
        conn.request(method, path, body=body, headers=all_headers)
        response = conn.getresponse()
        data = response.read()
        return response, data

    def post(self, body, **kwargs):
        response, data = self.request("POST", "/api/v1/control", body, **kwargs)
        return response.status, json.loads(data)

    def test_control_sends_datagram(self):
        status, result = self.post({"action": "rate", "value": 12.5})
        self.assertEqual(status, 200)
        self.assertEqual(result["payload"], "cset rate 12.5")
        self.assertEqual(self.sink.recv(), "cset rate 12.5")
        response, data = self.request("GET", "/api/v1/status")
        self.assertEqual(response.status, 200)
        status = json.loads(data)
        self.assertEqual(status["last_sent"]["payload"], "cset rate 12.5")
        self.assertEqual(status["statistics"], {"error": "no statistics file configured"})

    def test_bad_values_are_400(self):
        for body in [{"action": "rate", "value": ""}, {"action": "rate"}, {"action": "raw", "value": "Q"}]:
            with self.subTest(body=body):
                self.assertEqual(self.post(body)[0], 400)
        # A huge integer used to kill the handler thread without a response
        self.assertEqual(self.post(b'{"action": "rate", "value": 1' + b"0" * 400 + b"}")[0], 400)
        self.assertEqual(self.post(b"not json")[0], 400)

    def test_wrong_content_type_is_400(self):
        status, _ = self.post({"action": "pause"}, headers={"Content-Type": "text/plain"})
        self.assertEqual(status, 400)

    def test_short_body_times_out(self):
        # A body shorter than its Content-Length used to hold a thread and socket forever
        self.assertIsNotNone(self.server.RequestHandlerClass.timeout)
        self.server.RequestHandlerClass.timeout = 0.2
        head = (f"POST /api/v1/control HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\n"
                "Content-Type: application/json\r\nContent-Length: 100\r\n")
        if self.token is not None:
            head += f"Authorization: Bearer {self.token}\r\n"
        data = b""
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            sock.sendall(head.encode("ascii") + b'\r\n{"a"')
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except socket.timeout:
                self.fail("server kept the connection open")
        self.assertTrue(data.startswith(b"HTTP/1.0 408 "), data)
        self.assertEqual(self.request("GET", "/healthz")[0].status, 200)

    def test_send_failure_is_502(self):
        self.state.target = ("127.0.0.1", closed_udp_port())
        self.assertEqual(self.post({"action": "pause"})[0], 502)

    def test_second_quit_is_refused(self):
        self.assertEqual(self.post({"action": "quit"})[0], 200)
        self.assertEqual(self.post({"action": "quit"})[0], 409)
        self.assertEqual(self.sink.recv(), "q")

    def test_pause_toggles_are_counted(self):
        self.post({"action": "pause"})
        self.post({"action": "pause"})
        _, data = self.request("GET", "/api/v1/status")
        self.assertEqual(json.loads(data)["pause_toggles_sent"], 2)

    def test_host_header_is_checked(self):
        for host in ["localhost", "[::1]"]:
            response, _ = self.request("GET", "/healthz", headers={"Host": f"{host}:{self.port}"})
            self.assertEqual(response.status, 200)
        for host in ["evil.example:%d" % self.port, "127.0.0.1", "127.0.0.1:1"]:
            with self.subTest(host=host):
                response, _ = self.request("GET", "/api/v1/status", headers={"Host": host})
                self.assertEqual(response.status, 403)
        status, _ = self.post({"action": "pause"}, headers={"Origin": "http://evil.example"})
        self.assertEqual(status, 403)
        status, _ = self.post({"action": "pause"}, headers={"Origin": f"http://localhost:{self.port}"})
        self.assertEqual(status, 200)

    def test_dashboard_headers(self):
        response, body = self.request("GET", "/")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader("X-Frame-Options"), "DENY")
        csp = response.getheader("Content-Security-Policy")
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertNotIn("unsafe-inline", csp)
        for source in control.inline_hashes(body.decode("utf-8"))["script"]:
            self.assertIn(source, csp)
        self.assertNotIn(b"onclick", body)

    def test_unknown_path_is_404(self):
        self.assertEqual(self.request("GET", "/nope")[0].status, 404)
        self.assertEqual(self.request("POST", "/nope", {"action": "pause"})[0].status, 404)


class HttpUsersModeTests(HttpTests):
    mode = "users"

    def test_rate_is_refused_in_users_mode(self):
        self.assertEqual(self.post({"action": "rate", "value": 5})[0], 409)
        self.assertEqual(self.post({"action": "users", "value": 5})[0], 200)

    def test_control_sends_datagram(self):
        status, result = self.post({"action": "users", "value": 3})
        self.assertEqual(status, 200)
        self.assertEqual(self.sink.recv(), "cset users 3")


class HttpTokenTests(HttpTests):
    token = "s3cret"

    def request(self, method, path, body=None, headers=None):
        all_headers = {"Authorization": "Bearer s3cret"}
        all_headers.update(headers or {})
        return super().request(method, path, body, all_headers)

    def test_missing_or_wrong_token_is_401(self):
        for value in ["", "Bearer nope"]:
            with self.subTest(value=value):
                response, _ = self.request("GET", "/api/v1/status", headers={"Authorization": value})
                self.assertEqual(response.status, 401)


class MainTests(unittest.TestCase):
    def test_refuses_remote_listen_without_opt_in_and_token(self):
        env = dict(os.environ)
        env.pop("SIPP_CONTROL_TOKEN", None)
        for argv in (["--listen", "0.0.0.0"], ["--listen", "0.0.0.0", "--allow-remote"]):
            with self.subTest(argv=argv):
                with unittest.mock.patch.dict(os.environ, env, clear=True):
                    with self.assertRaises(SystemExit) as caught, \
                            unittest.mock.patch("sys.stderr"):
                        control.main(argv)
                    self.assertEqual(caught.exception.code, 2)

    def test_startup_says_where_the_dashboard_is(self):
        server = unittest.mock.MagicMock()
        server.server_address = ("127.0.0.1", 9880)
        server.serve_forever.side_effect = KeyboardInterrupt
        with unittest.mock.patch.object(control, "make_server", return_value=server), \
                unittest.mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            self.assertEqual(control.main([]), 0)
        self.assertIn("listening on http://127.0.0.1:9880/", err.getvalue())
        self.assertIn("SIPp at 127.0.0.1:8888", err.getvalue())

    def test_remote_hosts_include_listen_address(self):
        hosts = control.allowed_hosts("192.0.2.1", 9880, ["sipp.example"])
        self.assertIn("192.0.2.1:9880", hosts)
        self.assertIn("sipp.example:9880", hosts)
        self.assertIn("localhost:9880", hosts)


if __name__ == "__main__":
    unittest.main()

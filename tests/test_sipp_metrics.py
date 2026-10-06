#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import contextlib
import http.server
import importlib.util
import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
# A -trace_stat file written by "sipp -sn uac -m 5 -r 5 -trace_stat -fd 1"
# against "sipp -sn uas" on the loopback interface.
FIXTURE = ROOT / "tests" / "data" / "uac_trace_stat.txt"
FIXTURE_ROW_TIME = 1791138153.989577
FIXTURE_START_TIME = 1791138152.979043


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


load("sipp_endpoint", ROOT / "tools" / "sipp_endpoint.py")
load("sipp_report", ROOT / "tools" / "sipp_report.py")
metrics = load("sipp_metrics", ROOT / "tools" / "sipp_metrics.py")
otlp = load("sipp_otlp", ROOT / "tools" / "sipp_otlp.py")


def fixture_lines():
    return FIXTURE.read_text(encoding="utf-8").splitlines()


def write_stat(path: Path, rows: int = 4) -> Path:
    lines = fixture_lines()
    path.write_text("\n".join(lines[:1 + rows]) + "\n", encoding="utf-8")
    return path


def store_at(reader, now: float, stale_after: float = 120.0):
    return metrics.SnapshotStore(reader, stale_after, clock=lambda: now)


@contextlib.contextmanager
def serving(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def get(url: str):
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status, response.headers.get("Content-Type"), response.read().decode()
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, exc.headers.get("Content-Type"), exc.read().decode()


class ReaderTests(unittest.TestCase):
    def test_real_row_with_time_columns(self):
        snap = metrics.StatFileReader(FIXTURE).read()
        self.assertEqual(snap.values["SuccessfulCall(C)"], 5.0)
        self.assertEqual(snap.values["ElapsedTime(C)"], 1.0)
        self.assertAlmostEqual(snap.values["ResponseTime1(C)"], 0.002)
        self.assertAlmostEqual(snap.values["CallLength(C)"], 0.007)
        self.assertEqual(snap.values["ResponseTimeRepartition1_<10(C)"], 5.0)
        self.assertNotIn("CurrentTime", snap.values)
        self.assertAlmostEqual(snap.row_time, FIXTURE_ROW_TIME)
        self.assertAlmostEqual(snap.start_time, FIXTURE_START_TIME)

    def test_partial_last_row_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_stat(Path(tmp) / "uac_1_.csv", rows=3)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(fixture_lines()[4][:200])
            snap = metrics.StatFileReader(path).read()
            self.assertAlmostEqual(snap.row_time, 1791138153.989152)

    def test_header_only_and_missing_file_raise_runtime_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            header_only = write_stat(Path(tmp) / "uac_1_.csv", rows=0)
            with self.assertRaisesRegex(RuntimeError, "no complete statistics row"):
                metrics.StatFileReader(header_only).read()
            with self.assertRaisesRegex(RuntimeError, "cannot read"):
                metrics.StatFileReader(Path(tmp) / "missing_1_.csv").read()

    def test_file_without_current_time_uses_mtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "run_1_.csv"
            path.write_text("SuccessfulCall(C)\n3\n", encoding="utf-8")
            os.utime(path, (1000, 1000))
            snap = metrics.StatFileReader(path).read()
            self.assertEqual(snap.row_time, 1000)
            self.assertIsNone(snap.start_time)


class DiscoveryTests(unittest.TestCase):
    def test_only_the_stat_file_is_selected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stat = write_stat(root / "uac_1234_.csv")
            others = [root / name for name in (
                "uac_1234_counts.csv", "uac_1234_error_codes.csv", "uac_1234_rtt.csv",
                "users.csv", "users_42_.csv")]
            for other in others:
                other.write_text("CurrentTime;ElapsedTime\nx;1\n", encoding="utf-8")
            now = time.time()
            os.utime(stat, (now - 10, now - 10))
            for other in others:
                os.utime(other, (now, now))
            self.assertEqual(metrics.find_latest_stat_file(root), stat)

    def test_no_stat_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "uac_1234_counts.csv").write_text("CurrentTime\n1\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "no SIPp -trace_stat file"):
                metrics.find_latest_stat_file(Path(tmp))

    def test_file_removed_after_listing_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            older = write_stat(root / "uac_100_.csv")
            newer = write_stat(root / "uac_200_.csv")
            now = time.time()
            os.utime(older, (now - 10, now - 10))
            os.utime(newer, (now, now))
            removed = {newer.name}
            real_stat = Path.stat

            def stat(path, *args, **kwargs):
                # The file is listed, then removed before it is stat()ed.
                if path.name in removed:
                    raise FileNotFoundError(2, "No such file or directory", str(path))
                return real_stat(path, *args, **kwargs)

            with mock.patch.object(Path, "stat", stat):
                self.assertEqual(metrics.find_latest_stat_file(root), older)
                removed.add(older.name)
                with self.assertRaisesRegex(RuntimeError, "no SIPp -trace_stat file"):
                    metrics.find_latest_stat_file(root)

    def test_restart_is_picked_up_and_scenario_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = write_stat(root / "uac_100_.csv", rows=2)
            uas = write_stat(root / "uas_99_.csv", rows=4)
            now = time.time()
            os.utime(first, (now - 20, now - 20))
            os.utime(uas, (now - 5, now - 5))
            reader = metrics.StatFileReader(None, directory=root, scenario="uac")
            self.assertEqual(reader.read().source, str(first))
            second = write_stat(root / "uac_200_.csv", rows=4)
            os.utime(second, (now, now))
            snap = reader.read()
            self.assertEqual(snap.source, str(second))
            self.assertAlmostEqual(snap.row_time, FIXTURE_ROW_TIME)


class PrometheusTests(unittest.TestCase):
    def test_names(self):
        self.assertEqual(metrics.metric_name("SuccessfulCall(C)"), "sipp_successfulcall_c")
        self.assertEqual(metrics.metric_name("1xx response"), "sipp_field_1xx_response")
        self.assertEqual(metrics.describe_column("SuccessfulCall(C)"), ("sipp_successfulcall", True, False))
        self.assertEqual(metrics.describe_column("SuccessfulCall(P)"), ("sipp_successfulcall_period", False, False))
        self.assertEqual(metrics.describe_column("ElapsedTime(C)"), ("sipp_elapsedtime_seconds", True, True))
        self.assertEqual(metrics.describe_column("ResponseTime1(C)"), ("sipp_responsetime1_seconds", False, True))
        self.assertEqual(metrics.describe_column("CallRate(C)"), ("sipp_callrate", False, False))
        self.assertEqual(metrics.describe_column("TotalCallCreated"), ("sipp_totalcallcreated", True, False))
        self.assertEqual(metrics.describe_column("CallLengthRepartition_>=10000(C)"),
                         ("sipp_calllengthrepartition_ge_10000", True, False))

    def test_counters_gauges_and_age(self):
        snap = metrics.StatFileReader(FIXTURE).read()
        text = metrics.render_prometheus(snap, FIXTURE_ROW_TIME + 3, False)
        self.assertIn("sipp_exporter_up 1\n", text)
        self.assertIn("sipp_stat_row_age_seconds 3.000000\n", text)
        self.assertIn("# TYPE sipp_successfulcall_total counter\nsipp_successfulcall_total 5.0\n", text)
        self.assertIn("# TYPE sipp_successfulcall_period gauge\n", text)
        self.assertIn("# TYPE sipp_elapsedtime_seconds_total counter\nsipp_elapsedtime_seconds_total 1.0\n", text)
        self.assertIn("# TYPE sipp_responsetime1_seconds gauge\nsipp_responsetime1_seconds 0.002\n", text)
        self.assertIn("# TYPE sipp_currentcall gauge\n", text)
        self.assertIn("sipp_responsetimerepartition1_lt_10_total 5.0\n", text)
        names = [line.split()[2] for line in text.splitlines() if line.startswith("# TYPE")]
        self.assertEqual(len(names), len(set(names)))

    def test_stale_row_is_not_served_as_live(self):
        reader = metrics.StatFileReader(FIXTURE)
        text = store_at(reader, FIXTURE_ROW_TIME + 600).render_prometheus()
        self.assertIn("sipp_exporter_up 0\n", text)
        self.assertIn("sipp_stat_row_age_seconds 600.000000\n", text)
        self.assertNotIn("sipp_successfulcall", text)
        self.assertIn("sipp_successfulcall_total", store_at(reader, FIXTURE_ROW_TIME + 600, 0).render_prometheus())

    def test_unreadable_file(self):
        store = store_at(metrics.StatFileReader(Path("/nonexistent/uac_1_.csv")), 0)
        self.assertEqual(store.render_prometheus().splitlines()[-1], "sipp_exporter_up 0")
        self.assertIn("cannot read", json.loads(store.render_json())["error"])
        self.assertFalse(store.healthy())

    def test_os_error_while_searching_is_reported(self):
        store = store_at(metrics.StatFileReader(None, directory=Path("/var/tmp/sipp")), 0)
        error = PermissionError(13, "Permission denied", "/var/tmp/sipp")
        with mock.patch.object(metrics, "find_latest_stat_file", side_effect=error):
            self.assertEqual(store.render_prometheus().splitlines()[-1], "sipp_exporter_up 0")
            self.assertIn("Permission denied", json.loads(store.render_json())["error"])
            self.assertFalse(store.healthy())


class HttpTests(unittest.TestCase):
    def test_endpoints(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_stat(Path(tmp) / "uac_1_.csv")
            clock = [FIXTURE_ROW_TIME + 1]
            store = metrics.SnapshotStore(metrics.StatFileReader(path), 120, clock=lambda: clock[0])
            with serving(metrics.make_server(store, "127.0.0.1", 0)) as base:
                status, ctype, body = get(base + "/metrics")
                self.assertEqual(status, 200)
                self.assertTrue(ctype.startswith("text/plain; version=0.0.4"))
                self.assertIn("sipp_successfulcall_total 5.0", body)

                status, ctype, body = get(base + "/v1/metrics")
                self.assertEqual((status, ctype), (200, "application/json"))
                payload = json.loads(body)
                self.assertFalse(payload["stale"])
                self.assertAlmostEqual(payload["metrics"]["ResponseTime1(C)"], 0.002)

                self.assertEqual(get(base + "/healthz")[0], 200)
                self.assertEqual(get(base + "/nope")[0], 404)

                clock[0] += 600
                self.assertEqual(get(base + "/healthz")[0], 503)
                self.assertTrue(json.loads(get(base + "/v1/metrics")[2])["stale"])

                path.unlink()
                self.assertEqual(get(base + "/healthz")[0], 503)
                self.assertIn("sipp_exporter_up 0", get(base + "/metrics")[2])

    def test_serve_says_where_it_listens(self):
        server = mock.MagicMock()
        server.server_address = ("127.0.0.1", 9100)
        server.serve_forever.side_effect = KeyboardInterrupt
        err = io.StringIO()
        with mock.patch.object(metrics, "make_server", return_value=server), contextlib.redirect_stderr(err):
            self.assertEqual(metrics.main(["--stat-file", str(FIXTURE), "--serve"]), 0)
        self.assertIn("listening on http://127.0.0.1:9100/metrics", err.getvalue())
        server.server_close.assert_called_once()

    def test_main_prints_one_snapshot(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = metrics.main(["--stat-file", str(FIXTURE), "--stale-after", "0"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())["metrics"]["SuccessfulCall(C)"], 5.0)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(metrics.main(["--stat-file", str(FIXTURE)]), 1)


class Collector(http.server.BaseHTTPRequestHandler):
    requests = []
    status = 200

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        type(self).requests.append((self.path, dict(self.headers), json.loads(body)))
        self.send_response(type(self).status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):
        return


class Redirector(http.server.BaseHTTPRequestHandler):
    location = ""

    def do_POST(self):
        self.send_response(302)
        self.send_header("Location", type(self).location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):
        return


class OtlpTests(unittest.TestCase):
    def test_redirect_is_not_followed(self):
        Collector.requests = []
        Collector.status = 200
        target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Collector)
        redirector = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Redirector)
        with serving(target) as target_base, serving(redirector) as base:
            Redirector.location = target_base + "/v1/metrics"
            with self.assertRaisesRegex(RuntimeError, "HTTP 302"):
                otlp.push(base + "/v1/metrics", {}, 2, {"Authorization": "Bearer secret"})
        self.assertEqual(Collector.requests, [])


    def test_counters_are_cumulative_sums_at_the_row_time(self):
        payload = otlp.build_otlp(metrics.StatFileReader(FIXTURE).read(), "loadtest")
        found = {m["name"]: m for m in payload["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]}
        total = found["sipp_successfulcall"]["sum"]
        self.assertTrue(total["isMonotonic"])
        self.assertEqual(total["aggregationTemporality"], 2)
        point = total["dataPoints"][0]
        self.assertEqual(point["asDouble"], 5.0)
        self.assertEqual(point["timeUnixNano"], str(int(FIXTURE_ROW_TIME * 1e9)))
        self.assertEqual(point["startTimeUnixNano"], str(int(FIXTURE_START_TIME * 1e9)))
        latency = found["sipp_responsetime1_seconds"]
        self.assertEqual(latency["unit"], "s")
        self.assertAlmostEqual(latency["gauge"]["dataPoints"][0]["asDouble"], 0.002)

    def test_header_validation(self):
        self.assertEqual(otlp.parse_headers(["Authorization=Bearer token"]),
                         {"Authorization": "Bearer token"})
        for bad in ("=value", "novalue", "X-Test=value\nInjected: true", "Bad Name=1", "Bad:Name=1"):
            with self.assertRaises(ValueError):
                otlp.parse_headers([bad])
        self.assertEqual(otlp.parse_env_headers("a=1,Authorization=Basic%20abc%3D"),
                         {"a": "1", "Authorization": "Basic abc="})

    def test_push_to_local_collector(self):
        Collector.requests = []
        Collector.status = 200
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Collector)
        with tempfile.TemporaryDirectory() as tmp, serving(server) as base:
            header_file = Path(tmp) / "headers"
            header_file.write_text("# secret\nAuthorization=Bearer from-file\n\nX-Scope=a\n", encoding="utf-8")
            argv = ["--stat-file", str(FIXTURE), "--stale-after", "0", "--once",
                    "--endpoint", base + "/v1/metrics", "--header-file", str(header_file),
                    "--header", "X-Scope=b"]
            with mock.patch.dict(os.environ, {otlp.HEADERS_ENV: "X-Env=1,Authorization=from-env"}):
                self.assertEqual(otlp.main(argv), 0)
        path, headers, payload = Collector.requests[0]
        self.assertEqual(path, "/v1/metrics")
        self.assertEqual(headers["Authorization"], "Bearer from-file")
        self.assertEqual((headers["X-Scope"], headers["X-Env"]), ("b", "1"))
        names = [m["name"] for m in payload["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]]
        self.assertIn("sipp_successfulcall", names)

    def test_exporter_survives_missing_stale_and_refused(self):
        Collector.requests = []
        Collector.status = 500
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Collector)
        with tempfile.TemporaryDirectory() as tmp, serving(server) as base:
            path = Path(tmp) / "uac_1_.csv"
            clock = [FIXTURE_ROW_TIME + 1]
            store = metrics.SnapshotStore(metrics.StatFileReader(path), 120, clock=lambda: clock[0])
            exporter = otlp.OtlpExporter(store, base + "/v1/metrics", 5, {}, "sipp")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertFalse(exporter.run_once())
                self.assertFalse(exporter.run_once())
                write_stat(path)
                self.assertFalse(exporter.run_once())
                Collector.status = 200
                self.assertTrue(exporter.run_once())
                self.assertTrue(exporter.run_once())
                clock[0] += 600
                self.assertFalse(exporter.run_once())
            self.assertEqual(len(Collector.requests), 2)
            lines = out.getvalue().splitlines()
            self.assertEqual(len(lines), 3)
            self.assertIn("cannot read", lines[0])
            self.assertIn("500", lines[1])
            self.assertIn("not exported", lines[2])

    def test_exporter_survives_os_error_while_reading(self):
        Collector.requests = []
        Collector.status = 200
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Collector)
        with tempfile.TemporaryDirectory() as tmp, serving(server) as base:
            write_stat(Path(tmp) / "uac_1_.csv")
            store = store_at(metrics.StatFileReader(None, directory=Path(tmp)), FIXTURE_ROW_TIME + 1)
            exporter = otlp.OtlpExporter(store, base + "/v1/metrics", 5, {}, "sipp")
            error = FileNotFoundError(2, "No such file or directory", tmp)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                with mock.patch.object(metrics, "find_latest_stat_file", side_effect=error):
                    self.assertFalse(exporter.run_once())
                self.assertTrue(exporter.run_once())
        self.assertEqual(len(Collector.requests), 1)
        self.assertIn("No such file or directory", out.getvalue())

    def test_bad_arguments_exit_with_usage_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = str(Path(tmp) / "missing")
            for argv in (["--header", "Bad Name=1"], ["--header-file", missing], ["--endpoint", "file:///x"]):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                    otlp.main(["--once"] + argv)
                self.assertEqual(raised.exception.code, 2)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(otlp.main(["--once", "--stat-dir", tmp]), 1)


if __name__ == "__main__":
    unittest.main()

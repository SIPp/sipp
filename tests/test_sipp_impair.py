#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import importlib.util
import socket
import sys
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
spec = importlib.util.spec_from_file_location("sipp_impair", ROOT / "tools" / "sipp_impair.py")
impair = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = impair
spec.loader.exec_module(impair)


class FakeSocket:
    def __init__(self):
        self.sent = []

    def sendto(self, data, target):
        self.sent.append((data, target))
        return len(data)


class FailingSocket:
    def sendto(self, data, target):
        raise OSError("network unreachable")


TARGET = ("127.0.0.1", 9000)
UP = impair.TO_UPSTREAM
DOWN = impair.TO_CLIENT


class ImpairmentTests(unittest.TestCase):
    def test_fixed_delay(self):
        sock = FakeSocket()
        engine = impair.ImpairmentEngine(impair.Profile(delay_ms=100), seed=1)
        engine.submit(UP, sock, TARGET, b"x", 1.0)
        engine.flush(1.099)
        self.assertEqual(sock.sent, [])
        engine.flush(1.101)
        self.assertEqual(len(sock.sent), 1)

    def test_full_loss(self):
        sock = FakeSocket()
        engine = impair.ImpairmentEngine(impair.Profile(loss_percent=100), seed=1)
        engine.submit(UP, sock, TARGET, b"x", 1.0)
        engine.flush(2.0)
        self.assertEqual(sock.sent, [])
        self.assertEqual(engine.directions[UP].counters.dropped, 1)

    def test_duplication(self):
        sock = FakeSocket()
        engine = impair.ImpairmentEngine(impair.Profile(duplicate_percent=100), seed=1)
        engine.submit(UP, sock, TARGET, b"x", 1.0)
        engine.flush(2.0)
        self.assertEqual(len(sock.sent), 2)
        self.assertEqual(engine.directions[UP].counters.duplicated, 1)

    def test_reordering_inverts_adjacent_packets(self):
        sock = FakeSocket()
        profile = impair.Profile(reorder_percent=100, reorder_delay_ms=40)
        engine = impair.ImpairmentEngine(profile, seed=1)
        engine.submit(UP, sock, TARGET, b"first", 1.000)
        engine.submit(UP, sock, TARGET, b"second", 1.010)
        engine.flush(2.0)
        self.assertEqual([data for data, _ in sock.sent], [b"second", b"first"])
        self.assertEqual(engine.directions[UP].counters.reordered, 1)

    def test_reordering_is_adjacent_at_20ms_spacing(self):
        sock = FakeSocket()
        profile = impair.Profile(reorder_percent=100, reorder_delay_ms=40)
        engine = impair.ImpairmentEngine(profile, seed=1)
        for i in range(6):
            now = 1.0 + i * 0.020
            engine.flush(now)
            engine.submit(UP, sock, TARGET, bytes([i]), now)
        engine.flush(2.0)
        self.assertEqual([data[0] for data, _ in sock.sent], [1, 0, 3, 2, 5, 4])

    def test_reorder_slot_is_per_direction(self):
        up, down = FakeSocket(), FakeSocket()
        profile = impair.Profile(reorder_percent=100, reorder_delay_ms=40)
        engine = impair.ImpairmentEngine(profile, seed=1)
        for i in range(4):
            now = 1.0 + i * 0.005
            engine.submit(UP, up, TARGET, bytes([i]), now)
            engine.submit(DOWN, down, TARGET, bytes([100 + i]), now)
        engine.flush(2.0)
        self.assertEqual([data[0] for data, _ in up.sent], [1, 0, 3, 2])
        self.assertEqual([data[0] for data, _ in down.sent], [101, 100, 103, 102])
        self.assertEqual(engine.directions[UP].counters.reordered, 2)
        self.assertEqual(engine.directions[DOWN].counters.reordered, 2)

    def test_burst_state_is_per_direction(self):
        sock = FakeSocket()
        profile = impair.Profile(burst_start_percent=100, burst_length=3)
        engine = impair.ImpairmentEngine(profile, seed=1)
        engine.submit(UP, sock, TARGET, b"a", 1.0)
        self.assertEqual(engine.directions[DOWN].burst_remaining, 0)
        self.assertEqual(engine.directions[UP].burst_remaining, 2)

    def test_reorder_hold_expires_without_losing_packet(self):
        sock = FakeSocket()
        profile = impair.Profile(reorder_percent=100, reorder_delay_ms=40)
        engine = impair.ImpairmentEngine(profile, seed=1)
        engine.submit(UP, sock, TARGET, b"only", 1.0)
        engine.flush(1.039)
        self.assertEqual(sock.sent, [])
        engine.flush(1.041)
        self.assertEqual([data for data, _ in sock.sent], [b"only"])
        self.assertEqual(engine.directions[UP].counters.reordered, 0)

    def test_burst_loss(self):
        sock = FakeSocket()
        profile = impair.Profile(burst_start_percent=100, burst_length=3)
        engine = impair.ImpairmentEngine(profile, seed=1)
        for i in range(3):
            engine.submit(UP, sock, TARGET, bytes([i]), 1.0)
        self.assertEqual(engine.directions[UP].counters.burst_dropped, 3)
        self.assertEqual(len(engine.queue), 0)

    def test_profile_validation(self):
        with self.assertRaises(ValueError):
            impair.Profile(loss_percent=101).validate()
        with self.assertRaises(ValueError):
            impair.Profile(jitter_ms=-1).validate()
        with self.assertRaises(ValueError):
            impair.Profile(reorder_percent=1, reorder_delay_ms=0).validate()
        for value in (float("nan"), float("inf")):
            for name in ("delay_ms", "jitter_ms", "reorder_delay_ms"):
                with self.assertRaises(ValueError):
                    impair.Profile(**{name: value}).validate()
        with self.assertRaises(ValueError):
            impair.Profile(loss_percent=float("nan")).validate()

    def test_send_error_is_counted_not_raised(self):
        engine = impair.ImpairmentEngine(impair.Profile(), seed=1)
        engine.submit(UP, FailingSocket(), TARGET, b"x", 1.0)
        engine.flush(2.0)
        counters = engine.directions[UP].counters
        self.assertEqual((counters.forwarded, counters.send_errors), (0, 1))

    def test_queue_is_bounded(self):
        sock = FakeSocket()
        engine = impair.ImpairmentEngine(impair.Profile(delay_ms=100), seed=1, max_queue=2)
        for i in range(5):
            engine.submit(UP, sock, TARGET, bytes([i]), 1.0)
        self.assertEqual(len(engine.queue), 2)
        self.assertEqual(engine.directions[UP].counters.overflow, 3)
        with self.assertRaises(ValueError):
            impair.ImpairmentEngine(impair.Profile(), max_queue=0)

    def test_counters_balance_when_copies_overflow(self):
        sock = FakeSocket()
        engine = impair.ImpairmentEngine(impair.Profile(duplicate_percent=100), seed=1, max_queue=1)
        for i in range(20):
            engine.submit(UP, sock, TARGET, b"x", 1.0 + i / 1000)
        engine.flush(2.0)
        c = engine.directions[UP].counters
        self.assertEqual(len(sock.sent), 1)
        self.assertEqual((c.received, c.duplicated, c.forwarded, c.overflow), (20, 20, 1, 39))
        self.assertEqual(c.received + c.duplicated, c.dropped + c.forwarded + c.overflow + c.send_errors)

    def test_seed_repeats_per_direction_regardless_of_interleaving(self):
        profile = impair.Profile(loss_percent=30, duplicate_percent=10, reorder_percent=10,
                                 burst_start_percent=5, burst_length=3)

        def run(order):
            sockets = {UP: FakeSocket(), DOWN: FakeSocket()}
            engine = impair.ImpairmentEngine(profile, seed=42)
            for index, (name, i) in enumerate(order):
                now = 1.0 + index * 0.001
                engine.flush(now)
                engine.submit(name, sockets[name], TARGET, i.to_bytes(2, "big"), now)
            engine.flush(10.0)
            return {name: [data for data, _ in sock.sent] for name, sock in sockets.items()}

        separate = [(UP, i) for i in range(200)] + [(DOWN, i) for i in range(200)]
        interleaved = [(name, i) for i in range(200) for name in (DOWN, UP)]
        first = run(separate)
        self.assertEqual(first, run(separate))
        self.assertEqual(first, run(interleaved))
        self.assertNotEqual(first[UP], first[DOWN])
        self.assertLess(len(first[UP]), 200)

    def test_seed_decisions_do_not_depend_on_timing(self):
        profile = impair.Profile(loss_percent=30, delay_ms=20, jitter_ms=10, duplicate_percent=20,
                                 reorder_percent=30, reorder_delay_ms=40)
        count = 60

        def run(spacing):
            sockets = {UP: FakeSocket(), DOWN: FakeSocket()}
            held = {UP: [], DOWN: []}
            delays = {UP: {}, DOWN: {}}
            engine = impair.ImpairmentEngine(profile, seed=3)
            now = 1.0
            for i in range(count):
                now += spacing(i)
                engine.flush(now)
                for name, sock in sockets.items():
                    data = bytes([i])
                    engine.submit(name, sock, TARGET, data, now)
                    direction = engine.directions[name]
                    if direction.held is not None and direction.held.data == data:
                        held[name].append(i)
                    dues = [p.due for p in engine.queue if p.sock is sock and p.data == data]
                    if dues:
                        delays[name][i] = round(min(dues) - now, 6)
            engine.flush(now + 1.0)
            decisions = {}
            for name, sock in sockets.items():
                sent = [data[0] for data, _ in sock.sent]
                decisions[name] = {
                    "dropped": [i for i in range(count) if i not in sent],
                    "duplicated": [i for i in range(count) if sent.count(i) > 1],
                    "held": held[name],
                    "delays": delays[name],
                }
            return decisions, engine

        # At 1 ms every held packet is swapped with its successor; at 100 ms
        # every one is sent on its deadline before the next packet arrives.
        fast, fast_engine = run(lambda i: 0.001)
        slow, slow_engine = run(lambda i: 0.100)
        for name in (UP, DOWN):
            self.assertTrue(all(fast[name][key] for key in ("dropped", "duplicated", "held")))
            self.assertGreater(fast_engine.directions[name].counters.reordered, 0)
            self.assertEqual(slow_engine.directions[name].counters.reordered, 0)
        self.assertNotEqual(fast[UP], fast[DOWN])
        self.assertEqual(slow, fast)
        self.assertEqual(run(lambda i: 0.010)[0], fast)
        self.assertEqual(run(lambda i: 0.150 if i % 3 == 0 else 0.005)[0], fast)

    def test_report_lists_both_directions(self):
        engine = impair.ImpairmentEngine(impair.Profile(), seed=1)
        engine.submit(UP, FakeSocket(), TARGET, b"x", 1.0)
        report = engine.report().splitlines()
        self.assertEqual(len(report), 2)
        self.assertIn("client->upstream received=1", report[0])
        self.assertIn("upstream->client received=0", report[1])

    def test_endpoint_parser_accepts_ipv4_and_bracketed_ipv6(self):
        self.assertEqual(impair.parse_endpoint("127.0.0.1:9000"), ("127.0.0.1", 9000))
        self.assertEqual(impair.parse_endpoint("[2001:db8::1]:9000"), ("2001:db8::1", 9000))

    def test_endpoint_parser_rejects_unbracketed_ipv6(self):
        with self.assertRaises(impair.argparse.ArgumentTypeError):
            impair.parse_endpoint("::1:3478")


def _ipv6_available():
    if not socket.has_ipv6:
        return False
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.bind(("::1", 0))
    except OSError:
        return False
    return True


def _dual_stack_available():
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.bind(("::", 0))
            return not sock.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY)
    except (AttributeError, OSError):
        return False


class ProxySocketTests(unittest.TestCase):
    TIMEOUT = 2.0

    def start(self, host="127.0.0.1", family=socket.AF_INET, profile=None, seed=1, client=None,
              listen=None):
        self.family = family
        self.host = host
        self.peer = self.udp(host)
        upstream = self.peer.getsockname()[:2]
        engine = impair.ImpairmentEngine(profile or impair.Profile(), seed=seed)
        self.proxy = impair.Proxy((listen or host, 0), upstream, engine, client)
        self.listen_addr = self.proxy.listen.getsockname()[:2]
        self.thread = threading.Thread(target=self.proxy.run, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        self.proxy.stop()
        self.thread.join(self.TIMEOUT)
        self.assertFalse(self.thread.is_alive())

    def udp(self, host=None):
        sock = socket.socket(self.family, socket.SOCK_DGRAM)
        sock.bind((host or self.host, 0))
        sock.settimeout(self.TIMEOUT)
        self.addCleanup(sock.close)
        return sock

    def assertSilent(self, sock):
        sock.settimeout(0.2)
        with self.assertRaises(socket.timeout):
            sock.recvfrom(2048)
        sock.settimeout(self.TIMEOUT)

    def check_bidirectional(self):
        client = self.udp()
        client.sendto(b"ping", self.listen_addr)
        data, proxy_upstream = self.peer.recvfrom(2048)
        self.assertEqual(data, b"ping")
        self.assertNotEqual(proxy_upstream[:2], client.getsockname()[:2])
        self.peer.sendto(b"pong", proxy_upstream)
        data, source = client.recvfrom(2048)
        self.assertEqual(data, b"pong")
        self.assertEqual(source[:2], self.listen_addr)
        return client, proxy_upstream

    def test_bidirectional_forwarding_ipv4(self):
        self.start()
        self.check_bidirectional()

    @unittest.skipUnless(_ipv6_available(), "IPv6 loopback unavailable")
    def test_bidirectional_forwarding_ipv6(self):
        self.start("::1", socket.AF_INET6)
        self.check_bidirectional()

    def test_upstream_socket_is_connected(self):
        self.start()
        self.assertEqual(self.proxy.upstream.getpeername()[:2], self.peer.getsockname()[:2])
        self.assertNotEqual(self.proxy.upstream.getsockname()[0], "0.0.0.0")

    def test_client_locked_to_first_sender(self):
        self.start()
        client, proxy_upstream = self.check_bidirectional()
        intruder = self.udp()
        intruder.sendto(b"hijack", self.listen_addr)
        self.assertSilent(self.peer)
        self.peer.sendto(b"still-mine", proxy_upstream)
        self.assertEqual(client.recvfrom(2048)[0], b"still-mine")
        self.assertSilent(intruder)
        self.assertEqual(self.proxy.engine.directions[UP].counters.rejected, 1)

    def test_fixed_client_endpoint(self):
        allowed = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        allowed.bind(("127.0.0.1", 0))
        allowed.settimeout(self.TIMEOUT)
        self.addCleanup(allowed.close)
        self.start(client=allowed.getsockname())
        other = self.udp()
        other.sendto(b"first-but-wrong", self.listen_addr)
        self.assertSilent(self.peer)
        allowed.sendto(b"ok", self.listen_addr)
        self.assertEqual(self.peer.recvfrom(2048)[0], b"ok")

    @unittest.skipUnless(_dual_stack_available(), "dual-stack IPv6 socket unavailable")
    def test_fixed_ipv4_client_on_dual_stack_listen(self):
        allowed = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        allowed.bind(("127.0.0.1", 0))
        allowed.settimeout(self.TIMEOUT)
        self.addCleanup(allowed.close)
        self.start(client=allowed.getsockname(), listen="::")
        listen_addr = ("127.0.0.1", self.listen_addr[1])
        other = self.udp()
        other.sendto(b"first-but-wrong", listen_addr)
        self.assertSilent(self.peer)
        allowed.sendto(b"ok", listen_addr)
        data, proxy_upstream = self.peer.recvfrom(2048)
        self.assertEqual(data, b"ok")
        self.peer.sendto(b"back", proxy_upstream)
        self.assertEqual(allowed.recvfrom(2048)[0], b"back")

    @unittest.skipUnless(_ipv6_available(), "IPv6 loopback unavailable")
    def test_ipv4_client_is_refused_on_ipv6_only_listen(self):
        with self.assertRaises(ValueError):
            impair.Proxy(("::1", 0), ("127.0.0.1", 9), impair.ImpairmentEngine(impair.Profile()),
                         client=("127.0.0.1", 5004))

    def test_injection_to_upstream_socket_is_ignored(self):
        self.start()
        client, proxy_upstream = self.check_bidirectional()
        stranger = self.udp()
        stranger.sendto(b"inject", proxy_upstream)
        self.assertSilent(client)

    def test_seed_repeats_through_real_proxy(self):
        def received(seed):
            self.start(profile=impair.Profile(loss_percent=50), seed=seed)
            client = self.udp()
            for i in range(40):
                client.sendto(bytes([i]), self.listen_addr)
                time.sleep(0.001)
            got = []
            self.peer.settimeout(0.3)
            try:
                while True:
                    got.append(self.peer.recvfrom(2048)[0][0])
            except socket.timeout:
                pass
            self.stop()
            return got

        first = received(7)
        self.assertEqual(first, received(7))
        self.assertLess(len(first), 40)


if __name__ == "__main__":
    unittest.main()

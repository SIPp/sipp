#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Deterministic UDP media impairment proxy for SIPp RTP tests."""

from __future__ import annotations

import argparse
import heapq
import random
import selectors
import socket
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

Address = Tuple[str, int]
SocketAddress = tuple


@dataclass
class Profile:
    loss_percent: float = 0.0
    delay_ms: float = 0.0
    jitter_ms: float = 0.0
    duplicate_percent: float = 0.0
    reorder_percent: float = 0.0
    reorder_delay_ms: float = 40.0
    burst_start_percent: float = 0.0
    burst_length: int = 0

    def validate(self) -> None:
        for name, value in (
            ("loss-percent", self.loss_percent),
            ("duplicate-percent", self.duplicate_percent),
            ("reorder-percent", self.reorder_percent),
            ("burst-start-percent", self.burst_start_percent),
        ):
            if not 0.0 <= value <= 100.0:
                raise ValueError(f"{name} must be between 0 and 100")
        if self.delay_ms < 0.0 or self.jitter_ms < 0.0 or self.reorder_delay_ms < 0.0:
            raise ValueError("delay values must be non-negative")
        if self.reorder_percent > 0.0 and self.reorder_delay_ms <= 0.0:
            raise ValueError("reorder-delay-ms must be positive when reordering is enabled")
        if self.burst_length < 0:
            raise ValueError("burst-length must be non-negative")


@dataclass(order=True)
class ScheduledPacket:
    due: float
    sequence: int
    sock: socket.socket
    target: SocketAddress
    data: bytes


@dataclass
class HeldPacket:
    sock: socket.socket
    target: SocketAddress
    data: bytes
    due: float
    deadline: float


@dataclass
class Counters:
    received: int = 0
    forwarded: int = 0
    dropped: int = 0
    duplicated: int = 0
    reordered: int = 0
    burst_dropped: int = 0


class ImpairmentEngine:
    def __init__(self, profile: Profile, seed: Optional[int] = None) -> None:
        profile.validate()
        self.profile = profile
        self.random = random.Random(seed)
        self.queue: List[ScheduledPacket] = []
        self.sequence = 0
        self.burst_remaining = 0
        self.held_reorder: Optional[HeldPacket] = None
        self.counters = Counters()

    def _chance(self, percent: float) -> bool:
        return percent > 0.0 and self.random.random() * 100.0 < percent

    def _schedule(self, sock: socket.socket, target: SocketAddress, data: bytes, due: float) -> None:
        self.sequence += 1
        heapq.heappush(self.queue, ScheduledPacket(due, self.sequence, sock, target, data))

    def _schedule_packet(self, sock: socket.socket, target: SocketAddress, data: bytes, due: float) -> None:
        self._schedule(sock, target, data, due)
        if self._chance(self.profile.duplicate_percent):
            self._schedule(sock, target, data, due + 0.000001)
            self.counters.duplicated += 1

    def _base_due(self, now: float) -> float:
        jitter = self.random.uniform(-self.profile.jitter_ms, self.profile.jitter_ms)
        delay = max(0.0, self.profile.delay_ms + jitter)
        return now + delay / 1000.0

    def _drop(self) -> bool:
        if self.burst_remaining > 0:
            self.burst_remaining -= 1
            self.counters.dropped += 1
            self.counters.burst_dropped += 1
            return True
        if self.profile.burst_length and self._chance(self.profile.burst_start_percent):
            self.burst_remaining = max(0, self.profile.burst_length - 1)
            self.counters.dropped += 1
            self.counters.burst_dropped += 1
            return True
        if self._chance(self.profile.loss_percent):
            self.counters.dropped += 1
            return True
        return False

    def submit(self, sock: socket.socket, target: SocketAddress, data: bytes, now: float) -> None:
        self.counters.received += 1
        if self._drop():
            return

        due = self._base_due(now)

        # A selected packet is held for at most reorder_delay_ms.  If another
        # non-dropped packet arrives first, send that one before the held one,
        # producing a real adjacent-packet inversion rather than merely adding
        # the same delay to every selected packet.
        if self.held_reorder is not None:
            held = self.held_reorder
            self.held_reorder = None
            self._schedule_packet(sock, target, data, due)
            held_due = max(held.deadline, due + 0.000001)
            self._schedule_packet(held.sock, held.target, held.data, held_due)
            self.counters.reordered += 1
            return

        if self._chance(self.profile.reorder_percent):
            deadline = due + self.profile.reorder_delay_ms / 1000.0
            self.held_reorder = HeldPacket(sock, target, data, due, deadline)
            return

        self._schedule_packet(sock, target, data, due)

    def _release_expired_reorder(self, now: float) -> None:
        held = self.held_reorder
        if held is not None and held.deadline <= now:
            self.held_reorder = None
            self._schedule_packet(held.sock, held.target, held.data, held.deadline)

    def flush(self, now: float) -> None:
        self._release_expired_reorder(now)
        while self.queue and self.queue[0].due <= now:
            packet = heapq.heappop(self.queue)
            packet.sock.sendto(packet.data, packet.target)
            self.counters.forwarded += 1

    def timeout(self, now: float, default: float = 0.1) -> float:
        deadlines = []
        if self.queue:
            deadlines.append(self.queue[0].due)
        if self.held_reorder is not None:
            deadlines.append(self.held_reorder.deadline)
        if not deadlines:
            return default
        return max(0.0, min(default, min(deadlines) - now))


def _resolve(endpoint: Address, passive: bool = False) -> tuple[int, SocketAddress]:
    host, port = endpoint
    flags = socket.AI_PASSIVE if passive else 0
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM, 0, flags)
    except socket.gaierror as exc:
        raise ValueError(f"cannot resolve {host}:{port}: {exc}") from exc
    if not infos:
        raise ValueError(f"cannot resolve {host}:{port}")
    family, _, _, _, sockaddr = infos[0]
    return family, sockaddr


class Proxy:
    def __init__(self, listen: Address, upstream: Address, engine: ImpairmentEngine) -> None:
        listen_family, listen_addr = _resolve(listen, passive=True)
        upstream_family, upstream_addr = _resolve(upstream)

        self.listen = socket.socket(listen_family, socket.SOCK_DGRAM)
        self.listen.bind(listen_addr)

        self.upstream = socket.socket(upstream_family, socket.SOCK_DGRAM)
        wildcard: SocketAddress = ("::", 0, 0, 0) if upstream_family == socket.AF_INET6 else ("0.0.0.0", 0)
        self.upstream.bind(wildcard)

        self.upstream_target = upstream_addr
        self.client: Optional[SocketAddress] = None
        self.engine = engine
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.listen, selectors.EVENT_READ, "client")
        self.selector.register(self.upstream, selectors.EVENT_READ, "upstream")

    def run(self) -> None:
        try:
            while True:
                now = time.monotonic()
                self.engine.flush(now)
                for key, _ in self.selector.select(self.engine.timeout(now)):
                    data, peer = key.fileobj.recvfrom(65535)
                    if key.data == "client":
                        self.client = peer
                        self.engine.submit(self.upstream, self.upstream_target, data, time.monotonic())
                    elif self.client is not None:
                        self.engine.submit(self.listen, self.client, data, time.monotonic())
        finally:
            self.selector.close()
            self.listen.close()
            self.upstream.close()


def parse_endpoint(text: str) -> Address:
    text = text.strip()
    if text.startswith("["):
        end = text.find("]")
        if end <= 1 or end + 1 >= len(text) or text[end + 1] != ":":
            raise argparse.ArgumentTypeError("endpoint must be [IPv6]:PORT")
        host = text[1:end]
        port = text[end + 2:]
    else:
        host, sep, port = text.rpartition(":")
        if not sep or not host:
            raise argparse.ArgumentTypeError("endpoint must be HOST:PORT")
    try:
        number = int(port)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= number <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return host, number


def main() -> int:
    parser = argparse.ArgumentParser(description="Impair UDP media between SIPp and its RTP peer")
    parser.add_argument("--listen", type=parse_endpoint, required=True, help="local HOST:PORT advertised to SIPp or its peer")
    parser.add_argument("--upstream", type=parse_endpoint, required=True, help="real RTP destination HOST:PORT")
    parser.add_argument("--loss-percent", type=float, default=0.0)
    parser.add_argument("--delay-ms", type=float, default=0.0)
    parser.add_argument("--jitter-ms", type=float, default=0.0)
    parser.add_argument("--duplicate-percent", type=float, default=0.0)
    parser.add_argument("--reorder-percent", type=float, default=0.0)
    parser.add_argument("--reorder-delay-ms", type=float, default=40.0)
    parser.add_argument("--burst-start-percent", type=float, default=0.0,
                        help="chance that a packet starts a consecutive loss burst")
    parser.add_argument("--burst-length", type=int, default=0,
                        help="number of consecutive packets dropped by a burst")
    parser.add_argument("--seed", type=int, help="seed for reproducible impairment")
    args = parser.parse_args()
    profile = Profile(
        loss_percent=args.loss_percent,
        delay_ms=args.delay_ms,
        jitter_ms=args.jitter_ms,
        duplicate_percent=args.duplicate_percent,
        reorder_percent=args.reorder_percent,
        reorder_delay_ms=args.reorder_delay_ms,
        burst_start_percent=args.burst_start_percent,
        burst_length=args.burst_length,
    )
    try:
        profile.validate()
        proxy = Proxy(args.listen, args.upstream, ImpairmentEngine(profile, args.seed))
    except ValueError as exc:
        parser.error(str(exc))
    proxy.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

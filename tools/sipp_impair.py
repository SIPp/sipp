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


@dataclass
class Profile:
    loss_percent: float = 0.0
    delay_ms: float = 0.0
    jitter_ms: float = 0.0

    def validate(self) -> None:
        if not 0.0 <= self.loss_percent <= 100.0:
            raise ValueError("loss-percent must be between 0 and 100")
        if self.delay_ms < 0.0:
            raise ValueError("delay-ms must be non-negative")
        if self.jitter_ms < 0.0:
            raise ValueError("jitter-ms must be non-negative")


@dataclass(order=True)
class ScheduledPacket:
    due: float
    sequence: int
    sock: socket.socket
    target: Address
    data: bytes


@dataclass
class Counters:
    received: int = 0
    forwarded: int = 0
    dropped: int = 0


class ImpairmentEngine:
    def __init__(self, profile: Profile, seed: Optional[int] = None) -> None:
        profile.validate()
        self.profile = profile
        self.random = random.Random(seed)
        self.queue: List[ScheduledPacket] = []
        self.sequence = 0
        self.counters = Counters()

    def submit(self, sock: socket.socket, target: Address, data: bytes, now: float) -> None:
        self.counters.received += 1
        if self.random.random() * 100.0 < self.profile.loss_percent:
            self.counters.dropped += 1
            return
        jitter = self.random.uniform(-self.profile.jitter_ms, self.profile.jitter_ms)
        delay = max(0.0, self.profile.delay_ms + jitter) / 1000.0
        self.sequence += 1
        heapq.heappush(self.queue, ScheduledPacket(now + delay, self.sequence, sock, target, data))

    def flush(self, now: float) -> None:
        while self.queue and self.queue[0].due <= now:
            packet = heapq.heappop(self.queue)
            packet.sock.sendto(packet.data, packet.target)
            self.counters.forwarded += 1

    def timeout(self, now: float, default: float = 0.1) -> float:
        if not self.queue:
            return default
        return max(0.0, min(default, self.queue[0].due - now))


class Proxy:
    def __init__(self, listen: Address, upstream: Address, engine: ImpairmentEngine) -> None:
        self.listen = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.listen.bind(listen)
        self.upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.upstream.bind((listen[0], 0))
        self.upstream_target = upstream
        self.client: Optional[Address] = None
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
    parser.add_argument("--seed", type=int, help="seed for reproducible impairment")
    args = parser.parse_args()
    profile = Profile(args.loss_percent, args.delay_ms, args.jitter_ms)
    try:
        profile.validate()
    except ValueError as exc:
        parser.error(str(exc))
    Proxy(args.listen, args.upstream, ImpairmentEngine(profile, args.seed)).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

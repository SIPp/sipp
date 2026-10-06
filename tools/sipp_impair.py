#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Seedable UDP media impairment proxy for SIPp RTP tests."""

from __future__ import annotations

import argparse
import heapq
import ipaddress
import math
import random
import selectors
import signal
import socket
import sys
import time
from dataclasses import dataclass, field, fields
from typing import Dict, List, Optional, TextIO, Tuple

from sipp_endpoint import format_endpoint, parse_endpoint

Address = Tuple[str, int]
SocketAddress = tuple

TO_UPSTREAM = "client->upstream"
TO_CLIENT = "upstream->client"
DIRECTIONS = (TO_UPSTREAM, TO_CLIENT)

# Spacing used to order packets that share a due time: a duplicate goes out
# right after its original and a held (reordered) packet right after both.
EPSILON = 0.000001
DEFAULT_MAX_QUEUE = 4096
RECV_SIZE = 65535


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
        for name, value in (
            ("delay-ms", self.delay_ms),
            ("jitter-ms", self.jitter_ms),
            ("reorder-delay-ms", self.reorder_delay_ms),
        ):
            if not math.isfinite(value) or value < 0.0:
                raise ValueError(f"{name} must be a finite non-negative number")
        if self.reorder_percent > 0.0 and self.reorder_delay_ms <= 0.0:
            raise ValueError("reorder-delay-ms must be positive when reordering is enabled")
        if self.burst_length < 0:
            raise ValueError("burst-length must be non-negative")


@dataclass
class Counters:
    received: int = 0
    forwarded: int = 0
    dropped: int = 0
    burst_dropped: int = 0
    duplicated: int = 0
    reordered: int = 0
    overflow: int = 0
    send_errors: int = 0
    rejected: int = 0

    def format(self) -> str:
        return " ".join(f"{f.name}={getattr(self, f.name)}" for f in fields(self))


@dataclass(order=True)
class ScheduledPacket:
    due: float
    sequence: int
    sock: socket.socket = field(compare=False)
    target: Optional[SocketAddress] = field(compare=False)
    data: bytes = field(compare=False)
    counters: Counters = field(compare=False)


@dataclass
class HeldPacket:
    sock: socket.socket
    target: Optional[SocketAddress]
    data: bytes
    deadline: float
    duplicate: bool


class Direction:
    """Impairment state of one direction of the flow.

    Each direction has its own RNG, burst state, reorder slot and counters,
    and every draw for a packet is taken when it arrives, so the decisions
    taken for the Nth packet of a direction depend only on the seed and N,
    never on how the two directions interleave or on packet timing.
    """

    def __init__(self, name: str, seed: Optional[int]) -> None:
        self.name = name
        self.random = random.Random(None if seed is None else f"{seed}/{name}")
        self.burst_remaining = 0
        self.held: Optional[HeldPacket] = None
        self.awaiting_partner = False
        self.counters = Counters()

    def chance(self, percent: float) -> bool:
        return percent > 0.0 and self.random.random() * 100.0 < percent


class ImpairmentEngine:
    def __init__(self, profile: Profile, seed: Optional[int] = None,
                 max_queue: int = DEFAULT_MAX_QUEUE) -> None:
        profile.validate()
        if max_queue < 1:
            raise ValueError("max-queue must be positive")
        self.profile = profile
        self.max_queue = max_queue
        self.queue: List[ScheduledPacket] = []
        self.sequence = 0
        self.directions: Dict[str, Direction] = {name: Direction(name, seed) for name in DIRECTIONS}

    def _schedule(self, direction: Direction, sock: socket.socket,
                  target: Optional[SocketAddress], data: bytes, due: float) -> bool:
        if len(self.queue) >= self.max_queue:
            direction.counters.overflow += 1
            return False
        self.sequence += 1
        heapq.heappush(self.queue, ScheduledPacket(due, self.sequence, sock, target, data, direction.counters))
        return True

    def _schedule_packet(self, direction: Direction, sock: socket.socket,
                         target: Optional[SocketAddress], data: bytes, due: float,
                         duplicate: bool) -> None:
        self._schedule(direction, sock, target, data, due)
        # A copy counts as duplicated even if the queue is full, where it
        # also counts as overflow, so that received + duplicated always
        # equals dropped + forwarded + overflow + send_errors + waiting.
        if duplicate:
            direction.counters.duplicated += 1
            self._schedule(direction, sock, target, data, due + EPSILON)

    def _base_due(self, direction: Direction, now: float) -> float:
        jitter = direction.random.uniform(-self.profile.jitter_ms, self.profile.jitter_ms)
        delay = max(0.0, self.profile.delay_ms + jitter)
        return now + delay / 1000.0

    def _drop(self, direction: Direction) -> bool:
        counters = direction.counters
        if direction.burst_remaining > 0:
            direction.burst_remaining -= 1
            counters.dropped += 1
            counters.burst_dropped += 1
            return True
        if self.profile.burst_length and direction.chance(self.profile.burst_start_percent):
            direction.burst_remaining = self.profile.burst_length - 1
            counters.dropped += 1
            counters.burst_dropped += 1
            return True
        if direction.chance(self.profile.loss_percent):
            counters.dropped += 1
            return True
        return False

    def submit(self, name: str, sock: socket.socket, target: Optional[SocketAddress],
               data: bytes, now: float) -> None:
        """Queue one packet; target None sends on a connected socket."""
        direction = self.directions[name]
        direction.counters.received += 1
        if self._drop(direction):
            return

        # Every draw for this packet is taken now, in this order, so none of
        # them depends on when a held packet leaves.
        due = self._base_due(direction, now)
        duplicate = direction.chance(self.profile.duplicate_percent)
        reorder = direction.chance(self.profile.reorder_percent)

        # The packet after a held one is its partner and is never held
        # itself, even when the held packet already left at its deadline.
        # A held packet is sent just after its partner, so the inversion is
        # between adjacent packets.
        if direction.awaiting_partner:
            direction.awaiting_partner = False
            self._schedule_packet(direction, sock, target, data, due, duplicate)
            held = direction.held
            if held is not None:
                direction.held = None
                self._schedule_packet(direction, held.sock, held.target, held.data,
                                      due + 2 * EPSILON, held.duplicate)
                direction.counters.reordered += 1
            return

        if reorder:
            deadline = due + self.profile.reorder_delay_ms / 1000.0
            direction.held = HeldPacket(sock, target, data, deadline, duplicate)
            direction.awaiting_partner = True
            return

        self._schedule_packet(direction, sock, target, data, due, duplicate)

    def _release_expired(self, now: float) -> None:
        # Without a following packet the held one is sent at its deadline, so
        # reordering never turns into loss.
        for direction in self.directions.values():
            held = direction.held
            if held is not None and held.deadline <= now:
                direction.held = None
                self._schedule_packet(direction, held.sock, held.target, held.data,
                                      held.deadline, held.duplicate)

    def flush(self, now: float) -> None:
        self._release_expired(now)
        while self.queue and self.queue[0].due <= now:
            packet = heapq.heappop(self.queue)
            try:
                if packet.target is None:
                    packet.sock.send(packet.data)
                else:
                    packet.sock.sendto(packet.data, packet.target)
            except OSError:
                packet.counters.send_errors += 1
                continue
            packet.counters.forwarded += 1

    def timeout(self, now: float, default: float = 0.1) -> float:
        deadlines = [held.deadline for held in (d.held for d in self.directions.values()) if held is not None]
        if self.queue:
            deadlines.append(self.queue[0].due)
        if not deadlines:
            return default
        return max(0.0, min(default, min(deadlines) - now))

    def report(self) -> str:
        return "\n".join(f"sipp_impair: {name} {d.counters.format()}" for name, d in self.directions.items())


def _resolve(endpoint: Address, passive: bool = False, family: int = socket.AF_UNSPEC) -> tuple[int, SocketAddress]:
    host, port = endpoint
    flags = socket.AI_PASSIVE if passive else 0
    try:
        infos = socket.getaddrinfo(host, port, family, socket.SOCK_DGRAM, 0, flags)
    except socket.gaierror as exc:
        raise ValueError(f"cannot resolve {host}:{port}: {exc}") from exc
    if not infos:
        raise ValueError(f"cannot resolve {host}:{port}")
    family, _, _, _, sockaddr = infos[0]
    return family, sockaddr


def _dual_stack(listen_family: int, listen_addr: SocketAddress) -> bool:
    return listen_family == socket.AF_INET6 and ipaddress.ip_address(listen_addr[0]).is_unspecified


def _resolve_client(client: Address, listen_family: int, listen_addr: SocketAddress) -> SocketAddress:
    try:
        return _resolve(client, family=listen_family)[1]
    except ValueError:
        # Only a [::] listener takes IPv4 too; [::1] can never see this client.
        if not _dual_stack(listen_family, listen_addr):
            raise
    # A dual-stack IPv6 socket sees an IPv4 client as ::ffff:a.b.c.d and
    # sends to it through that address.
    host, port = _resolve(client, family=socket.AF_INET)[1]
    return _resolve((f"::ffff:{host}", port), family=socket.AF_INET6)[1]


class Proxy:
    """Forward one UDP flow between a single client and the upstream peer.

    The upstream socket is connect()ed, so the kernel picks the local address
    and only delivers datagrams from the upstream peer.  The client is either
    fixed with ``client`` or locked to the first sender; datagrams from any
    other source are counted as rejected and discarded.
    """

    def __init__(self, listen: Address, upstream: Address, engine: ImpairmentEngine,
                 client: Optional[Address] = None) -> None:
        listen_family, listen_addr = _resolve(listen, passive=True)
        upstream_family, upstream_addr = _resolve(upstream)
        self.client: Optional[SocketAddress] = None
        if client is not None:
            self.client = _resolve_client(client, listen_family, listen_addr)

        self.listen = socket.socket(listen_family, socket.SOCK_DGRAM)
        if _dual_stack(listen_family, listen_addr):
            # Linux defaults to dual-stack, but net.ipv6.bindv6only can change it
            self.listen.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        self.upstream = socket.socket(upstream_family, socket.SOCK_DGRAM)
        try:
            self.listen.bind(listen_addr)
            self.upstream.connect(upstream_addr)
        except OSError as exc:
            self.listen.close()
            self.upstream.close()
            raise ValueError(f"cannot open sockets: {exc}") from exc

        self.engine = engine
        self.running = False
        self.report_requested = False
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.listen, selectors.EVENT_READ, TO_UPSTREAM)
        self.selector.register(self.upstream, selectors.EVENT_READ, TO_CLIENT)

    def stop(self) -> None:
        self.running = False

    def _accept_client(self, peer: SocketAddress) -> bool:
        if self.client is None:
            self.client = peer
            return True
        return peer[:2] == self.client[:2]

    def _receive(self, key: selectors.SelectorKey) -> None:
        try:
            data, peer = key.fileobj.recvfrom(RECV_SIZE)
        except OSError:
            # e.g. ICMP port unreachable reported on the connected socket
            return
        now = time.monotonic()
        if key.data == TO_UPSTREAM:
            if not self._accept_client(peer):
                self.engine.directions[TO_UPSTREAM].counters.rejected += 1
                return
            self.engine.submit(TO_UPSTREAM, self.upstream, None, data, now)
        elif self.client is not None:
            self.engine.submit(TO_CLIENT, self.listen, self.client, data, now)
        else:
            self.engine.directions[TO_CLIENT].counters.rejected += 1

    def run(self, stream: Optional[TextIO] = None) -> None:
        self.running = True
        try:
            while self.running:
                now = time.monotonic()
                self.engine.flush(now)
                if self.report_requested and stream is not None:
                    self.report_requested = False
                    print(self.engine.report(), file=stream, flush=True)
                for key, _ in self.selector.select(self.engine.timeout(now)):
                    self._receive(key)
        finally:
            self.close()

    def close(self) -> None:
        self.selector.close()
        self.listen.close()
        self.upstream.close()


def _install_signals(proxy: Proxy) -> None:
    signal.signal(signal.SIGTERM, lambda *_: proxy.stop())
    if hasattr(signal, "SIGUSR1"):
        signal.signal(signal.SIGUSR1, lambda *_: setattr(proxy, "report_requested", True))


def main() -> int:
    parser = argparse.ArgumentParser(description="Impair one UDP media flow between SIPp and its RTP peer")
    parser.add_argument("--listen", type=parse_endpoint, required=True, help="local HOST:PORT advertised to the client")
    parser.add_argument("--upstream", type=parse_endpoint, required=True, help="real RTP destination HOST:PORT")
    parser.add_argument("--client", type=parse_endpoint,
                        help="only accept HOST:PORT as client (default: lock to the first sender)")
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
    parser.add_argument("--max-queue", type=int, default=DEFAULT_MAX_QUEUE,
                        help=f"maximum number of queued packets (default: {DEFAULT_MAX_QUEUE})")
    parser.add_argument("--seed", type=int, help="seed for reproducible per-direction impairment decisions")
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
        engine = ImpairmentEngine(profile, args.seed, args.max_queue)
        proxy = Proxy(args.listen, args.upstream, engine, args.client)
    except ValueError as exc:
        parser.error(str(exc))
    _install_signals(proxy)
    print(f"sipp_impair: listening on {format_endpoint(proxy.listen.getsockname()[:2])}, "
          f"forwarding to {format_endpoint(args.upstream)}", file=sys.stderr, flush=True)
    try:
        proxy.run(sys.stderr)
    except KeyboardInterrupt:
        pass
    print(engine.report(), file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

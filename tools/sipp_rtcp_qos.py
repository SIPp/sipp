#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Decode RTCP reception reports and estimate media QoS/MOS."""

from __future__ import annotations

import argparse
import base64
import json
import math
import socket
import struct
import time
from dataclasses import dataclass, asdict
from typing import Iterable, List, Optional


NTP_EPOCH = 2208988800


@dataclass(frozen=True)
class ReportBlock:
    ssrc: int
    fraction_lost: int
    cumulative_lost: int
    highest_sequence: int
    jitter: int
    lsr: int
    dlsr: int

    @property
    def loss_percent(self) -> float:
        return self.fraction_lost * 100.0 / 256.0


@dataclass(frozen=True)
class RtcpPacket:
    packet_type: int
    sender_ssrc: int
    reports: List[ReportBlock]


def _signed24(data: bytes) -> int:
    value = int.from_bytes(data, "big")
    return value - (1 << 24) if value & 0x800000 else value


def parse_rtcp(data: bytes) -> List[RtcpPacket]:
    """Parse compound RTCP SR/RR packets and their report blocks."""
    packets: List[RtcpPacket] = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            raise ValueError("truncated RTCP header")
        first, packet_type, words = struct.unpack_from("!BBH", data, offset)
        version = first >> 6
        count = first & 0x1F
        size = (words + 1) * 4
        if version != 2:
            raise ValueError(f"unsupported RTCP version {version}")
        if size < 4 or offset + size > len(data):
            raise ValueError("invalid RTCP packet length")
        packet = data[offset:offset + size]
        if packet_type in (200, 201):
            minimum = 28 if packet_type == 200 else 8
            if len(packet) < minimum:
                raise ValueError("truncated RTCP SR/RR")
            sender_ssrc = struct.unpack_from("!I", packet, 4)[0]
            report_offset = 28 if packet_type == 200 else 8
            reports: List[ReportBlock] = []
            for _ in range(count):
                if report_offset + 24 > len(packet):
                    raise ValueError("truncated RTCP report block")
                ssrc = struct.unpack_from("!I", packet, report_offset)[0]
                fraction = packet[report_offset + 4]
                lost = _signed24(packet[report_offset + 5:report_offset + 8])
                highest, jitter, lsr, dlsr = struct.unpack_from("!IIII", packet, report_offset + 8)
                reports.append(ReportBlock(ssrc, fraction, lost, highest, jitter, lsr, dlsr))
                report_offset += 24
            packets.append(RtcpPacket(packet_type, sender_ssrc, reports))
        offset += size
    return packets


def ntp_middle_32(unix_time: Optional[float] = None) -> int:
    now = time.time() if unix_time is None else unix_time
    seconds = int(now) + NTP_EPOCH
    fraction = int((now - int(now)) * (1 << 32)) & 0xFFFFFFFF
    return ((seconds & 0xFFFF) << 16) | (fraction >> 16)


def rtt_ms(report: ReportBlock, arrival_middle_ntp: int) -> Optional[float]:
    if not report.lsr:
        return None
    delta = (arrival_middle_ntp - report.lsr - report.dlsr) & 0xFFFFFFFF
    # Values with the high bit set represent a wrapped/invalid negative RTT.
    if delta & 0x80000000:
        return None
    return delta * 1000.0 / 65536.0


def estimate_mos(report: ReportBlock, clock_rate: int, round_trip_ms: Optional[float]) -> dict:
    if clock_rate <= 0:
        raise ValueError("clock rate must be positive")
    jitter_ms = report.jitter * 1000.0 / clock_rate
    loss = report.loss_percent
    rtt = max(round_trip_ms or 0.0, 0.0)
    # Lightweight G.711-style E-model approximation. This is an estimate,
    # not a replacement for codec-aware ITU-T G.107 calculation.
    one_way_delay = rtt / 2.0 + 2.0 * jitter_ms + 10.0
    delay_impairment = 0.024 * one_way_delay
    if one_way_delay > 177.3:
        delay_impairment += 0.11 * (one_way_delay - 177.3)
    equipment_impairment = 2.5 * loss
    r_factor = max(0.0, min(100.0, 93.2 - delay_impairment - equipment_impairment))
    if r_factor <= 0:
        mos = 1.0
    elif r_factor >= 100:
        mos = 4.5
    else:
        mos = 1.0 + 0.035 * r_factor + r_factor * (r_factor - 60.0) * (100.0 - r_factor) * 0.000007
        mos = max(1.0, min(4.5, mos))
    return {
        "loss_percent": loss,
        "jitter_ms": jitter_ms,
        "rtt_ms": round_trip_ms,
        "r_factor": r_factor,
        "mos_lq": mos,
    }


def decode(data: bytes, clock_rate: int = 8000, arrival_middle_ntp: Optional[int] = None) -> list:
    arrival = ntp_middle_32() if arrival_middle_ntp is None else arrival_middle_ntp
    output = []
    for packet in parse_rtcp(data):
        item = {"packet_type": packet.packet_type, "sender_ssrc": packet.sender_ssrc, "reports": []}
        for report in packet.reports:
            rtt = rtt_ms(report, arrival)
            item["reports"].append({**asdict(report), **estimate_mos(report, clock_rate, rtt)})
        output.append(item)
    return output


def _host_port(value: str) -> tuple[str, int]:
    host, sep, port = value.rpartition(":")
    if not sep or not host:
        raise argparse.ArgumentTypeError("expected HOST:PORT")
    try:
        parsed = int(port)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("invalid port") from exc
    if not 1 <= parsed <= 65535:
        raise argparse.ArgumentTypeError("port must be 1..65535")
    return host, parsed


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Decode RTCP QoS reports and estimate MOS")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--hex", dest="hex_data", help="one compound RTCP datagram as hex")
    source.add_argument("--listen", type=_host_port, metavar="HOST:PORT", help="listen for RTCP UDP datagrams")
    parser.add_argument("--clock-rate", type=int, default=8000, help="RTP clock rate for jitter conversion")
    args = parser.parse_args(argv)

    if args.hex_data is not None:
        try:
            data = bytes.fromhex(args.hex_data)
            print(json.dumps(decode(data, args.clock_rate), sort_keys=True))
        except ValueError as exc:
            parser.error(str(exc))
        return 0

    host, port = args.listen
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((host, port))
        while True:
            data, peer = sock.recvfrom(65535)
            try:
                payload = {"peer": f"{peer[0]}:{peer[1]}", "rtcp": decode(data, args.clock_rate)}
            except ValueError as exc:
                payload = {"peer": f"{peer[0]}:{peer[1]}", "error": str(exc)}
            print(json.dumps(payload, sort_keys=True), flush=True)


if __name__ == "__main__":
    raise SystemExit(main())

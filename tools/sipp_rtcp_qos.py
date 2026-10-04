#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Decode RTCP/SRTCP reception reports and estimate conversational media QoS."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import math
import os
import socket
import struct
import time
from collections import OrderedDict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple


NTP_EPOCH = 2208988800
SRTCP_AUTH_TAG_BYTES = 10
DEFAULT_MAX_RTT_MS = 10_000.0
DEFAULT_QOS_STATE_CAPACITY = 1024
REPLAY_WINDOW = 64


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
    def interval_loss_percent(self) -> float:
        return self.fraction_lost * 100.0 / 256.0


@dataclass(frozen=True)
class RtcpPacket:
    packet_type: int
    sender_ssrc: int
    reports: List[ReportBlock]


class QosState:
    """Track rolling loss baselines per reporter/source pair with bounded state."""

    def __init__(self, max_entries: int = DEFAULT_QOS_STATE_CAPACITY) -> None:
        if max_entries <= 0:
            raise ValueError("QoS state capacity must be positive")
        self.max_entries = max_entries
        self._baseline: OrderedDict[Tuple[int, int], Tuple[int, int]] = OrderedDict()

    def loss_percent(self, sender_ssrc: int, report: ReportBlock) -> Tuple[float, str]:
        key = (sender_ssrc, report.ssrc)
        baseline = self._baseline.get(key)
        if baseline is None:
            if len(self._baseline) >= self.max_entries:
                self._baseline.popitem(last=False)
            self._baseline[key] = (report.highest_sequence, report.cumulative_lost)
            return report.interval_loss_percent, "interval"

        self._baseline.move_to_end(key)
        base_sequence, base_lost = baseline
        expected = report.highest_sequence - base_sequence
        lost = report.cumulative_lost - base_lost
        self._baseline[key] = (report.highest_sequence, report.cumulative_lost)
        if expected <= 0 or lost < 0:
            return report.interval_loss_percent, "interval-reset"
        return max(0.0, min(100.0, lost * 100.0 / expected)), "observed-delta"


def _signed24(data: bytes) -> int:
    value = int.from_bytes(data, "big")
    return value - (1 << 24) if value & 0x800000 else value


def parse_rtcp(data: bytes) -> List[RtcpPacket]:
    """Parse compound RTCP SR/RR packets, including final-packet padding."""
    packets: List[RtcpPacket] = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            raise ValueError("truncated RTCP header")
        first, packet_type, words = struct.unpack_from("!BBH", data, offset)
        version = first >> 6
        padded = bool(first & 0x20)
        count = first & 0x1F
        size = (words + 1) * 4
        if version != 2:
            raise ValueError(f"unsupported RTCP version {version}")
        if size < 4 or offset + size > len(data):
            raise ValueError("invalid RTCP packet length")
        packet = data[offset:offset + size]
        payload_end = len(packet)
        if padded:
            if offset + size != len(data):
                raise ValueError("RTCP padding is only valid on the final compound packet")
            padding = packet[-1]
            if padding == 0 or padding > len(packet) - 4:
                raise ValueError("invalid RTCP padding")
            payload_end -= padding

        if packet_type in (200, 201):
            minimum = 28 if packet_type == 200 else 8
            if payload_end < minimum:
                raise ValueError("truncated RTCP SR/RR")
            sender_ssrc = struct.unpack_from("!I", packet, 4)[0]
            report_offset = 28 if packet_type == 200 else 8
            reports: List[ReportBlock] = []
            for _ in range(count):
                if report_offset + 24 > payload_end:
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


def rtt_ms(report: ReportBlock, arrival_middle_ntp: int, *,
           local_ssrcs: Optional[Set[int]] = None,
           max_rtt_ms: float = DEFAULT_MAX_RTT_MS) -> Optional[float]:
    """Return RTT only when the report refers to a known local SR sender."""
    if not report.lsr or not local_ssrcs or report.ssrc not in local_ssrcs:
        return None
    if max_rtt_ms <= 0:
        raise ValueError("maximum RTT must be positive")
    delta = (arrival_middle_ntp - report.lsr - report.dlsr) & 0xFFFFFFFF
    if delta & 0x80000000:
        return None
    value = delta * 1000.0 / 65536.0
    return value if value <= max_rtt_ms else None


def _mos_from_r(r_factor: float) -> float:
    if r_factor <= 0:
        return 1.0
    if r_factor >= 100:
        return 4.5
    mos = 1.0 + 0.035 * r_factor + r_factor * (r_factor - 60.0) * (100.0 - r_factor) * 0.000007
    return max(1.0, min(4.5, mos))


def estimate_mos(report: ReportBlock, clock_rate: int, round_trip_ms: Optional[float], *,
                 loss_percent: Optional[float] = None, ie: float = 0.0,
                 bpl: float = 25.1) -> dict:
    """Estimate conversational MOS with a simplified G.107-style model.

    Jitter is reported but is deliberately not converted into playout delay: that
    would require codec/ptime and jitter-buffer behaviour that this probe does not
    observe. If RTT is unavailable, conversational R/MOS are returned as null.
    """
    if clock_rate <= 0:
        raise ValueError("clock rate must be positive")
    if not 0.0 <= ie < 95.0:
        raise ValueError("Ie must be in the range 0..95")
    if bpl <= 0:
        raise ValueError("Bpl must be positive")
    jitter_ms = report.jitter * 1000.0 / clock_rate
    loss = report.interval_loss_percent if loss_percent is None else loss_percent
    loss = max(0.0, min(100.0, loss))
    ie_eff = ie if loss == 0.0 else ie + (95.0 - ie) * loss / (loss + bpl)

    if round_trip_ms is None:
        return {
            "interval_loss_percent": report.interval_loss_percent,
            "mos_loss_percent": loss,
            "jitter_ms": jitter_ms,
            "rtt_ms": None,
            "r_factor": None,
            "mos_cq": None,
            "ie_eff": ie_eff,
        }

    rtt = max(round_trip_ms, 0.0)
    one_way_delay = rtt / 2.0
    delay_impairment = 0.024 * one_way_delay
    if one_way_delay > 177.3:
        delay_impairment += 0.11 * (one_way_delay - 177.3)
    r_factor = max(0.0, min(100.0, 93.2 - delay_impairment - ie_eff))
    return {
        "interval_loss_percent": report.interval_loss_percent,
        "mos_loss_percent": loss,
        "jitter_ms": jitter_ms,
        "rtt_ms": round_trip_ms,
        "r_factor": r_factor,
        "mos_cq": _mos_from_r(r_factor),
        "ie_eff": ie_eff,
    }


def decode(data: bytes, clock_rate: int = 8000, arrival_middle_ntp: Optional[int] = None, *,
           local_ssrcs: Optional[Set[int]] = None,
           max_rtt_ms: float = DEFAULT_MAX_RTT_MS,
           ie: float = 0.0, bpl: float = 25.1,
           state: Optional[QosState] = None) -> list:
    if clock_rate <= 0:
        raise ValueError("clock rate must be positive")
    arrival = ntp_middle_32() if arrival_middle_ntp is None else arrival_middle_ntp
    tracker = state or QosState()
    output = []
    for packet in parse_rtcp(data):
        item = {"packet_type": packet.packet_type, "sender_ssrc": packet.sender_ssrc, "reports": []}
        for report in packet.reports:
            loss_percent, loss_source = tracker.loss_percent(packet.sender_ssrc, report)
            rtt = rtt_ms(report, arrival, local_ssrcs=local_ssrcs, max_rtt_ms=max_rtt_ms)
            metrics = estimate_mos(report, clock_rate, rtt, loss_percent=loss_percent, ie=ie, bpl=bpl)
            item["reports"].append({
                **asdict(report),
                **metrics,
                "mos_loss_source": loss_source,
            })
        output.append(item)
    return output


def _aes_ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise RuntimeError("SRTCP decoding requires the optional 'cryptography' Python package") from exc
    encryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _srtcp_kdf(master_key: bytes, master_salt: bytes, label: int, length: int) -> bytes:
    """RFC 3711 AES-CM KDF with kdr=0, using SRTCP labels 3/4/5."""
    if len(master_key) != 16 or len(master_salt) != 14:
        raise ValueError("AES_CM_128 SRTCP requires a 16-byte master key and 14-byte master salt")
    if label not in (0x03, 0x04, 0x05):
        raise ValueError("SRTCP KDF label must be 0x03, 0x04 or 0x05")
    if length <= 0:
        raise ValueError("derived key length must be positive")
    x = bytearray(master_salt + b"\x00\x00")
    x[7] ^= label
    return _aes_ctr(master_key, bytes(x), b"\x00" * length)


def _sdes_material(inline_key: str) -> tuple[bytes, bytes]:
    text = inline_key.strip()
    if text.lower().startswith("inline:"):
        text = text[7:]
    if "|" in text:
        raise ValueError("SDES lifetime/MKI parameters are not supported")
    try:
        material = base64.b64decode(text, validate=True)
    except Exception as exc:
        raise ValueError("invalid SDES inline base64 key") from exc
    if len(material) != 30:
        raise ValueError("AES_CM_128 SDES inline key must contain exactly 30 decoded bytes")
    return material[:16], material[16:30]


class SrtcpContext:
    """Cache SRTCP session keys and enforce a 64-packet replay window."""

    def __init__(self, inline_key: str, tag_bytes: int = SRTCP_AUTH_TAG_BYTES) -> None:
        if tag_bytes != SRTCP_AUTH_TAG_BYTES:
            raise ValueError("AES-CM SRTCP uses an 80-bit authentication tag")
        master_key, master_salt = _sdes_material(inline_key)
        self.enc_key = _srtcp_kdf(master_key, master_salt, 0x03, 16)
        self.auth_key = _srtcp_kdf(master_key, master_salt, 0x04, 20)
        self.salt_key = _srtcp_kdf(master_key, master_salt, 0x05, 14)
        self.tag_bytes = tag_bytes
        self._replay: Dict[int, Tuple[int, int]] = {}

    def _check_replay(self, ssrc: int, index: int) -> None:
        state = self._replay.get(ssrc)
        if state is None:
            return
        highest, bitmap = state
        if index > highest:
            return
        distance = highest - index
        if distance >= REPLAY_WINDOW or bitmap & (1 << distance):
            raise ValueError("SRTCP replay or packet outside replay window")

    def _commit_index(self, ssrc: int, index: int) -> None:
        state = self._replay.get(ssrc)
        if state is None:
            self._replay[ssrc] = (index, 1)
            return
        highest, bitmap = state
        if index > highest:
            shift = index - highest
            bitmap = 1 if shift >= REPLAY_WINDOW else ((bitmap << shift) | 1) & ((1 << REPLAY_WINDOW) - 1)
            self._replay[ssrc] = (index, bitmap)
        else:
            self._replay[ssrc] = (highest, bitmap | (1 << (highest - index)))

    def decrypt(self, packet: bytes) -> tuple[bytes, int, bool]:
        if len(packet) < 8 + 4 + self.tag_bytes:
            raise ValueError("truncated SRTCP packet")
        authenticated = packet[:-self.tag_bytes]
        supplied_tag = packet[-self.tag_bytes:]
        index_word = struct.unpack("!I", authenticated[-4:])[0]
        encrypted = bool(index_word & 0x80000000)
        index = index_word & 0x7FFFFFFF
        rtcp = authenticated[:-4]
        if len(rtcp) < 8:
            raise ValueError("truncated SRTCP RTCP header")
        ssrc = struct.unpack_from("!I", rtcp, 4)[0]

        expected_tag = hmac.new(self.auth_key, authenticated, hashlib.sha1).digest()[:self.tag_bytes]
        if not hmac.compare_digest(supplied_tag, expected_tag):
            raise ValueError("SRTCP authentication failed")
        self._check_replay(ssrc, index)

        if encrypted:
            iv_int = int.from_bytes(self.salt_key + b"\x00\x00", "big") ^ (ssrc << 64) ^ (index << 16)
            iv = iv_int.to_bytes(16, "big")
            rtcp = rtcp[:8] + _aes_ctr(self.enc_key, iv, rtcp[8:])
        self._commit_index(ssrc, index)
        return rtcp, index, encrypted


def decrypt_srtcp(packet: bytes, inline_key: str, tag_bytes: int = SRTCP_AUTH_TAG_BYTES) -> tuple[bytes, int, bool]:
    """One-shot compatibility wrapper around :class:`SrtcpContext`."""
    return SrtcpContext(inline_key, tag_bytes).decrypt(packet)


def decode_datagram(data: bytes, clock_rate: int, srtcp: Optional[SrtcpContext], *,
                    local_ssrcs: Optional[Set[int]] = None,
                    max_rtt_ms: float = DEFAULT_MAX_RTT_MS,
                    ie: float = 0.0, bpl: float = 25.1,
                    state: Optional[QosState] = None) -> dict:
    metadata = {"srtcp": False}
    if srtcp is not None:
        data, index, encrypted = srtcp.decrypt(data)
        metadata = {"srtcp": True, "srtcp_index": index, "encrypted": encrypted}
    return {
        **metadata,
        "rtcp": decode(data, clock_rate, local_ssrcs=local_ssrcs,
                       max_rtt_ms=max_rtt_ms, ie=ie, bpl=bpl, state=state),
    }


def _host_port(value: str) -> tuple[str, int]:
    value = value.strip()
    if value.startswith("["):
        end = value.find("]")
        if end <= 1 or end + 1 >= len(value) or value[end + 1] != ":":
            raise argparse.ArgumentTypeError("expected [IPv6]:PORT")
        host = value[1:end]
        port = value[end + 2:]
    else:
        if value.count(":") != 1:
            raise argparse.ArgumentTypeError("IPv6 literals must use [IPv6]:PORT")
        host, port = value.split(":", 1)
        if not host:
            raise argparse.ArgumentTypeError("expected HOST:PORT")
    try:
        parsed = int(port)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("invalid port") from exc
    if not 1 <= parsed <= 65535:
        raise argparse.ArgumentTypeError("port must be 1..65535")
    return host, parsed


def _parse_ssrc(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("SSRC must be an integer or 0x-prefixed hex value") from exc
    if not 0 <= parsed <= 0xFFFFFFFF:
        raise argparse.ArgumentTypeError("SSRC must fit in 32 bits")
    return parsed


def _bind_udp(endpoint: tuple[str, int]) -> socket.socket:
    host, port = endpoint
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM, 0, socket.AI_PASSIVE)
    except socket.gaierror as exc:
        raise RuntimeError(f"cannot resolve {host}:{port}: {exc}") from exc
    last_error: Optional[OSError] = None
    for family, socktype, proto, _, sockaddr in infos:
        sock = socket.socket(family, socktype, proto)
        try:
            sock.bind(sockaddr)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
    raise RuntimeError(f"cannot bind {host}:{port}: {last_error or 'no usable address'}")


def _normalize_ip(host: str) -> str:
    candidate = host.split("%", 1)[0]
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return host
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return str(address)


def _resolve_peer(endpoint: tuple[str, int]) -> Set[Tuple[str, int]]:
    host, port = endpoint
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        raise RuntimeError(f"cannot resolve peer {host}:{port}: {exc}") from exc
    return {(_normalize_ip(info[4][0]), info[4][1]) for info in infos}


class OutputRateLimiter:
    def __init__(self, rate: float) -> None:
        if rate < 0:
            raise ValueError("rate limit cannot be negative")
        self.rate = rate
        self.capacity = max(1.0, rate) if rate else 0.0
        self.tokens = self.capacity
        self.updated = time.monotonic()

    def allow(self) -> bool:
        if self.rate == 0:
            return True
        now = time.monotonic()
        elapsed = now - self.updated
        self.updated = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        if self.tokens < 1.0:
            return False
        self.tokens -= 1.0
        return True


def _read_secret(*, inline: Optional[str], file_path: Optional[str], env_name: Optional[str]) -> Optional[str]:
    supplied = sum(value is not None for value in (inline, file_path, env_name))
    if supplied > 1:
        raise ValueError("choose only one SRTCP key source")
    value: Optional[str]
    if inline is not None:
        value = inline.strip()
    elif file_path is not None:
        try:
            value = Path(file_path).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ValueError(f"cannot read SRTCP key file: {exc}") from exc
    elif env_name is not None:
        value = os.environ.get(env_name)
        if value is None:
            raise ValueError(f"environment variable {env_name!r} is not set")
        value = value.strip()
    else:
        return None
    if not value:
        raise ValueError("SRTCP key material is empty")
    return value


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Decode RTCP/SRTCP QoS reports and estimate conversational MOS")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--hex", dest="hex_data", help="one RTCP/SRTCP datagram as hex")
    source.add_argument("--listen", type=_host_port, metavar="HOST:PORT", help="listen for RTCP/SRTCP UDP datagrams")
    parser.add_argument("--clock-rate", type=int, default=8000, help="RTP clock rate for jitter conversion")
    parser.add_argument("--local-ssrc", action="append", type=_parse_ssrc, default=[], help="local RTP SSRC whose SR may be referenced by LSR (repeatable)")
    parser.add_argument("--max-rtt-ms", type=float, default=DEFAULT_MAX_RTT_MS, help="reject larger RTT samples")
    parser.add_argument("--ie", type=float, default=0.0, help="codec equipment impairment factor (default 0 for G.711-like media)")
    parser.add_argument("--bpl", type=float, default=25.1, help="codec packet-loss robustness factor (default 25.1 for G.711 with PLC)")
    secret = parser.add_mutually_exclusive_group()
    secret.add_argument("--srtcp-inline", help="SDES inline key material (visible in process listings; prefer file/env)")
    secret.add_argument("--srtcp-inline-file", help="read SDES inline key material from a file")
    secret.add_argument("--srtcp-inline-env", help="read SDES inline key material from this environment variable")
    parser.add_argument("--peer", type=_host_port, metavar="HOST:PORT", help="accept listener datagrams only from this source")
    parser.add_argument("--rate-limit", type=float, default=50.0, metavar="LINES_PER_SEC", help="maximum listener JSON lines per second; 0 disables limiting")
    args = parser.parse_args(argv)
    if args.clock_rate <= 0:
        parser.error("--clock-rate must be positive")
    if args.max_rtt_ms <= 0:
        parser.error("--max-rtt-ms must be positive")
    if not 0.0 <= args.ie < 95.0:
        parser.error("--ie must be in the range 0..95")
    if args.bpl <= 0:
        parser.error("--bpl must be positive")
    if args.rate_limit < 0:
        parser.error("--rate-limit cannot be negative")
    if args.peer and args.listen is None:
        parser.error("--peer requires --listen")

    try:
        inline = _read_secret(inline=args.srtcp_inline,
                              file_path=args.srtcp_inline_file,
                              env_name=args.srtcp_inline_env)
        srtcp = SrtcpContext(inline) if inline is not None else None
    except (ValueError, RuntimeError) as exc:
        parser.error(str(exc))

    local_ssrcs = set(args.local_ssrc)
    state = QosState()

    if args.hex_data is not None:
        try:
            data = bytes.fromhex(args.hex_data)
            print(json.dumps(decode_datagram(
                data, args.clock_rate, srtcp, local_ssrcs=set(),
                max_rtt_ms=args.max_rtt_ms, ie=args.ie, bpl=args.bpl, state=state), sort_keys=True))
        except (ValueError, RuntimeError) as exc:
            parser.error(str(exc))
        return 0

    try:
        sock = _bind_udp(args.listen)
        allowed_peers = _resolve_peer(args.peer) if args.peer else None
        limiter = OutputRateLimiter(args.rate_limit)
    except (ValueError, RuntimeError) as exc:
        parser.error(str(exc))
    with sock:
        while True:
            data, peer = sock.recvfrom(65535)
            peer_key = (_normalize_ip(peer[0]), peer[1])
            if allowed_peers is not None and peer_key not in allowed_peers:
                continue
            peer_text = f"[{peer[0]}]:{peer[1]}" if ":" in peer[0] else f"{peer[0]}:{peer[1]}"
            try:
                payload = {
                    "peer": peer_text,
                    **decode_datagram(data, args.clock_rate, srtcp,
                                      local_ssrcs=local_ssrcs,
                                      max_rtt_ms=args.max_rtt_ms,
                                      ie=args.ie, bpl=args.bpl, state=state),
                }
            except (ValueError, RuntimeError) as exc:
                payload = {"peer": peer_text, "error": str(exc)}
            if limiter.allow():
                print(json.dumps(payload, sort_keys=True), flush=True)


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Decode RTCP/SRTCP reception reports and estimate media QoS/MOS."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import math
import socket
import struct
import time
from dataclasses import dataclass, asdict
from typing import Iterable, List, Optional


NTP_EPOCH = 2208988800
SRTCP_AUTH_TAG_BYTES = 10


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
    if delta & 0x80000000:
        return None
    return delta * 1000.0 / 65536.0


def estimate_mos(report: ReportBlock, clock_rate: int, round_trip_ms: Optional[float]) -> dict:
    if clock_rate <= 0:
        raise ValueError("clock rate must be positive")
    jitter_ms = report.jitter * 1000.0 / clock_rate
    loss = report.loss_percent
    rtt = max(round_trip_ms or 0.0, 0.0)
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
    return {"loss_percent": loss, "jitter_ms": jitter_ms, "rtt_ms": round_trip_ms,
            "r_factor": r_factor, "mos_lq": mos}


def decode(data: bytes, clock_rate: int = 8000, arrival_middle_ntp: Optional[int] = None) -> list:
    if clock_rate <= 0:
        raise ValueError("clock rate must be positive")
    arrival = ntp_middle_32() if arrival_middle_ntp is None else arrival_middle_ntp
    output = []
    for packet in parse_rtcp(data):
        item = {"packet_type": packet.packet_type, "sender_ssrc": packet.sender_ssrc, "reports": []}
        for report in packet.reports:
            rtt = rtt_ms(report, arrival)
            item["reports"].append({**asdict(report), **estimate_mos(report, clock_rate, rtt)})
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
    text = inline_key.split("|", 1)[0]
    try:
        material = base64.b64decode(text, validate=True)
    except Exception as exc:
        raise ValueError("invalid SDES inline base64 key") from exc
    if len(material) != 30:
        raise ValueError("AES_CM_128 SDES inline key must contain exactly 30 decoded bytes")
    return material[:16], material[16:30]


def decrypt_srtcp(packet: bytes, inline_key: str, tag_bytes: int = SRTCP_AUTH_TAG_BYTES) -> tuple[bytes, int, bool]:
    """Authenticate and decrypt AES_CM_128_HMAC_SHA1 SRTCP (RFC 3711)."""
    if tag_bytes != SRTCP_AUTH_TAG_BYTES:
        raise ValueError("supported AES-CM SRTCP suites require an 80-bit authentication tag")
    if len(packet) < 8 + 4 + tag_bytes:
        raise ValueError("truncated SRTCP packet")
    master_key, master_salt = _sdes_material(inline_key)
    enc_key = _srtcp_kdf(master_key, master_salt, 0x03, 16)
    auth_key = _srtcp_kdf(master_key, master_salt, 0x04, 20)
    salt_key = _srtcp_kdf(master_key, master_salt, 0x05, 14)

    authenticated = packet[:-tag_bytes]
    supplied_tag = packet[-tag_bytes:]
    expected_tag = hmac.new(auth_key, authenticated, hashlib.sha1).digest()[:tag_bytes]
    if not hmac.compare_digest(supplied_tag, expected_tag):
        raise ValueError("SRTCP authentication failed")

    index_word = struct.unpack("!I", authenticated[-4:])[0]
    encrypted = bool(index_word & 0x80000000)
    index = index_word & 0x7FFFFFFF
    rtcp = authenticated[:-4]
    if encrypted:
        if len(rtcp) < 8:
            raise ValueError("truncated encrypted SRTCP payload")
        ssrc = struct.unpack_from("!I", rtcp, 4)[0]
        iv_int = int.from_bytes(salt_key + b"\x00\x00", "big") ^ (ssrc << 64) ^ (index << 16)
        iv = iv_int.to_bytes(16, "big")
        rtcp = rtcp[:8] + _aes_ctr(enc_key, iv, rtcp[8:])
    return rtcp, index, encrypted


def decode_datagram(data: bytes, clock_rate: int, srtcp_inline: Optional[str]) -> dict:
    metadata = {"srtcp": False}
    if srtcp_inline:
        data, index, encrypted = decrypt_srtcp(data, srtcp_inline)
        metadata = {"srtcp": True, "srtcp_index": index, "encrypted": encrypted}
    return {**metadata, "rtcp": decode(data, clock_rate)}


def _host_port(value: str) -> tuple[str, int]:
    value = value.strip()
    if value.startswith("["):
        end = value.find("]")
        if end <= 1 or end + 1 >= len(value) or value[end + 1] != ":":
            raise argparse.ArgumentTypeError("expected [IPv6]:PORT")
        host = value[1:end]
        port = value[end + 2:]
    else:
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


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Decode RTCP/SRTCP QoS reports and estimate MOS")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--hex", dest="hex_data", help="one RTCP/SRTCP datagram as hex")
    source.add_argument("--listen", type=_host_port, metavar="HOST:PORT", help="listen for RTCP/SRTCP UDP datagrams")
    parser.add_argument("--clock-rate", type=int, default=8000, help="RTP clock rate for jitter conversion")
    parser.add_argument("--srtcp-inline", help="SDES inline base64 master key+salt for AES_CM_128_HMAC_SHA1")
    args = parser.parse_args(argv)
    if args.clock_rate <= 0:
        parser.error("--clock-rate must be positive")

    if args.hex_data is not None:
        try:
            data = bytes.fromhex(args.hex_data)
            print(json.dumps(decode_datagram(data, args.clock_rate, args.srtcp_inline), sort_keys=True))
        except (ValueError, RuntimeError) as exc:
            parser.error(str(exc))
        return 0

    try:
        sock = _bind_udp(args.listen)
    except RuntimeError as exc:
        parser.error(str(exc))
    with sock:
        while True:
            data, peer = sock.recvfrom(65535)
            try:
                payload = {"peer": f"{peer[0]}:{peer[1]}",
                           **decode_datagram(data, args.clock_rate, args.srtcp_inline)}
            except (ValueError, RuntimeError) as exc:
                payload = {"peer": f"{peer[0]}:{peer[1]}", "error": str(exc)}
            print(json.dumps(payload, sort_keys=True), flush=True)


if __name__ == "__main__":
    raise SystemExit(main())

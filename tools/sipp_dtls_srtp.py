#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Run an OpenSSL DTLS-SRTP handshake and export RFC 5764 key material."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import asdict, dataclass
from typing import Iterable, Optional, Tuple

EXPORTER_LABEL = "EXTRACTOR-dtls_srtp"
SUPPORTED_PROFILES = {
    "SRTP_AES128_CM_SHA1_80": (16, 14),
    "SRTP_AES128_CM_SHA1_32": (16, 14),
}


@dataclass(frozen=True)
class SrtpKeys:
    profile: str
    client_master_key: str
    server_master_key: str
    client_master_salt: str
    server_master_salt: str


def split_keying_material(profile: str, material: bytes) -> SrtpKeys:
    sizes = SUPPORTED_PROFILES.get(profile)
    if sizes is None:
        raise ValueError(f"unsupported SRTP profile {profile!r}")
    key_len, salt_len = sizes
    expected = 2 * (key_len + salt_len)
    if len(material) != expected:
        raise ValueError(f"{profile} exporter must be {expected} bytes, got {len(material)}")
    offset = 0
    client_key = material[offset:offset + key_len]; offset += key_len
    server_key = material[offset:offset + key_len]; offset += key_len
    client_salt = material[offset:offset + salt_len]; offset += salt_len
    server_salt = material[offset:offset + salt_len]
    return SrtpKeys(profile, client_key.hex(), server_key.hex(), client_salt.hex(), server_salt.hex())


def parse_openssl_output(output: str) -> Tuple[str, bytes]:
    profile_match = re.search(r"SRTP Extension negotiated, profile=([^\s]+)", output)
    if not profile_match:
        raise RuntimeError("OpenSSL did not negotiate an SRTP protection profile")
    key_match = re.search(r"Keying material:\s*([0-9A-Fa-f]+)", output)
    if not key_match:
        raise RuntimeError("OpenSSL did not print DTLS exporter keying material")
    try:
        material = bytes.fromhex(key_match.group(1))
    except ValueError as exc:
        raise RuntimeError("invalid OpenSSL keying material output") from exc
    return profile_match.group(1), material


def run_handshake(remote: Tuple[str, int], *, cert: str, key: str,
                  profile: str = "SRTP_AES128_CM_SHA1_80", bind: Optional[str] = None,
                  openssl: str = "openssl", timeout: float = 10.0) -> Tuple[SrtpKeys, str]:
    sizes = SUPPORTED_PROFILES.get(profile)
    if sizes is None:
        raise ValueError(f"unsupported SRTP profile {profile!r}")
    export_len = 2 * sum(sizes)
    command = [
        openssl, "s_client", "-dtls1_2", "-connect", f"{remote[0]}:{remote[1]}",
        "-use_srtp", profile,
        "-keymatexport", EXPORTER_LABEL,
        "-keymatexportlen", str(export_len),
        "-cert", cert, "-key", key,
        "-showcerts", "-timeout",
    ]
    if bind:
        command.extend(["-bind", bind])
    try:
        completed = subprocess.run(command, input="", text=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"DTLS handshake failed to execute: {exc}") from exc
    if completed.returncode != 0:
        tail = "\n".join(completed.stdout.splitlines()[-12:])
        raise RuntimeError(f"OpenSSL DTLS handshake failed ({completed.returncode}):\n{tail}")
    negotiated, material = parse_openssl_output(completed.stdout)
    if negotiated != profile:
        raise RuntimeError(f"peer negotiated {negotiated}, expected {profile}")
    return split_keying_material(negotiated, material), completed.stdout


def _remote(value: str) -> Tuple[str, int]:
    host, sep, raw_port = value.rpartition(":")
    if not sep or not host:
        raise argparse.ArgumentTypeError("expected HOST:PORT")
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("invalid port") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be 1..65535")
    return host.strip("[]"), port


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="DTLS-SRTP handshake probe for SIPp media tests")
    parser.add_argument("remote", type=_remote)
    parser.add_argument("--cert", required=True, help="local PEM certificate")
    parser.add_argument("--key", required=True, help="local PEM private key")
    parser.add_argument("--profile", choices=tuple(SUPPORTED_PROFILES), default="SRTP_AES128_CM_SHA1_80")
    parser.add_argument("--bind", help="optional local HOST:PORT passed to openssl s_client")
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)
    try:
        keys, _ = run_handshake(args.remote, cert=args.cert, key=args.key, profile=args.profile,
                                bind=args.bind, openssl=args.openssl, timeout=args.timeout)
    except (ValueError, RuntimeError) as exc:
        parser.error(str(exc))
    print(json.dumps(asdict(keys), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

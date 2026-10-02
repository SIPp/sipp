#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Run an OpenSSL DTLS-SRTP handshake and export RFC 5764 key material."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import ssl
import subprocess
from dataclasses import asdict, dataclass
from typing import Iterable, Optional, Tuple

EXPORTER_LABEL = "EXTRACTOR-dtls_srtp"
SUPPORTED_PROFILES = {
    "SRTP_AES128_CM_SHA1_80": (16, 14),
    "SRTP_AES128_CM_SHA1_32": (16, 14),
}
CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)


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


def peer_certificate_fingerprint(output: str) -> str:
    match = CERT_RE.search(output)
    if not match:
        raise RuntimeError("OpenSSL output contains no peer certificate")
    try:
        der = ssl.PEM_cert_to_DER_cert(match.group(0))
    except ValueError as exc:
        raise RuntimeError("invalid peer certificate in OpenSSL output") from exc
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def normalize_fingerprint(value: str) -> str:
    value = value.strip().upper()
    value = re.sub(r"^SHA[- ]?256\s*[:=]?\s*", "", value)
    compact = re.sub(r"[^0-9A-F]", "", value)
    if len(compact) != 64:
        raise ValueError("peer fingerprint must contain a SHA-256 digest")
    return ":".join(compact[i:i + 2] for i in range(0, 64, 2))


def verify_peer_fingerprint(output: str, expected: str) -> str:
    actual = peer_certificate_fingerprint(output)
    normalized = normalize_fingerprint(expected)
    if not hmac.compare_digest(actual, normalized):
        raise RuntimeError(f"DTLS peer fingerprint mismatch: got {actual}, expected {normalized}")
    return actual


def run_handshake(remote: Tuple[str, int], *, cert: str, key: str,
                  profile: str = "SRTP_AES128_CM_SHA1_80", bind: Optional[str] = None,
                  peer_fingerprint: Optional[str] = None, openssl: str = "openssl",
                  timeout: float = 10.0) -> Tuple[SrtpKeys, str, str]:
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
    fingerprint = (verify_peer_fingerprint(completed.stdout, peer_fingerprint)
                   if peer_fingerprint else peer_certificate_fingerprint(completed.stdout))
    return split_keying_material(negotiated, material), fingerprint, completed.stdout


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
    parser.add_argument("--peer-fingerprint", help="expected SDP SHA-256 fingerprint")
    parser.add_argument("--show-keys", action="store_true", help="include sensitive SRTP key material in JSON output")
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)
    try:
        keys, fingerprint, _ = run_handshake(
            args.remote, cert=args.cert, key=args.key, profile=args.profile,
            bind=args.bind, peer_fingerprint=args.peer_fingerprint,
            openssl=args.openssl, timeout=args.timeout)
    except (ValueError, RuntimeError) as exc:
        parser.error(str(exc))
    output = {"profile": keys.profile, "peer_fingerprint_sha256": fingerprint}
    if args.show_keys:
        output["keys"] = asdict(keys)
    print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

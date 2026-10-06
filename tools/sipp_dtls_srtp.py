#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Run a diagnostic OpenSSL DTLS-SRTP handshake and inspect RFC 5764 key material."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import ssl
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Optional, Tuple

from sipp_endpoint import format_endpoint, parse_endpoint

EXPORTER_LABEL = "EXTRACTOR-dtls_srtp"
SUPPORTED_PROFILES = {
    "SRTP_AEAD_AES_128_GCM": (16, 12),
    "SRTP_AES128_CM_SHA1_80": (16, 14),
    "SRTP_AES128_CM_SHA1_32": (16, 14),
}
DEFAULT_PROFILES = tuple(SUPPORTED_PROFILES)
CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)
PROFILE_RE = re.compile(r"^SRTP Extension negotiated, profile=([^\s]+)\s*$", re.MULTILINE)
KEYING_RE = re.compile(r"^\s*Keying material:\s*([0-9A-Fa-f]+)\s*$", re.MULTILINE)
FINGERPRINT_RE = re.compile(
    r"^sha-256\s+((?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2})$",
    re.IGNORECASE,
)
SENSITIVE_OUTPUT_MARKERS = (
    "Master-Key:",
    "TLS session ticket:",
    "Keying material:",
)


@dataclass(frozen=True)
class SrtpKeys:
    profile: str
    client_master_key: str
    server_master_key: str
    client_master_salt: str
    server_master_salt: str


def _exporter_length(profile: str) -> int:
    sizes = SUPPORTED_PROFILES.get(profile)
    if sizes is None:
        raise ValueError(f"unsupported SRTP profile {profile!r}")
    return 2 * sum(sizes)


def _parse_profiles(value: str) -> Tuple[str, ...]:
    profiles = tuple(part.strip() for part in value.split(":") if part.strip())
    if not profiles:
        raise ValueError("at least one SRTP profile is required")
    unsupported = [profile for profile in profiles if profile not in SUPPORTED_PROFILES]
    if unsupported:
        raise ValueError(f"unsupported SRTP profile {unsupported[0]!r}")
    if len(set(profiles)) != len(profiles):
        raise ValueError("SRTP profile list contains duplicates")
    return profiles


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


def _handshake_output(output: str) -> str:
    """Return only OpenSSL's handshake/export section, excluding peer app data."""
    key_match = KEYING_RE.search(output)
    if not key_match:
        raise RuntimeError("OpenSSL did not print DTLS exporter keying material")
    # s_client prints the exporter line before relaying peer application data.
    # Stop there so peer-controlled text cannot influence subsequent parsing.
    return output[:key_match.end()]


def parse_openssl_output(output: str) -> Tuple[str, bytes]:
    section = _handshake_output(output)
    profile_match = PROFILE_RE.search(section)
    if not profile_match:
        raise RuntimeError("OpenSSL did not negotiate an SRTP protection profile")
    key_match = KEYING_RE.search(section)
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
    match = FINGERPRINT_RE.fullmatch(value.strip())
    if not match:
        raise ValueError(
            "peer fingerprint must be 'sha-256' followed by 32 colon-separated hex pairs"
        )
    return match.group(1).upper()


def verify_peer_fingerprint(output: str, expected: str) -> str:
    actual = peer_certificate_fingerprint(output)
    normalized = normalize_fingerprint(expected)
    if not hmac.compare_digest(actual, normalized):
        raise RuntimeError(f"DTLS peer fingerprint mismatch: got {actual}, expected {normalized}")
    return actual


def _error_tail(output: Optional[str], lines: int = 12) -> str:
    """Return a useful OpenSSL error tail without exposing session key material."""
    if not output:
        return ""
    cutoff = len(output)
    for marker in SENSITIVE_OUTPUT_MARKERS:
        position = output.find(marker)
        if position >= 0:
            cutoff = min(cutoff, position)
    safe = output[:cutoff].rstrip()
    return "\n".join(safe.splitlines()[-lines:])


def run_handshake(remote: Tuple[str, int], *, cert: str, key: str,
                  profile: str = ":".join(DEFAULT_PROFILES), bind: Optional[str] = None,
                  peer_fingerprint: Optional[str] = None, openssl: str = "openssl",
                  timeout: float = 10.0) -> Tuple[SrtpKeys, str]:
    profiles = _parse_profiles(profile)
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if not openssl.strip():
        raise ValueError("OpenSSL executable cannot be empty")
    if peer_fingerprint is not None:
        # Fail before starting the handshake for malformed SDP fingerprints,
        # including an explicitly supplied empty string.
        normalize_fingerprint(peer_fingerprint)

    # OpenSSL requires a fixed exporter length before negotiation. Asking for the
    # maximum length is safe for TLS 1.2 exporters; shorter SRTP profiles consume
    # the corresponding prefix after the profile is known.
    export_len = max(_exporter_length(item) for item in profiles)
    command = [
        openssl, "s_client", "-dtls1_2", "-connect", format_endpoint(remote),
        "-use_srtp", ":".join(profiles),
        "-keymatexport", EXPORTER_LABEL,
        "-keymatexportlen", str(export_len),
        "-cert", cert, "-key", key,
        "-pass", "pass:",
        "-showcerts", "-timeout",
    ]
    if bind:
        command.extend(["-bind", bind])
    try:
        completed = subprocess.run(command, input="", text=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        captured = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout
        tail = _error_tail(captured)
        detail = f"\n{tail}" if tail else ""
        raise RuntimeError(f"OpenSSL DTLS handshake timed out after {timeout:g}s{detail}") from exc
    except OSError as exc:
        raise RuntimeError(f"DTLS handshake failed to execute: {exc}") from exc

    if completed.returncode != 0:
        tail = _error_tail(completed.stdout)
        detail = f":\n{tail}" if tail else ""
        raise RuntimeError(f"OpenSSL DTLS handshake failed ({completed.returncode}){detail}")

    section = _handshake_output(completed.stdout)
    negotiated, material = parse_openssl_output(section)
    if negotiated not in profiles:
        raise RuntimeError(f"peer negotiated unoffered SRTP profile {negotiated}")
    expected_len = _exporter_length(negotiated)
    if len(material) < expected_len:
        raise RuntimeError(
            f"OpenSSL exported {len(material)} bytes for {negotiated}, expected at least {expected_len}"
        )
    keys = split_keying_material(negotiated, material[:expected_len])
    fingerprint = (
        verify_peer_fingerprint(section, peer_fingerprint)
        if peer_fingerprint is not None
        else peer_certificate_fingerprint(section)
    )
    return keys, fingerprint


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="DTLS-SRTP diagnostic handshake probe for SIPp media tests")
    parser.add_argument("remote", type=parse_endpoint)
    parser.add_argument("--cert", required=True, help="local PEM certificate")
    parser.add_argument("--key", required=True, help="local PEM private key (unencrypted only)")
    parser.add_argument(
        "--profile",
        default=":".join(DEFAULT_PROFILES),
        help="colon-separated SRTP profile preference list passed to openssl -use_srtp",
    )
    parser.add_argument("--bind", help="optional local HOST:PORT passed to openssl s_client")
    parser.add_argument("--peer-fingerprint", help="expected SDP fingerprint: sha-256 XX:XX:...")
    parser.add_argument("--show-keys", action="store_true", help="include diagnostic SRTP key material in JSON output")
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)
    if args.show_keys and args.peer_fingerprint is None:
        parser.error("--show-keys requires --peer-fingerprint so the DTLS peer fingerprint is verified")
    for label, path in (("certificate", args.cert), ("private key", args.key)):
        if not Path(path).is_file():
            parser.error(f"local {label} file does not exist: {path}")
    try:
        keys, fingerprint = run_handshake(
            args.remote, cert=args.cert, key=args.key, profile=args.profile,
            bind=args.bind, peer_fingerprint=args.peer_fingerprint,
            openssl=args.openssl, timeout=args.timeout)
    except (ValueError, RuntimeError) as exc:
        parser.error(str(exc))
    output = {
        "profile": keys.profile,
        "peer_fingerprint_sha256": fingerprint,
        "peer_authenticated": args.peer_fingerprint is not None,
    }
    if args.show_keys:
        output["keys"] = asdict(keys)
    print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

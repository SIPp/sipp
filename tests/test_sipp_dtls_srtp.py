#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sipp_dtls_srtp", ROOT / "tools" / "sipp_dtls_srtp.py")
dtls = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = dtls
spec.loader.exec_module(dtls)


class ExporterTests(unittest.TestCase):
    def test_rfc5764_key_split(self):
        material = bytes(range(60))
        keys = dtls.split_keying_material("SRTP_AES128_CM_SHA1_80", material)
        self.assertEqual(keys.client_master_key, material[0:16].hex())
        self.assertEqual(keys.server_master_key, material[16:32].hex())
        self.assertEqual(keys.client_master_salt, material[32:46].hex())
        self.assertEqual(keys.server_master_salt, material[46:60].hex())

    def test_rejects_wrong_exporter_length(self):
        with self.assertRaises(ValueError):
            dtls.split_keying_material("SRTP_AES128_CM_SHA1_80", b"x" * 59)

    def test_parse_openssl_output(self):
        material = bytes(range(60)).hex().upper()
        output = (
            "CONNECTED\n"
            "SRTP Extension negotiated, profile=SRTP_AES128_CM_SHA1_80\n"
            f"Keying material: {material}\n"
        )
        profile, parsed = dtls.parse_openssl_output(output)
        self.assertEqual(profile, "SRTP_AES128_CM_SHA1_80")
        self.assertEqual(parsed, bytes(range(60)))


class FingerprintTests(unittest.TestCase):
    def test_normalizes_sdp_fingerprint(self):
        compact = "AA" * 32
        colon = ":".join(["AA"] * 32)
        self.assertEqual(dtls.normalize_fingerprint(f"sha-256 {colon}"), colon)
        self.assertEqual(dtls.normalize_fingerprint(compact.lower()), colon)

    def test_rejects_non_sha256_length(self):
        with self.assertRaises(ValueError):
            dtls.normalize_fingerprint("AA:BB")


class HandshakeWrapperTests(unittest.TestCase):
    def test_builds_openssl_dtls_srtp_command(self):
        material = bytes(range(60)).hex()
        output = (
            "SRTP Extension negotiated, profile=SRTP_AES128_CM_SHA1_80\n"
            f"Keying material: {material}\n"
        )
        completed = subprocess.CompletedProcess([], 0, stdout=output)
        fingerprint = ":".join(["11"] * 32)
        with mock.patch.object(dtls.subprocess, "run", return_value=completed) as run, \
             mock.patch.object(dtls, "peer_certificate_fingerprint", return_value=fingerprint):
            keys, actual_fingerprint, _ = dtls.run_handshake(
                ("192.0.2.10", 4444), cert="client.crt", key="client.key",
                bind="0.0.0.0:5555", timeout=2.0)

        command = run.call_args.args[0]
        self.assertIn("-dtls1_2", command)
        self.assertIn("-use_srtp", command)
        self.assertIn("-keymatexport", command)
        self.assertIn(dtls.EXPORTER_LABEL, command)
        self.assertIn("-keymatexportlen", command)
        self.assertIn("60", command)
        self.assertIn("-bind", command)
        self.assertEqual(keys.profile, "SRTP_AES128_CM_SHA1_80")
        self.assertEqual(actual_fingerprint, fingerprint)

    def test_nonzero_openssl_exit_is_error(self):
        completed = subprocess.CompletedProcess([], 1, stdout="handshake failure")
        with mock.patch.object(dtls.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(RuntimeError, "handshake failed"):
                dtls.run_handshake(("192.0.2.10", 4444), cert="c", key="k")


if __name__ == "__main__":
    unittest.main()

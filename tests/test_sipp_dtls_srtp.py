#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import hashlib
import importlib.util
import io
import json
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
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

    def test_aead_gcm_key_split(self):
        material = bytes(range(56))
        keys = dtls.split_keying_material("SRTP_AEAD_AES_128_GCM", material)
        self.assertEqual(keys.client_master_key, material[0:16].hex())
        self.assertEqual(keys.server_master_key, material[16:32].hex())
        self.assertEqual(keys.client_master_salt, material[32:44].hex())
        self.assertEqual(keys.server_master_salt, material[44:56].hex())

    def test_rejects_wrong_exporter_length(self):
        with self.assertRaises(ValueError):
            dtls.split_keying_material("SRTP_AES128_CM_SHA1_80", b"x" * 59)

    def test_parse_ignores_peer_application_data(self):
        material = bytes(range(60)).hex().upper()
        output = (
            "CONNECTED\n"
            "SRTP Extension negotiated, profile=SRTP_AES128_CM_SHA1_80\n"
            f"Keying material: {material}\n"
            "peer says SRTP Extension negotiated, profile=SRTP_AEAD_AES_128_GCM\n"
            "Keying material: DEADBEEF\n"
        )
        profile, parsed = dtls.parse_openssl_output(output)
        self.assertEqual(profile, "SRTP_AES128_CM_SHA1_80")
        self.assertEqual(parsed, bytes(range(60)))


class FingerprintTests(unittest.TestCase):
    def test_requires_sha256_sdp_fingerprint_syntax(self):
        colon = ":".join(["Aa"] * 32)
        self.assertEqual(dtls.normalize_fingerprint(f"sha-256 {colon}"), colon.upper())

    def test_rejects_compact_wrong_algorithm_and_junk(self):
        colon = ":".join(["AA"] * 32)
        for value in ("AA" * 32, f"sha-1 {colon}", f"sha-256 {colon[:-2]}ZZ"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    dtls.normalize_fingerprint(value)


class EndpointTests(unittest.TestCase):
    def test_remote_parser_and_formatter(self):
        self.assertEqual(dtls._remote("192.0.2.1:4444"), ("192.0.2.1", 4444))
        self.assertEqual(dtls._remote("[2001:db8::1]:4444"), ("2001:db8::1", 4444))
        self.assertEqual(dtls.format_endpoint(("192.0.2.1", 4444)), "192.0.2.1:4444")
        self.assertEqual(dtls.format_endpoint(("2001:db8::1", 4444)), "[2001:db8::1]:4444")

    def test_invalid_endpoint_is_rejected(self):
        with self.assertRaises(ValueError):
            dtls.format_endpoint(("", 4444))
        with self.assertRaises(ValueError):
            dtls.format_endpoint(("192.0.2.1", 0))


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
            keys, actual_fingerprint = dtls.run_handshake(
                ("192.0.2.10", 4444), cert="client.crt", key="client.key",
                bind="0.0.0.0:5555", timeout=2.0)

        command = run.call_args.args[0]
        self.assertIn("-dtls1_2", command)
        self.assertEqual(
            command[command.index("-use_srtp") + 1],
            "SRTP_AEAD_AES_128_GCM:SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32",
        )
        self.assertIn("-keymatexport", command)
        self.assertIn(dtls.EXPORTER_LABEL, command)
        self.assertEqual(command[command.index("-keymatexportlen") + 1], "60")
        self.assertEqual(command[command.index("-pass") + 1], "pass:")
        self.assertIn("-bind", command)
        self.assertEqual(keys.profile, "SRTP_AES128_CM_SHA1_80")
        self.assertEqual(actual_fingerprint, fingerprint)

    def test_ipv6_connect_is_bracketed(self):
        material = bytes(range(60)).hex()
        output = (
            "SRTP Extension negotiated, profile=SRTP_AES128_CM_SHA1_80\n"
            f"Keying material: {material}\n"
        )
        completed = subprocess.CompletedProcess([], 0, stdout=output)
        fingerprint = ":".join(["11"] * 32)
        with mock.patch.object(dtls.subprocess, "run", return_value=completed) as run, \
             mock.patch.object(dtls, "peer_certificate_fingerprint", return_value=fingerprint):
            dtls.run_handshake(
                ("2001:db8::10", 4444), cert="client.crt", key="client.key",
                profile="SRTP_AES128_CM_SHA1_80",
            )
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("-connect") + 1], "[2001:db8::10]:4444")

    def test_invalid_timeout_is_rejected_before_process_start(self):
        with mock.patch.object(dtls.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                dtls.run_handshake(("192.0.2.10", 4444), cert="c", key="k", timeout=0)
        run.assert_not_called()

    def test_invalid_fingerprint_is_rejected_before_process_start(self):
        with mock.patch.object(dtls.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                dtls.run_handshake(("192.0.2.10", 4444), cert="c", key="k",
                                   peer_fingerprint="AA:BB")
        run.assert_not_called()

    def test_empty_fingerprint_is_rejected_before_process_start(self):
        with mock.patch.object(dtls.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                dtls.run_handshake(("192.0.2.10", 4444), cert="c", key="k",
                                   peer_fingerprint="")
        run.assert_not_called()

    def test_nonzero_exit_truncates_sensitive_session_output(self):
        secret = "AB" * 60
        completed = subprocess.CompletedProcess(
            [], 1, stdout=(
                "handshake failure\n"
                f"Master-Key: {secret}\n"
                "TLS session ticket:\n"
                f"0000 - {secret}\n"
                f"Keying material: {secret}\n"
            )
        )
        with mock.patch.object(dtls.subprocess, "run", return_value=completed):
            with self.assertRaises(RuntimeError) as caught:
                dtls.run_handshake(("192.0.2.10", 4444), cert="c", key="k")
        message = str(caught.exception)
        self.assertIn("handshake failure", message)
        self.assertNotIn(secret, message)
        self.assertNotIn("Master-Key:", message)
        self.assertNotIn("TLS session ticket:", message)
        self.assertNotIn("Keying material:", message)

    def test_timeout_truncates_sensitive_session_output(self):
        secret = "CD" * 60
        output = (
            "CONNECTED\n"
            f"Master-Key: {secret}\n"
            "TLS session ticket:\n"
            f"0000 - {secret}\n"
            f"Keying material: {secret}\n"
        )
        timeout = subprocess.TimeoutExpired(cmd=["openssl"], timeout=1, output=output)
        with mock.patch.object(dtls.subprocess, "run", side_effect=timeout):
            with self.assertRaises(RuntimeError) as caught:
                dtls.run_handshake(("192.0.2.10", 4444), cert="c", key="k", timeout=1)
        message = str(caught.exception)
        self.assertIn("timed out", message)
        self.assertNotIn(secret, message)
        self.assertNotIn("Master-Key:", message)
        self.assertNotIn("TLS session ticket:", message)
        self.assertNotIn("Keying material:", message)

    def test_show_keys_requires_verified_peer_fingerprint(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
            dtls.main([
                "192.0.2.10:4444", "--cert", "client.crt", "--key", "client.key",
                "--show-keys",
            ])
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("--show-keys requires --peer-fingerprint", stderr.getvalue())


@unittest.skipUnless(shutil.which("openssl"), "openssl is required for DTLS loopback test")
class OpenSslLoopbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        root = Path(cls.tempdir.name)
        cls.cert = root / "cert.pem"
        cls.key = root / "key.pem"
        cls.encrypted_key = root / "encrypted-key.pem"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-subj", "/CN=sipp-dtls-loopback", "-days", "1",
                "-keyout", str(cls.key), "-out", str(cls.cert),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        subprocess.run(
            [
                "openssl", "pkey", "-in", str(cls.key), "-aes-256-cbc",
                "-passout", "pass:secret", "-out", str(cls.encrypted_key),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        pem = cls.cert.read_text(encoding="ascii")
        digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest().upper()
        cls.fingerprint = ":".join(digest[i:i + 2] for i in range(0, 64, 2))

    @classmethod
    def tearDownClass(cls):
        cls.tempdir.cleanup()

    def _wait_for_server(self, process, port, timeout=3.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if process.poll() is not None:
                output = process.stdout.read() if process.stdout else ""
                self.fail(f"openssl s_server exited early: {output}")
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                return
            finally:
                probe.close()
            time.sleep(0.02)
        self.fail("openssl s_server did not bind its UDP port in time")

    def _server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        process = subprocess.Popen(
            [
                "openssl", "s_server", "-dtls1_2", "-accept", f"127.0.0.1:{port}",
                "-cert", str(self.cert), "-key", str(self.key),
                "-use_srtp", ":".join(dtls.DEFAULT_PROFILES),
                "-keymatexport", dtls.EXPORTER_LABEL, "-keymatexportlen", "60",
                "-naccept", "1",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self._wait_for_server(process, port)
        return process, port

    def _finish_server(self, process, timeout=3.0):
        try:
            output, _ = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.terminate()
            output, _ = process.communicate(timeout=3)
        return output or ""

    def test_loopback_default_output_redacts_keys(self):
        server, port = self._server()
        stdout = io.StringIO()
        try:
            with redirect_stdout(stdout):
                rc = dtls.main([
                    f"127.0.0.1:{port}", "--cert", str(self.cert), "--key", str(self.key),
                    "--peer-fingerprint", f"sha-256 {self.fingerprint}", "--timeout", "3",
                ])
            self.assertEqual(rc, 0)
            result = json.loads(stdout.getvalue())
            self.assertTrue(result["peer_authenticated"])
            self.assertNotIn("keys", result)
            self.assertEqual(result["profile"], "SRTP_AEAD_AES_128_GCM")
        finally:
            self._finish_server(server)

    def test_loopback_show_keys_after_fingerprint_verification(self):
        server, port = self._server()
        stdout = io.StringIO()
        try:
            with redirect_stdout(stdout):
                rc = dtls.main([
                    f"127.0.0.1:{port}", "--cert", str(self.cert), "--key", str(self.key),
                    "--peer-fingerprint", f"sha-256 {self.fingerprint}", "--show-keys",
                    "--timeout", "3",
                ])
            self.assertEqual(rc, 0)
            result = json.loads(stdout.getvalue())
            self.assertIn("keys", result)
            self.assertEqual(result["keys"]["profile"], result["profile"])
        finally:
            self._finish_server(server)

    def test_loopback_export_matches_server_export(self):
        server, port = self._server()
        server_output = ""
        try:
            keys, _ = dtls.run_handshake(
                ("127.0.0.1", port), cert=str(self.cert), key=str(self.key),
                peer_fingerprint=f"sha-256 {self.fingerprint}", timeout=3,
            )
        finally:
            server_output = self._finish_server(server)
        match = dtls.KEYING_RE.search(server_output)
        self.assertIsNotNone(match, server_output)
        expected_len = dtls._exporter_length(keys.profile)
        server_material = bytes.fromhex(match.group(1))[:expected_len]
        client_material = bytes.fromhex(
            keys.client_master_key + keys.server_master_key
            + keys.client_master_salt + keys.server_master_salt
        )
        self.assertEqual(client_material, server_material)

    def test_loopback_wrong_fingerprint_emits_no_keys(self):
        server, port = self._server()
        stdout = io.StringIO()
        stderr = io.StringIO()
        wrong = ":".join(["00"] * 32)
        try:
            with redirect_stdout(stdout), redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
                dtls.main([
                    f"127.0.0.1:{port}", "--cert", str(self.cert), "--key", str(self.key),
                    "--peer-fingerprint", f"sha-256 {wrong}", "--show-keys", "--timeout", "3",
                ])
            self.assertEqual(caught.exception.code, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertNotIn("client_master_key", stderr.getvalue())
            self.assertNotIn("Keying material:", stderr.getvalue())
        finally:
            self._finish_server(server)

    def test_encrypted_key_fails_fast(self):
        server, port = self._server()
        stderr = io.StringIO()
        started = time.monotonic()
        try:
            with redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
                dtls.main([
                    f"127.0.0.1:{port}", "--cert", str(self.cert),
                    "--key", str(self.encrypted_key), "--timeout", "2",
                ])
            self.assertEqual(caught.exception.code, 2)
            self.assertLess(time.monotonic() - started, 2.0)
            self.assertIn("DTLS handshake failed", stderr.getvalue())
        finally:
            if server.poll() is None:
                server.terminate()
            self._finish_server(server)


if __name__ == "__main__":
    unittest.main()

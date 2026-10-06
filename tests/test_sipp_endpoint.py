#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import argparse
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from sipp_endpoint import format_endpoint, parse_endpoint  # noqa: E402


class EndpointTests(unittest.TestCase):
    def test_accepts_host_and_bracketed_ipv6(self):
        self.assertEqual(parse_endpoint("127.0.0.1:5060"), ("127.0.0.1", 5060))
        self.assertEqual(parse_endpoint("[::1]:5060"), ("::1", 5060))
        self.assertEqual(parse_endpoint("[::1]:0", allow_zero_port=True), ("::1", 0))
        self.assertEqual(format_endpoint(("::1", 5060)), "[::1]:5060")

    def test_rejects_ports_that_are_not_plain_digits(self):
        for value in ("h:8_0", "h:+80", "h: 80", "h:-1", "h:\u0668\u0660", "h:", "h:0x50"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                parse_endpoint(value)

    def test_rejects_out_of_range_and_unbracketed_ipv6(self):
        for value in ("h:0", "h:65536", "::1:3478"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                parse_endpoint(value)


if __name__ == "__main__":
    unittest.main()

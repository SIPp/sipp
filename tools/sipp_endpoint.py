#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Shared endpoint parsing helpers for SIPp companion tools."""

from __future__ import annotations

import argparse
from typing import Tuple


def parse_endpoint(value: str, *, allow_zero_port: bool = False) -> Tuple[str, int]:
    """Parse ``HOST:PORT`` or ``[IPv6]:PORT``.

    Port 0 is rejected unless ``allow_zero_port`` is set, which is meant for
    local bind addresses where 0 asks the operating system for an ephemeral
    port.
    """
    value = value.strip()
    if not value:
        raise argparse.ArgumentTypeError("expected HOST:PORT")

    if value.startswith("["):
        end = value.find("]")
        if end <= 1 or end + 1 >= len(value) or value[end + 1] != ":":
            raise argparse.ArgumentTypeError("expected [IPv6]:PORT")
        if value.find("[", 1) != -1 or "]" in value[end + 1:]:
            raise argparse.ArgumentTypeError("invalid bracketed endpoint")
        host = value[1:end]
        raw_port = value[end + 2:]
    else:
        if value.count(":") != 1:
            if ":" in value:
                raise argparse.ArgumentTypeError(
                    "IPv6 literals must use bracket notation: [IPv6]:PORT")
            raise argparse.ArgumentTypeError("expected HOST:PORT")
        host, raw_port = value.split(":", 1)
        if not host:
            raise argparse.ArgumentTypeError("expected HOST:PORT")

    try:
        port = int(raw_port)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("invalid port") from exc
    if allow_zero_port and port == 0:
        return host, port
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be 1..65535")
    return host, port


def format_endpoint(endpoint: Tuple[str, int]) -> str:
    host, port = endpoint
    host = host.strip()
    if not host:
        raise ValueError("host cannot be empty")
    if not 1 <= port <= 65535:
        raise ValueError("port must be 1..65535")
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Launch coordinated SIPp instances from a declarative CSV file."""

import argparse
import csv
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass

DEFAULT_BASE_PORT = 5060
MAX_CHILDREN = 256
TERMINATE_GRACE_SECONDS = 1.0
POLL_INTERVAL_SECONDS = 0.05


class ConfigError(ValueError):
    """Raised when a multi-instance configuration is invalid."""


@dataclass(frozen=True)
class InstanceSpec:
    role: str
    count: int
    args: tuple


@dataclass(frozen=True)
class ChildCommand:
    role: str
    instance: int
    port: int
    uses_port: bool
    argv: tuple


def parse_config(path):
    """Parse and validate a multi-instance CSV file."""
    try:
        source = Path(path).expanduser().resolve(strict=True)
    except OSError as exc:
        raise ConfigError(f"unable to resolve configuration file {path}: {exc}") from exc

    if not source.is_file():
        raise ConfigError(f"configuration path is not a regular file: {source}")

    specs = []
    total_children = 0
    first_content_row = True

    try:
        with source.open("r", encoding="utf-8", newline="") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                line = raw_line.rstrip("\r\n")
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                try:
                    row = next(csv.reader([line], strict=True))
                except csv.Error as exc:
                    raise ConfigError(
                        f"{source}:{line_number}: invalid CSV: {exc}"
                    ) from exc

                if len(row) != 3:
                    raise ConfigError(
                        f"{source}:{line_number}: expected role,count,args"
                    )

                if first_content_row:
                    first_content_row = False
                    header = tuple(field.strip().lower() for field in row)
                    if header == ("role", "count", "args"):
                        continue

                role, count_text, args_text = row
                if not role.strip():
                    raise ConfigError(f"{source}:{line_number}: role must not be empty")

                try:
                    count = int(count_text.strip(), 10)
                except ValueError as exc:
                    raise ConfigError(
                        f"{source}:{line_number}: count must be a number"
                    ) from exc

                if count <= 0:
                    raise ConfigError(
                        f"{source}:{line_number}: count must be greater than zero"
                    )
                if total_children + count > MAX_CHILDREN:
                    raise ConfigError(
                        f"{source}:{line_number}: configuration exceeds the maximum "
                        f"of {MAX_CHILDREN} child processes"
                    )

                try:
                    child_args = tuple(shlex.split(args_text, posix=True))
                except ValueError as exc:
                    raise ConfigError(f"{source}:{line_number}: {exc}") from exc
                if not child_args:
                    raise ConfigError(f"{source}:{line_number}: args must not be empty")

                specs.append(InstanceSpec(role, count, child_args))
                total_children += count
    except OSError as exc:
        raise ConfigError(f"unable to read configuration file {source}: {exc}") from exc

    if not specs:
        raise ConfigError(f"{source}: no multi-instance rows found")
    return specs


def _expand(value, role, instance, base_port, instance_port, port):
    replacements = (
        ("{role}", role),
        ("{instance}", str(instance)),
        ("{base_port}", str(base_port)),
        ("{instance_port}", str(instance_port)),
        ("{port}", str(port)),
    )
    for placeholder, replacement in replacements:
        value = value.replace(placeholder, replacement)
    return value


def build_commands(specs, base_port):
    """Expand validated instance rows into concrete SIPp child commands."""
    if not 1 <= base_port <= 65535:
        raise ConfigError("base port must be between 1 and 65535")

    commands = []
    next_instance_by_role = {}

    for spec in specs:
        first_instance = next_instance_by_role.get(spec.role, 0)
        for offset in range(spec.count):
            instance = first_instance + offset
            port = base_port + len(commands)
            instance_port = base_port + instance
            if port > 65535 or instance_port > 65535:
                raise ConfigError("generated port allocation exceeds 65535")

            uses_port = any("{port}" in arg for arg in spec.args)
            argv = tuple(
                _expand(
                    arg,
                    spec.role,
                    instance,
                    base_port,
                    instance_port,
                    port,
                )
                for arg in spec.args
            )

            commands.append(
                ChildCommand(spec.role, instance, port, uses_port, argv)
            )

        next_instance_by_role[spec.role] = first_instance + spec.count

    return commands


def resolve_sipp_executable(requested=None):
    """Resolve the SIPp binary, preferring the installed sibling over PATH."""
    if requested:
        candidates = (os.path.expanduser(requested),)
    else:
        script_dir = Path(__file__).resolve().parent
        sibling_names = ("sipp.exe", "sipp") if os.name == "nt" else ("sipp",)
        candidates = tuple(str(script_dir / name) for name in sibling_names) + ("sipp",)

    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return str(Path(found).resolve())

    if requested:
        raise ConfigError(f"unable to find executable SIPp binary: {requested}")
    raise ConfigError(
        "unable to find SIPp executable; use --sipp PATH to specify it"
    )


_shutdown_signal = None


def _handle_signal(signum, _frame):
    global _shutdown_signal
    if _shutdown_signal is None:
        _shutdown_signal = signum


def _install_signal_handlers():
    saved = {}
    for name in ("SIGINT", "SIGTERM", "SIGHUP"):
        signum = getattr(signal, name, None)
        if signum is not None:
            saved[signum] = signal.signal(signum, _handle_signal)
    return saved


def _restore_signal_handlers(saved):
    for signum, handler in saved.items():
        signal.signal(signum, handler)


def _terminate_processes(processes):
    active = [process for process in processes if process.poll() is None]
    for process in active:
        try:
            process.terminate()
        except OSError:
            pass

    deadline = time.monotonic() + TERMINATE_GRACE_SECONDS
    while active and time.monotonic() < deadline:
        active = [process for process in active if process.poll() is None]
        if active:
            time.sleep(POLL_INTERVAL_SECONDS)

    for process in active:
        try:
            process.kill()
        except OSError:
            pass

    for process in active:
        try:
            process.wait()
        except ChildProcessError:
            pass


def _normalize_returncode(returncode):
    # Popen reports a signal-terminated child as -signum, while shells report
    # 128 + signum; 128 - returncode maps SIGSEGV (-11) to the usual 139.
    return 128 - returncode if returncode < 0 else returncode


def _format_command(executable, command):
    return " ".join(
        shlex.quote(arg) for arg in (executable, *command.argv)
    )


def run_commands(executable, commands):
    """Start all children, supervise them, and aggregate their exit status."""
    global _shutdown_signal
    _shutdown_signal = None
    saved_handlers = _install_signal_handlers()
    processes = []

    try:
        for command in commands:
            if _shutdown_signal is not None:
                _terminate_processes(processes)
                return 128 + _shutdown_signal

            port = f" port={command.port}" if command.uses_port else ""
            print(
                f"Starting {command.role}[{command.instance}]{port}: "
                f"{_format_command(executable, command)}",
                flush=True,
            )
            try:
                processes.append(subprocess.Popen([executable, *command.argv]))
            except OSError as exc:
                print(f"failed to start child: {exc}", file=sys.stderr)
                _terminate_processes(processes)
                return 1

        while any(process.poll() is None for process in processes):
            if _shutdown_signal is not None:
                _terminate_processes(processes)
                return 128 + _shutdown_signal
            time.sleep(POLL_INTERVAL_SECONDS)

        for process in processes:
            status = _normalize_returncode(process.returncode)
            if status:
                return status
        return 0
    finally:
        if any(process.poll() is None for process in processes):
            _terminate_processes(processes)
        _restore_signal_handlers(saved_handlers)


def _port_number(value):
    try:
        port = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("must be between 1 and 65535")
    return port


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="Launch coordinated SIPp processes from a CSV file."
    )
    parser.add_argument("config", type=Path, help="CSV configuration file")
    parser.add_argument(
        "--base-port",
        type=_port_number,
        default=DEFAULT_BASE_PORT,
        help=f"base port used by placeholders (default: {DEFAULT_BASE_PORT})",
    )
    parser.add_argument(
        "--sipp",
        metavar="PATH",
        help="SIPp executable (default: sibling sipp, then PATH)",
    )
    return parser


def main(argv=None):
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        specs = parse_config(args.config)
        commands = build_commands(specs, args.base_port)
        executable = resolve_sipp_executable(args.sipp)
    except ConfigError as exc:
        print(f"{parser.prog}: {exc}", file=sys.stderr)
        return 1

    return run_commands(executable, commands)


if __name__ == "__main__":
    sys.exit(main())

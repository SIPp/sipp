#!/bin/sh
# SIPp's regression tests against sipp-rs, with none skipped for what this
# host lacks: built with legacy-tls, for #0990's TLS 1.0 and 1.1, and run
# in a mount namespace whose /etc/hosts has localhost on ::1 first, for
# #0646. Usage: ./regress.sh [runtests arguments]
set -e
cd "$(dirname "$0")"
cargo build --release --locked --features legacy-tls --target-dir target/legacy
sipp=$PWD/target/legacy/release/sipp-rs
hosts=$(mktemp)
# runtests, run in parallel, shows nothing until all tests are done: it
# keeps each test's output and status in files under its mktemp -d, which
# is here, and the progress below reports from.
work=$(mktemp -d)
total=$(for t in ../regress/*; do test -x "$t/run" && echo "$t"; done | wc -l)
# Where the sipp-rs processes that outlive their test are, for a test that
# hangs.
stuck() {
    for pid in $(pgrep -x sipp-rs); do
        test "$(ps -o etimes= -p "$pid")" -ge 60 2>/dev/null || continue
        ps -o pid,stat,pcpu,etime,wchan:24,nlwp,args -p "$pid" >&2
        if command -v gdb >/dev/null; then
            sudo -n gdb -p "$pid" -batch -ex 'thread apply all bt' 2>&1 | tail -60 >&2
        fi
    done
}
progress() {
    last=-1 same=0
    while sleep 30; do
        n=0 running= failed=
        for out in "$work"/tmp.*/*.out; do
            test -e "$out" || continue
            ret=${out%.out}.ret
            if test -e "$ret"; then
                n=$((n+1))
                test "$(cat "$ret")" = 0 || failed="$failed $(basename "$out" .out)"
            else
                running="$running $(basename "$out" .out)"
            fi
        done
        echo "regress: $n of $total tests done; running:${running:- none}; not ok:${failed:- none}" >&2
        if test "$n" = "$last"; then same=$((same+1)); else last=$n same=0; fi
        test "$same" = 3 && stuck
    done
}
progress &
reporter=$!
trap 'kill $reporter 2>/dev/null; rm -rf "$hosts" "$work"' EXIT
{ printf '::1\tlocalhost\n'; cat /etc/hosts; } >"$hosts"
export TMPDIR=$work
if unshare -rm true 2>/dev/null; then
    unshare -rm sh -c 'mount --bind "$1" /etc/hosts && shift && SIPP="$0" ../regress/runtests "$@"' \
        "$sipp" "$hosts" "$@"
else
    echo "no mount namespace: #0646 may be skipped" >&2
    SIPP="$sipp" ../regress/runtests "$@"
fi

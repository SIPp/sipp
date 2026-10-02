#!/bin/sh
# Runs sipp-rs.exe from WSL with its Linux file paths in Windows' form, for
# SIPp's regress tests against the Windows build:
#   SIPP=$PWD/wsl-sipp.sh ../regress/runtests -j 1
# (SIPP_EXE: the exe, by default the one windows.sh builds). An argument
# that is an absolute path to a file, or to one in a directory that is
# there, goes as `wslpath -w` has it; others, as "-ws_path /sip", as they are.
exe=${SIPP_EXE:-$(dirname "$(readlink -f "$0")")/target/x86_64-pc-windows-gnullvm/release/sipp-rs.exe}
n=$#
while [ $n -gt 0 ]; do
    a=$1
    shift
    case $a in
        /*)
            dir=$(dirname "$a")
            if [ -e "$a" ] || { [ "$dir" != / ] && [ -d "$dir" ]; }; then
                a=$(wslpath -w "$a")
            fi
            ;;
    esac
    set -- "$@" "$a"
    n=$((n - 1))
done
exec "$exe" "$@"

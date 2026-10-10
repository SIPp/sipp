#!/bin/sh
# Build sipp-rs.exe for Windows (x86_64, UCRT) from Linux, with llvm-mingw
# (https://github.com/mstorsjo/llvm-mingw): LLVM_MINGW is its directory.
# The exe needs no DLL beyond Windows 10's own. Usage: ./windows.sh [cargo args]
set -e
: "${LLVM_MINGW:?set LLVM_MINGW to an llvm-mingw directory}"
T=x86_64-pc-windows-gnullvm
export CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_LINKER="$LLVM_MINGW/bin/x86_64-w64-mingw32-clang"
export CC_x86_64_pc_windows_gnullvm="$LLVM_MINGW/bin/x86_64-w64-mingw32-clang"
export AR_x86_64_pc_windows_gnullvm="$LLVM_MINGW/bin/llvm-ar"
# Static: no libunwind.dll to ship. rustc passes clang a -no-pie it ignores.
export CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-Wno-unused-command-line-argument"
cd "$(dirname "$0")"
exec cargo build --release --target $T -p sipp-rs "$@"

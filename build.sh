#!/bin/sh

set -e  # abort on error

SRC_DIR=$(dirname "$0")

if test -z "$*"; then
    echo "build.sh: Please specify configure options," \
        "--none for defaults, or --full for all" >&2
    exit 1
elif test "$*" = "--help" || test "$*" = "-h"; then
    echo "build.sh: Please specify configure options," \
        "--none for defaults, or --full for all" >&2
    exit 1
fi

if test "$*" = "--none"; then
    cmake $SRC_DIR -DUSE_GSL=0 -DUSE_SCTP=0 -DUSE_PCAP=0
elif test "$*" = "--common"; then
    cmake $SRC_DIR -DUSE_GSL=1 -DUSE_PCAP=1 -DUSE_SCTP=0
elif test "$*" = "--full"; then
    cmake $SRC_DIR -DUSE_GSL=1 -DUSE_PCAP=1 -DUSE_SCTP=1
else
    # Debug build? Add -DDEBUG=1
    # Adjusted SIP max size? Add -DSIPP_MAX_MSG_SIZE=262144
    cmake $SRC_DIR "$@"
fi

if test -f build.ninja; then
    MAKE=ninja
else
    MAKE=`which gmake make 2>/dev/null | head -n1`  # prefer GNU make
    test -z "$MAKE" && echo "No (g)make found" >&2 && exit 1
    CPUCOUNT=$(nproc --all 2>/dev/null || echo 1)
    MAKEFLAGS="-j$CPUCOUNT"
fi
# For git checkout, run unit tests.
if test -e $SRC_DIR/gtest/.git; then
	"$MAKE" $MAKEFLAGS sipp_unittest
	./sipp_unittest
fi

# You want verbose or NOISY_BUILD? Use VERBOSE=1
"$MAKE" $MAKEFLAGS

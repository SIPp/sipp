#!/bin/sh
set -e  # abort on error

MAKE=`which gmake make 2>/dev/null | head -n1`  # prefer GNU make
test -z "$MAKE" && echo "No (g)make found" >&2 && exit 1
CPUCOUNT=$(nproc --all 2>/dev/null || echo 1)
MAKEFLAGS="-j$CPUCOUNT"

if test -z "$*"; then
    echo "build.sh: Please specify configure options," \
        "--none for defaults, or --full for all" >&2
    exit 1
elif test "$*" = "--help" || test "$*" = "-h"; then
    ./configure --help
    exit 1
fi

./autogen.sh

if test "$*" = "--none"; then
    ./configure
elif test "$*" = "--full"; then
    ./configure \
        --with-gsl \
        --with-openssl \
        --with-pcap \
        --with-rtpstream \
        --with-sctp
else
    ./configure "$@"
fi

# For git checkout, run unit tests.
if test -e gtest/.git; then
	"$MAKE" $MAKEFLAGS sipp_unittest
	./sipp_unittest
fi

"$MAKE" $MAKEFLAGS

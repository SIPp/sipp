#!/bin/sh
set -e  # abort on error

MAKE=`which gmake make 2>/dev/null | head -n1`  # prefer GNU make
test -z "$MAKE" && echo "No (g)make found" >&2 && exit 1

git submodule update --init
autoreconf -vifs

if test "$*" = "--full"; then
    ./configure \
        --with-gsl \
        --with-openssl \
        --with-pcap \
        --with-rtpstream \
        --with-sctp
else
    ./configure "$@"
fi

"$MAKE" clean

"$MAKE" sipp_unittest
./sipp_unittest

"$MAKE"

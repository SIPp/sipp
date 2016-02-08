#!/bin/sh
set -e  # abort on error

MAKE=`which gmake make 2>/dev/null | head -n1`  # prefer GNU make
test -z "$MAKE" && echo "No (g)make found" >&2 && exit 1

# Optional: for git checkout only.
if which git >/dev/null && test -d .git; then
	git submodule update --init
fi

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

# Optional: for git checkout only.
if test -f gtest/gtest.h; then
	"$MAKE" sipp_unittest
	./sipp_unittest
fi

"$MAKE"

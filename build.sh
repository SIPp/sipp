#!/bin/sh
set -e  # abort on error

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

make clean

make sipp_unittest
./sipp_unittest

make

#!/bin/sh
git submodule update --init &&
autoreconf -vifs &&
./configure "$@" &&
make sipp_unittest &&
./sipp_unittest &&
make

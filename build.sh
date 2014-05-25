git submodule update --init &&
touch configure.ac aclocal.m4 configure Makefile.am Makefile.in &&
./configure $@ &&
make sipp_unittest &&
./sipp_unittest &&
make

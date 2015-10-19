@AM_GIT_VERSION@

bin_PROGRAMS = sipp

TESTS = sipp_unittest

check_PROGRAMS = $(TESTS)

AM_CFLAGS=-I$(srcdir)/include -Wall -pedantic
AM_CXXFLAGS=-I$(srcdir)/include -Wall -pedantic

CLEANFILES =
EXTRA_DIST = \
	$(srcdir)/src/fortune.cpp \
	$(srcdir)/LICENSE.txt \
	$(srcdir)/README.md \
	$(srcdir)/THANKS \
	$(srcdir)/sipp.dtd \
	$(srcdir)/cpplint.py

if HAVE_OPENSSL
DEFS += -DUSE_OPENSSL
ssl_incl = \
	include/sslcommon.h
ssl_SOURCES = \
	$(ssl_incl) \
	src/sslinit.c \
	src/sslthreadsafe.c
endif

if HAVE_PCAP
DEFS += -DPCAPPLAY
pcap_incl = \
	include/prepare_pcap.h \
	include/send_packets.h
pcap_SOURCES = \
	$(pcap_incl) \
	src/prepare_pcap.c \
	src/send_packets.c
endif

if HAVE_RTP
DEFS += -DRTP_STREAM
rtp_SOURCES = \
	src/rtpstream.cpp \
	include/rtpstream.hpp
endif

if HAVE_SCTP
DEFS += -DUSE_SCTP
endif

if HAVE_GSL
DEFS += -DHAVE_GSL
endif

if HAVE_EPOLL
DEFS += -DHAVE_EPOLL
endif

common_incl = \
	include/comp.h \
	include/infile.hpp \
	include/listener.hpp \
	include/logger.hpp \
	include/md5.h \
	include/message.hpp \
	include/milenage.h \
	include/call_generation_task.hpp \
	include/ratetask.hpp \
	include/reporttask.hpp \
	include/rijndael.h \
	include/scenario.hpp \
	include/sip_parser.hpp \
	include/screen.hpp \
	include/socket.hpp \
	include/socketowner.hpp \
	include/stat.hpp \
	include/strings.hpp \
	include/task.hpp \
	include/time.hpp \
	include/variables.hpp \
	include/watchdog.hpp \
	include/xp_parser.h \
	include/actions.hpp \
	include/call.hpp \
	include/auth.hpp \
	include/deadcall.hpp

common_SOURCES = \
	src/actions.cpp \
	src/auth.cpp \
	src/comp.c \
	src/call.cpp \
	src/deadcall.cpp \
	src/infile.cpp \
	src/listener.cpp \
	src/logger.cpp \
	src/md5.c \
	src/message.cpp \
	src/milenage.c \
	src/call_generation_task.cpp \
	src/ratetask.cpp \
	src/reporttask.cpp \
	src/rijndael.c \
	src/scenario.cpp \
	src/sip_parser.cpp \
	src/screen.cpp \
	src/socket.cpp \
	src/socketowner.cpp \
	src/stat.cpp \
	src/strings.cpp \
	src/task.cpp \
	src/time.cpp \
	src/variables.cpp \
	src/watchdog.cpp \
	src/xp_parser.c \
	$(common_incl) \
	$(ssl_SOURCES) \
	$(pcap_SOURCES) \
	$(rtp_SOURCES)

sipp_SOURCES = \
	$(common_SOURCES) \
	src/sipp.cpp \
	include/sipp.hpp

sipp_CFLAGS = $(AM_CFLAGS) @GSL_CFLAGS@
sipp_CXXFLAGS = $(AM_CXXFLAGS) @GSL_CXXFLAGS@
sipp_LDADD = @LIBOBJS@ @GSL_LIBS@

# call.cpp and sipp.cpp use version.h; see AM_GIT_VERSION.
src/call.cpp: include/version.h
src/sipp.cpp: include/version.h

gtest_SOURCES = \
	gtest/src/gtest-death-test.cc \
	gtest/src/gtest-filepath.cc \
	gtest/src/gtest-internal-inl.h \
	gtest/src/gtest-port.cc \
	gtest/src/gtest-printers.cc \
	gtest/src/gtest-test-part.cc \
	gtest/src/gtest-typed-test.cc \
	gtest/src/gtest.cc \
	gmock/src/gmock-internal-utils.cc \
	gmock/src/gmock-matchers.cc

sipp_unittest_SOURCES = \
	$(common_SOURCES) \
	src/sipp_unittest.cpp \
	src/xp_parser_ut.cpp \
	$(gtest_SOURCES)

sipp_unittest_CFLAGS = $(AM_CFLAGS) -DGTEST=1 \
	-I$(srcdir)/gtest/include \
	-I$(srcdir)/gmock/include \
	-I$(srcdir)/gtest \
	-I$(srcdir)/gmock \
	@GSL_CFLAGS@

sipp_unittest_CXXFLAGS = $(AM_CXXFLAGS) -DGTEST=1 \
	-I$(srcdir)/gtest/include \
	-I$(srcdir)/gmock/include \
	-I$(srcdir)/gtest \
	-I$(srcdir)/gmock \
	@GSL_CXXFLAGS@

sipp_unittest_LDADD = @LIBOBJS@ @GSL_LIBS@

if HAVE_HELP2MAN
man_MANS = sipp.1
CLEANFILES += $(man_MANS)

sipp.1: ./sipp $(sipp_SOURCES)
	$(HELP2MAN) --output=$@ -v "-v" --no-info \
		--name='SIP testing tool and traffic generator' \
		./sipp
else
sipp.1:
	@echo "Warning: help2man not available, no man page is created."
endif

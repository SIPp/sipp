bin_PROGRAMS = sipp

TESTS = sipp_unittest

noinst_PROGRAMS = $(TESTS)

EXTRA_DIST = fortune.cpp pcap tools LICENSE.txt MEDIA.txt README.txt THANKS sipp.dtd

if HAVE_OPENSSL
DEFS += -D_USE_OPENSSL
ssl_SOURCES = sslcommon.h \
	      sslinit.c \
	      sslthreadsafe.c
endif

if HAVE_PCAP
DEFS += -DPCAPPLAY
pcap_SOURCES = prepare_pcap.c \
	       prepare_pcap.h \
	       send_packets.c \
	       send_packets.h
endif

if HAVE_SCTP
DEFS += -DUSE_SCTP
endif

if HAVE_GSL
DEFS += -DHAVE_GSL
endif

common_SOURCES = actions.cpp \
	       auth.c \
	       comp.c \
	       comp.h \
	       call.cpp \
	       deadcall.cpp \
	       infile.cpp \
	       infile.hpp \
	       listener.cpp \
	       listener.hpp \
	       logger.cpp \
	       logger.hpp \
	       md5.c \
	       md5.h \
	       message.cpp \
	       message.hpp \
	       milenage.c \
	       milenage.h \
	       opentask.cpp \
	       opentask.hpp \
	       reporttask.cpp \
	       reporttask.hpp \
	       rijndael.c \
	       rijndael.h \
	       scenario.cpp \
	       scenario.hpp \
	       sip_parser.cpp \
	       sip_parser.hpp \
	       screen.cpp \
	       screen.hpp \
	       socket.cpp \
	       socket.hpp \
	       socketowner.cpp \
	       socketowner.hpp \
	       stat.cpp \
	       stat.hpp \
	       strings.cpp \
	       strings.hpp \
	       task.cpp \
	       task.hpp \
	       time.cpp \
	       time.hpp \
	       variables.cpp \
	       variables.hpp \
	       watchdog.cpp \
	       watchdog.hpp \
	       xp_parser.c \
	       xp_parser.h \
	       $(ssl_SOURCES) \
	       $(pcap_SOURCES)

sipp_SOURCES = $(common_SOURCES) \
	       sipp.cpp \
	       sipp.hpp

sipp_CFLAGS = $(AM_CFLAGS) @GSL_CFLAGS@
sipp_CXXFLAGS = $(AM_CXXFLAGS) @GSL_CXXFLAGS@
sipp_LDADD = @LIBOBJS@ @GSL_LIBS@

sipp_unittest_SOURCES = $(common_SOURCES) sipp_unittest.cpp

sipp_unittest_CFLAGS = $(AM_CFLAGS) @GSL_CFLAGS@
sipp_unittest_CXXFLAGS = $(AM_CXXFLAGS) @GSL_CXXFLAGS@
sipp_unittest_LDADD = @LIBOBJS@ @GSL_LIBS@

bin_PROGRAMS = sipp

TESTS = sipp_unittest

noinst_PROGRAMS = $(TESTS)

AM_CFLAGS=-I./include
AM_CPPFLAGS=$(AM_CFLAGS)

EXTRA_DIST = src/fortune.cpp pcap LICENSE.txt README.txt THANKS sipp.dtd sipp.1 cpplint.py auto-generate-files.sh

if HAVE_OPENSSL
DEFS += -D_USE_OPENSSL
ssl_incl = include/sslcommon.h
ssl_SOURCES = $(ssl_incl) \
              src/sslinit.c \
	      src/sslthreadsafe.c
endif

if HAVE_PCAP
DEFS += -DPCAPPLAY
pcap_incl = include/prepare_pcap.h \
	       include/send_packets.h
pcap_SOURCES = $(pcap_incl) \
               src/prepare_pcap.c \
	       src/send_packets.c
endif

if HAVE_RTP
DEFS += -DRTP_STREAM
rtp_SOURCES = src/rtpstream.cpp include/rtpstream.hpp
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

common_incl = include/comp.h \
	        include/infile.hpp \
	        include/listener.hpp \
	        include/logger.hpp \
	        include/md5.h \
	        include/message.hpp \
	        include/milenage.h \
	        include/opentask.hpp \
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
	        include/deadcall.hpp

common_SOURCES = src/actions.cpp \
	       src/auth.c \
	       src/comp.c \
	       src/call.cpp \
	       src/deadcall.cpp \
	       src/infile.cpp \
	       src/listener.cpp \
	       src/logger.cpp \
	       src/md5.c \
	       src/message.cpp \
	       src/milenage.c \
	       src/opentask.cpp \
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

sipp_SOURCES = $(common_SOURCES) \
	       src/sipp.cpp \
	       include/sipp.hpp

sipp_CFLAGS = $(AM_CFLAGS) @GSL_CFLAGS@
sipp_CXXFLAGS = $(AM_CXXFLAGS) @GSL_CXXFLAGS@
sipp_LDADD = @LIBOBJS@ @GSL_LIBS@

sipp_unittest_SOURCES = $(common_SOURCES) src/sipp_unittest.cpp

sipp_unittest_CFLAGS = $(AM_CFLAGS) @GSL_CFLAGS@
sipp_unittest_CXXFLAGS = $(AM_CXXFLAGS) @GSL_CXXFLAGS@
sipp_unittest_LDADD = @LIBOBJS@ @GSL_LIBS@

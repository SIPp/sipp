bin_PROGRAMS = sipp

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

if HAVE_UNITTEST
DEFS += -DSIPP_UNITTEST
endif

if HAVE_SCTP
DEFS += -DUSE_SCTP
endif

sipp_SOURCES = actions.cpp \
	       auth.c \
	       comp.c \
	       comp.h \
	       call.cpp \
	       deadcall.cpp \
	       infile.cpp \
	       infile.hpp \
	       listener.cpp \
	       listener.hpp \
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
	       screen.cpp \
	       screen.hpp \
	       sipp.cpp \
	       sipp.hpp \
	       socketowner.cpp \
	       socketowner.hpp \
	       stat.cpp \
	       stat.hpp \
	       task.cpp \
	       task.hpp \
	       variables.cpp \
	       variables.hpp \
	       watchdog.cpp \
	       watchdog.hpp \
	       xp_parser.c \
	       xp_parser.h \
	       $(ssl_SOURCES) \
	       $(pcap_SOURCES)

sipp_LDADD = @LIBOBJS@


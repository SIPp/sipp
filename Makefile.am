bin_PROGRAMS = sipp

if HAVE_OPENSSL
DEFS += -D_USE_OPENSSL
ssl_SOURCES = sslinit.c \
	      sslthreadsafe.c
endif

if HAVE_PCAP
DEFS += -DPCAPPLAY
pcap_SOURCES = prepare_pcap.c \
	       send_packets.c
endif

if HAVE_UNITTEST
DEFS += -DSIPP_UNITTEST
endif

if HAVE_SCTP
DEFS += -DUSE_SCTP
endif

sipp_SOURCES = comp.c \
	       xp_parser.c \
	       actions.cpp \
	       call.cpp \
	       deadcall.cpp \
	       infile.cpp \
	       listener.cpp \
	       message.cpp \
	       opentask.cpp \
	       reporttask.cpp \
	       scenario.cpp \
	       screen.cpp \
	       sipp.cpp \
	       socketowner.cpp \
	       stat.cpp \
	       task.cpp \
	       variables.cpp \
	       watchdog.cpp \
		   md5.c \
           auth.c \
	       milenage.c \
	       rijndael.c \
	       $(ssl_SOURCES) \
	       $(pcap_SOURCES)

sipp_LDADD = @LIBOBJS@

#	       fortune.cpp

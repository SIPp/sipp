# ======================== initialization ===============================

AC_INIT([SIPp], [3.4.0], [sipp-users@lists.sourceforge.net], [sipp])

AC_CANONICAL_TARGET

AC_CONFIG_SRCDIR([src/sipp.cpp])
AC_CONFIG_HEADERS([include/config.h])
AM_INIT_AUTOMAKE([foreign])

AC_ARG_WITH([openssl],AC_HELP_STRING([--with-openssl], [build with OpenSSL support]), [openssl="$withval"],[openssl="no"])
AC_ARG_WITH([pcap],AC_HELP_STRING([--with-pcap], [build with pcap support]), [pcap="$withval"],[pcap="no"])
AC_ARG_WITH([rtpstream],AC_HELP_STRING([--with-rtpstream], [build with RTP streaming support]), [rtp="$withval"],[rtp="yes"])
AC_ARG_WITH([sctp],AC_HELP_STRING([--with-sctp], [build with SCTP support]), [sctp="$withval"],[sctp="no"])
AC_ARG_WITH([gsl],AC_HELP_STRING([--with-gsl], [build with GSL (GNU Scientific Library) support]), [gsl="$withval"],[gsl="no"])

# ==================== basic compiler settings ==========================

AC_PROG_CC
AC_PROG_CXX
AC_HEADER_STDC

case "$host" in
	*-linux*)
		CFLAGS="$CFLAGS -D__LINUX"
		CPPFLAGS="$CPPFLAGS -D__LINUX"
		;;
	*-darwin*)
		CFLAGS="$CFLAGS -D__DARWIN"
		CPPFLAGS="$CPPFLAGS -D__DARWIN"
		;;
	*-hpux*)
		CFLAGS="$CFLAGS -D__HPUX"
		CPPFLAGS="$CPPFLAGS -D__HPUX"
		;;
	*-freebsd*)
		CFLAGS="$CFLAGS -D__LINUX -I/usr/local/include"
		CPPFLAGS="$CPPFLAGS -D__LINUX -I/usr/local/include"
        LDFLAGS="$LDFLAGS -L/usr/local/lib"
		;;
	*-sunos*)
		CFLAGS="$CFLAGS -D__SUNOS"
		CPPFLAGS="$CPPFLAGS -D__SUNOS"
		;;
	*-cygwin*)
		CFLAGS="$CFLAGS -D__CYGWIN -I /usr/include/ncurses -I /usr/lib/WpdPack/Include -I /usr/include/SctpDrv"
		CPPFLAGS="$CPPFLAGS -D__CYGWIN -I /usr/include/ncurses -I /usr/lib/WpdPack/Include -I /usr/include/SctpDrv"
        LDFLAGS="$LDFLAGS -L /usr/lib/WpdPack/Lib -L /usr/lib/SctpDrv"
		;;
	*-tru64*)
		CFLAGS="$CFLAGS -D__OSF1"
		CPPFLAGS="$CPPFLAGS -D__OSF1"
		;;
esac

# ==================== checks for libraries =============================
AC_CHECK_LIB(curses,initscr,,[AC_MSG_ERROR([ncurses library missing])])
AC_CHECK_LIB(pthread, pthread_mutex_init, THREAD_LIBS="-lpthread",
               AC_MSG_ERROR(pthread library needed!))

# For Linux and SunOS
AC_SEARCH_LIBS([dlopen], [dl])
AC_SEARCH_LIBS([dlerror], [dl])
AC_SEARCH_LIBS([dlsym], [dl])

# For SunOS
AC_SEARCH_LIBS([inet_addr], [nsl])
AC_SEARCH_LIBS([inet_ntoa], [nsl])

AC_SEARCH_LIBS([pthread_mutex_init], [pthread])
AC_SEARCH_LIBS([pthread_mutex_destroy], [pthread])
AC_SEARCH_LIBS([pthread_mutex_lock], [pthread])
AC_SEARCH_LIBS([pthread_mutex_unlock], [pthread])
AC_SEARCH_LIBS([pthread_self], [pthread])
AC_SEARCH_LIBS([pthread_cancel], [pthread])
AC_SEARCH_LIBS([pthread_join], [pthread])
AC_SEARCH_LIBS([pthread_attr_init], [pthread])
AC_SEARCH_LIBS([pthread_attr_setstacksize], [pthread])
AC_SEARCH_LIBS([pthread_create], [pthread])
AC_SEARCH_LIBS([pthread_attr_destroy], [pthread])
AC_SEARCH_LIBS([pthread_setschedparam], [pthread])
AC_SEARCH_LIBS([pthread_setcancelstate], [pthread])
AC_SEARCH_LIBS([pthread_setcanceltype], [pthread])
AC_SEARCH_LIBS([pthread_exit], [pthread])
AC_SEARCH_LIBS([pthread_sigmask], [pthread])
#AC_SEARCH_LIBS([pthread_cleanup_push], [pthread]) <- macro
#AC_SEARCH_LIBS([pthread_cleanup_pop], [pthread]) <- macro

AC_SEARCH_LIBS([floor], [m])
AC_SEARCH_LIBS([pow], [m])

# For SunOS
AC_SEARCH_LIBS([htons], [socket])
AC_SEARCH_LIBS([ntohs], [socket])
AC_SEARCH_LIBS([bind], [socket])
AC_SEARCH_LIBS([freeaddrinfo], [socket])
AC_SEARCH_LIBS([getaddrinfo], [socket])
AC_SEARCH_LIBS([listen], [socket])
AC_SEARCH_LIBS([recvfrom], [socket])
AC_SEARCH_LIBS([shutdown], [socket])

# For Linux, SunOS and Cygwin
#AC_CHECK_LIB(stdc++,main,,[AC_MSG_ERROR([stdc++ library missing])])

# Conditional build with OpenSSL
if test "$openssl" = 'yes'; then
	AC_CHECK_HEADERS([openssl/md5.h],,[AC_MSG_ERROR([<openssl/md5.h> header missing])])
	AC_CHECK_HEADERS([openssl/bio.h],,[AC_MSG_ERROR([<openssl/bio.h> header missing])])
	AC_CHECK_HEADERS([openssl/err.h],,[AC_MSG_ERROR([<openssl/err.h> header missing])])
	AC_CHECK_HEADERS([openssl/rand.h],,[AC_MSG_ERROR([<openssl/rand.h> header missing])])
	AC_CHECK_HEADERS([openssl/ssl.h],,[AC_MSG_ERROR([<openssl/ssl.h> header missing])])
	AC_CHECK_HEADERS([openssl/x509v3.h],,[AC_MSG_ERROR([<openssl/x509v3.h> header missing])])
	AC_CHECK_LIB([ssl], [SSL_library_init],,[AC_MSG_ERROR([ssl library missing])])
	AC_CHECK_LIB([crypto], [CRYPTO_num_locks],,[AC_MSG_ERROR([crypto library missing])])
fi
# For Makefile.am
AM_CONDITIONAL(HAVE_OPENSSL, test "$openssl" = "yes")

# Conditional build with SCTP
if test "$sctp" = 'yes'; then
	AC_CHECK_HEADERS([netinet/sctp.h],,[AC_MSG_WARN([<netinet/sctp.h> header missing, but this is acceptable on Mac OS X Lion])])
	AC_SEARCH_LIBS([sctp_send],[sctp sctpsp],,[AC_MSG_ERROR([SCTP library missing])])
	AC_SEARCH_LIBS([sctp_freepaddrs],[sctp sctpsp],,[AC_MSG_ERROR([SCTP library missing])])
	AC_SEARCH_LIBS([sctp_bindx],[sctp sctpsp],,[AC_MSG_ERROR([SCTP library missing])])
	AC_SEARCH_LIBS([sctp_recvmsg],[sctp sctpsp],,[AC_MSG_ERROR([SCTP library missing])])
fi
# For Makefile.am
AM_CONDITIONAL(HAVE_SCTP, test "$sctp" = "yes")

# Conditional build with pcap
if test "$pcap" = 'yes'; then
	AC_CHECK_HEADERS([pcap.h],,[AC_MSG_ERROR([<pcap.h> header missing])])
	AC_SEARCH_LIBS([pcap_open_offline],[pcap wpcap],,[AC_MSG_ERROR([pcap library missing])])
	AC_SEARCH_LIBS([pcap_next],[pcap wpcap],,[AC_MSG_ERROR([pcap library missing])])
	AC_SEARCH_LIBS([pcap_next_ex],[pcap wpcap],,[AC_MSG_ERROR([pcap library missing])])
	AC_SEARCH_LIBS([pcap_close],[pcap wpcap],,[AC_MSG_ERROR([pcap library missing])])
fi
# For Makefile.am
AM_CONDITIONAL(HAVE_PCAP, test "$pcap" = "yes")

AM_CONDITIONAL(HAVE_RTP, test "$rtp" = "yes")

# Conditional build with pcap
if test "$gsl" = 'yes'; then
	AC_CHECK_HEADERS([gsl/gsl_randist.h],,[AC_MSG_ERROR([<gsl/gsl_randist.h> header missing])])
	AC_CHECK_HEADERS([gsl/gsl_rng.h],,[AC_MSG_ERROR([<gsl/gsl_rng.h> header missing])])
	AC_CHECK_HEADERS([gsl/gsl_cdf.h],,[AC_MSG_ERROR([<gsl/gsl_cdf.h> header missing])])
	AC_CHECK_LIB([m],[cos])
	AC_CHECK_LIB([gslcblas], [cblas_dgemm])
	AC_CHECK_LIB([gsl], [gsl_rng_alloc],
		     [
		      GSL_CFLAGS=`pkg-config gsl --cflags`
		      GSL_CXXFLAGS=`pkg-config gsl --cflags`
		      GSL_LIBS=`pkg-config gsl --libs`
		      AC_SUBST([GSL_CFLAGS])
		      AC_SUBST([GSL_CXXFLAGS])
		      AC_SUBST([GSL_LIBS])
		      ]
		     ,[AC_MSG_ERROR([gsl library missing])])
fi
# For Makefile.am
AM_CONDITIONAL(HAVE_GSL, test "$gsl" = "yes")

AX_HAVE_EPOLL([AX_CONFIG_FEATURE_ENABLE(epoll)],
    [AX_CONFIG_FEATURE_DISABLE(epoll)])
AX_CONFIG_FEATURE([epoll], [This platform supports epoll(7)],
    [HAVE_EPOLL], [This platform supports epoll(7).],
    [epoll="yes"], [epoll="no"])

AM_CONDITIONAL(HAVE_EPOLL, test "$epoll" = "yes")
# ==================== checks for header files ==========================

AC_FUNC_ALLOCA
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# ===== checks for typedefs, structures and compiler characteristics ====

AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# ==================== checks for library functions =====================

AC_FUNC_FORK
#AC_FUNC_MALLOC
#AC_FUNC_REALLOC
#AC_FUNC_STRTOD
AC_CHECK_FUNCS([alarm dup2 floor gethostname gettimeofday inet_ntoa memmove memset pow regcomp socket sqrt strcasecmp strchr strcspn strdup strerror strncasecmp strrchr strstr strtol strtoul strtoull])

# ==================== generate files ===================================

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA
 *
 *  Author : Richard GAYRAUD - 04 Nov 2003
 *           From Hewlett Packard Company.
 */

#ifndef __SIPP__
#define __SIPP__

/* Std C includes */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#ifdef USE_SCTP
#ifndef __DARWIN
#include <netinet/sctp.h>
#endif
#endif
#include <sys/time.h>
#include <sys/poll.h>
#ifdef HAVE_EPOLL
#include <sys/epoll.h>
#endif
#include <sys/resource.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <ctype.h>
#include <signal.h>
#include <time.h>
#include <limits.h>
#include <vector>
#include <string>
#include <map>
#include <set>
#include <math.h>
#ifndef __SUNOS
#include <curses.h>
#else
#include <stdarg.h>
#endif

#if defined(__HPUX) || defined(__SUNOS)
#include <alloca.h>
#endif

/* Sipp includes */

#include "xp_parser.h"
#include "scenario.hpp"
#include "screen.hpp"
#include "task.hpp"
#include "listener.hpp"
#include "socketowner.hpp"
#include "socket.hpp"
#include "call.hpp"
#include "comp.h"
#include "variables.hpp"
#include "stat.hpp"
#include "actions.hpp"
#include "infile.hpp"
#include "call_generation_task.hpp"
#include "reporttask.hpp"
#include "ratetask.hpp"
#include "watchdog.hpp"
/* Open SSL stuff */
#ifdef _USE_OPENSSL
#include "sslcommon.h"
#endif

/*
 * If this files is included in the Main, then extern definitions
 * are removed, and the _DEFAULT macro becomes '= value;'. Else
 * extern definition does not contain default values assignment
 */

#ifdef GLOBALS_FULL_DEFINITION
#define extern
#define _DEFVAL(value) = value
#else
#define _DEFVAL(value)
#endif

/************************** Constants **************************/

#define T_UDP                      0
#define T_TCP                      1
#define T_TLS                      2
#define T_SCTP                     3

#ifdef _USE_OPENSSL
#define DEFAULT_TLS_CERT           ((char *)"cacert.pem")
#define DEFAULT_TLS_KEY            ((char *)"cakey.pem")
#define DEFAULT_TLS_CRL            ((char *)"")
#endif

#define TRANSPORT_TO_STRING(p)     ((p==T_TCP) ? "TCP" : ((p==T_TLS)? "TLS" : ((p==T_UDP)? "UDP" : "SCTP")))

#define SIPP_MAXFDS                65536
#define SIPP_MAX_MSG_SIZE          65536

#define MSG_RETRANS_FIRST          0
#define MSG_RETRANS_RETRANSMISSION 1
#define MSG_RETRANS_NEVER          2

#define DISPLAY_STAT_SCREEN        1
#define DISPLAY_REPARTITION_SCREEN 2
#define DISPLAY_SCENARIO_SCREEN    3
#define DISPLAY_VARIABLE_SCREEN    4
#define DISPLAY_TDM_MAP_SCREEN     5
#define DISPLAY_SECONDARY_REPARTITION_SCREEN 6

#define MAX_RECV_LOOPS_PER_CYCLE   1000
#define MAX_SCHED_LOOPS_PER_CYCLE  1000
#define NB_UPDATE_PER_CYCLE        1

#define MAX_PATH                   250

#define MAX_PEER_SIZE              4096  /* 3pcc extended mode: max size of peer names */
#define MAX_LOCAL_TWIN_SOCKETS     10    /*3pcc extended mode:max number of peers from which
cmd messages are received */

/******************** Default parameters ***********************/

#define DEFAULT_RATE                 10.0
#define DEFAULT_RATE_SCALE           1.0
#define DEFAULT_RATE_PERIOD_MS       1000
#define DEFAULT_TRANSPORT            T_UDP
#define DEFAULT_PORT                 5060
#define DEFAULT_MEDIA_PORT           6000
#define DEFAULT_3PCC_PORT            6060
#define DEFAULT_SERVICE              ((char *)"service")
#define DEFAULT_AUTH_PASSWORD        ((char *)"password")
#define DEFAULT_REPORT_FREQ          1000
#define DEFAULT_RATE_INCR_FREQ       0
#define DEFAULT_REPORT_FREQ_DUMP_LOG 60000
#define DEFAULT_TIMER_RESOLUTION     1
#define DEFAULT_FREQ_DUMP_RTT        200
#define DEFAULT_MAX_MULTI_SOCKET     50000
#define DEFAULT_CTRL_SOCKET_PORT     8888
#define DEFAULT_DEADCALL_WAIT        33000

#define DEFAULT_BEHAVIOR_NONE        0
#define DEFAULT_BEHAVIOR_BYE         1
#define DEFAULT_BEHAVIOR_ABORTUNEXP  2
#define DEFAULT_BEHAVIOR_PINGREPLY   4

#define DEFAULT_BEHAVIOR_ALL         (DEFAULT_BEHAVIOR_BYE | DEFAULT_BEHAVIOR_ABORTUNEXP | DEFAULT_BEHAVIOR_PINGREPLY)

#ifdef RTP_STREAM
#define DEFAULT_MIN_RTP_PORT         8192
#define DEFAULT_MAX_RTP_PORT         65535
#define DEFAULT_RTP_PAYLOAD          8
#define DEFAULT_RTP_THREADTASKS      20
#endif

/************ User controls and command line options ***********/

extern int                duration                _DEFVAL(0);
extern double             rate                    _DEFVAL(DEFAULT_RATE);
extern double             rate_scale              _DEFVAL(DEFAULT_RATE_SCALE);
extern int                rate_increase           _DEFVAL(0);
extern int                rate_max                _DEFVAL(0);
extern unsigned long      rate_increase_freq      _DEFVAL(DEFAULT_RATE_INCR_FREQ);
extern bool               rate_quit               _DEFVAL(true);
extern int                users                   _DEFVAL(-1);
extern int                rate_period_ms          _DEFVAL(DEFAULT_RATE_PERIOD_MS);
extern int                sleeptime               _DEFVAL(0);
extern unsigned long      defl_recv_timeout       _DEFVAL(0);
extern unsigned long      defl_send_timeout       _DEFVAL(0);
extern unsigned long      global_timeout          _DEFVAL(0);
extern int                transport               _DEFVAL(DEFAULT_TRANSPORT);
extern bool               retrans_enabled         _DEFVAL(1);
extern int                rtcheck                 _DEFVAL(RTCHECK_FULL);
extern int                max_udp_retrans         _DEFVAL(UDP_MAX_RETRANS);
extern int                max_invite_retrans      _DEFVAL(UDP_MAX_RETRANS_INVITE_TRANSACTION);
extern int                max_non_invite_retrans  _DEFVAL(UDP_MAX_RETRANS_NON_INVITE_TRANSACTION);
extern unsigned long      default_behaviors       _DEFVAL(DEFAULT_BEHAVIOR_ALL);
extern unsigned long      deadcall_wait           _DEFVAL(DEFAULT_DEADCALL_WAIT);
extern bool               pause_msg_ign           _DEFVAL(0);
extern bool               auto_answer             _DEFVAL(false);
extern int                multisocket             _DEFVAL(0);
extern int                compression             _DEFVAL(0);
extern int                peripsocket             _DEFVAL(0);
extern int                peripfield              _DEFVAL(0);
extern bool               bind_local              _DEFVAL(false);
extern void             * monosocket_comp_state   _DEFVAL(0);
extern const char       * service                 _DEFVAL(DEFAULT_SERVICE);
extern const char       * auth_password           _DEFVAL(DEFAULT_AUTH_PASSWORD);
extern const char       * auth_username           _DEFVAL(0);
extern unsigned long      report_freq             _DEFVAL(DEFAULT_REPORT_FREQ);
extern unsigned long      report_freq_dumpLog     _DEFVAL
(DEFAULT_REPORT_FREQ_DUMP_LOG);
extern bool               periodic_rtd            _DEFVAL(false);
extern const char       * stat_delimiter          _DEFVAL(";");

extern bool               timeout_exit            _DEFVAL(false);
extern bool               timeout_error           _DEFVAL(false);

extern unsigned long      report_freq_dumpRtt     _DEFVAL
(DEFAULT_FREQ_DUMP_RTT);

extern int                max_multi_socket        _DEFVAL
(DEFAULT_MAX_MULTI_SOCKET);
extern bool               skip_rlimit             _DEFVAL(false);

extern unsigned int       timer_resolution        _DEFVAL(DEFAULT_TIMER_RESOLUTION);
extern int                max_recv_loops          _DEFVAL(MAX_RECV_LOOPS_PER_CYCLE);
extern int                max_sched_loops         _DEFVAL(MAX_SCHED_LOOPS_PER_CYCLE);

extern unsigned int       global_t2               _DEFVAL(DEFAULT_T2_TIMER_VALUE);

extern char               local_ip[40];
extern char               local_ip_escaped[42];
extern bool               local_ip_is_ipv6;
extern int                local_port              _DEFVAL(0);
#ifdef USE_SCTP
extern char               multihome_ip[40];
extern int                heartbeat               _DEFVAL(0);
extern int                assocmaxret             _DEFVAL(0);
extern int                pathmaxret              _DEFVAL(0);
extern int                pmtu                    _DEFVAL(0);
extern bool               gracefulclose           _DEFVAL(true);
#endif
extern char               control_ip[40];
extern int                control_port            _DEFVAL(0);
extern int                buff_size               _DEFVAL(65535);
extern int                tcp_readsize            _DEFVAL(65535);
#if defined(PCAPPLAY) || defined(RTP_STREAM)
extern int                hasMedia                _DEFVAL(0);
#endif
#ifdef RTP_STREAM
extern int                min_rtp_port            _DEFVAL(DEFAULT_MIN_RTP_PORT);
extern int                max_rtp_port            _DEFVAL(DEFAULT_MAX_RTP_PORT);
extern int                rtp_default_payload     _DEFVAL(DEFAULT_RTP_PAYLOAD);
extern int                rtp_tasks_per_thread    _DEFVAL(DEFAULT_RTP_THREADTASKS);
extern int                rtp_buffsize            _DEFVAL(65535);
#endif

extern bool               rtp_echo_enabled        _DEFVAL(0);
extern char               media_ip[40];
extern char               media_ip_escaped[42];
extern int                user_media_port         _DEFVAL(0);
extern int                media_port              _DEFVAL(0);
extern size_t             media_bufsize           _DEFVAL(2048);
extern bool               media_ip_is_ipv6;
extern char               remote_ip[40];
extern char               remote_ip_escaped[42];
extern int                remote_port             _DEFVAL(DEFAULT_PORT);
extern unsigned int       pid                     _DEFVAL(0);
extern bool               print_all_responses     _DEFVAL(false);
extern unsigned long      stop_after              _DEFVAL(0xffffffff);
extern int                quitting                _DEFVAL(0);
extern int                interrupt               _DEFVAL(0);
extern bool               paused                  _DEFVAL(false);
extern int                lose_packets            _DEFVAL(0);
extern double             global_lost             _DEFVAL(0.0);
extern char               remote_host[255];
extern char               twinSippHost[255];
extern char               twinSippIp[40];
extern char             * master_name;
extern char             * slave_number;
extern int                twinSippPort            _DEFVAL(DEFAULT_3PCC_PORT);
extern bool               twinSippMode            _DEFVAL(false);
extern bool               extendedTwinSippMode    _DEFVAL(false);

extern bool               nostdin                 _DEFVAL(false);
extern bool               use_curses              _DEFVAL(true);
extern bool               backgroundMode          _DEFVAL(false);
extern bool               signalDump              _DEFVAL(false);

extern int                currentScreenToDisplay  _DEFVAL
(DISPLAY_SCENARIO_SCREEN);
extern int                currentRepartitionToDisplay  _DEFVAL(1);
extern unsigned int       base_cseq               _DEFVAL(0);
extern char             * auth_uri                _DEFVAL(0);
extern const char       * call_id_string          _DEFVAL("%u-%p@%s");
extern char             **generic[100];

extern bool               callidSlash             _DEFVAL(false);

/* TDM map */
extern bool               use_tdmmap              _DEFVAL(false);
extern unsigned int       tdm_map_a               _DEFVAL(0);
extern unsigned int       tdm_map_b               _DEFVAL(0);
extern unsigned int       tdm_map_c               _DEFVAL(0);
extern unsigned int       tdm_map_x               _DEFVAL(0);
extern unsigned int       tdm_map_y               _DEFVAL(0);
extern unsigned int       tdm_map_z               _DEFVAL(0);
extern unsigned int       tdm_map_h               _DEFVAL(0);
extern bool               tdm_map[1024];

#ifdef _USE_OPENSSL
extern BIO              * twinSipp_bio;
extern SSL              * twinSipp_ssl;
extern char             * tls_cert_name           _DEFVAL(DEFAULT_TLS_CERT);
extern char             * tls_key_name            _DEFVAL(DEFAULT_TLS_KEY);
extern char             * tls_crl_name            _DEFVAL(DEFAULT_TLS_CRL);

#endif

// extern field file management
typedef std::map<string, FileContents *> file_map;
extern file_map inFiles;
typedef std::map<string, str_int_map *> file_index;
extern char *ip_file _DEFVAL(NULL);
extern char *default_file _DEFVAL(NULL);

// free user id list
extern list<int> freeUsers;
extern list<int> retiredUsers;
extern AllocVariableTable *globalVariables        _DEFVAL(NULL);
extern AllocVariableTable *userVariables          _DEFVAL(NULL);
typedef std::map<int, VariableTable *> int_vt_map;
extern int_vt_map         userVarMap;

//extern int      new_socket(bool P_use_ipv6, int P_type_socket, int * P_status);
extern struct   sipp_socket *new_sipp_socket(bool use_ipv6, int transport);
struct sipp_socket *new_sipp_call_socket(bool use_ipv6, int transport, bool *existing);
struct sipp_socket *sipp_accept_socket(struct sipp_socket *accept_socket);
extern int      sipp_bind_socket(struct sipp_socket *socket, struct sockaddr_storage *saddr, int *port);
extern int      sipp_connect_socket(struct sipp_socket *socket, struct sockaddr_storage *dest);
extern int      sipp_reconnect_socket(struct sipp_socket *socket);
extern void     sipp_customize_socket(struct sipp_socket *socket);
extern int      delete_socket(int P_socket);
extern int      min_socket          _DEFVAL(65535);
extern int      select_socket       _DEFVAL(0);
extern bool     socket_close        _DEFVAL(true);
extern bool     test_socket         _DEFVAL(true);
extern bool     maxSocketPresent    _DEFVAL(false);

#include "time.hpp"

/************************ Statistics **************************/

extern unsigned long last_report_calls            _DEFVAL(0);
extern unsigned long nb_net_send_errors           _DEFVAL(0);
extern unsigned long nb_net_cong                  _DEFVAL(0);
extern unsigned long nb_net_recv_errors           _DEFVAL(0);
extern bool          cpu_max                      _DEFVAL(false);
extern bool          outbound_congestion          _DEFVAL(false);
extern int           open_calls_user_setting      _DEFVAL(0);
extern int           resynch_send                 _DEFVAL(0);
extern int           resynch_recv                 _DEFVAL(0);
extern unsigned long rtp_pckts                    _DEFVAL(0);
extern unsigned long rtp_bytes                    _DEFVAL(0);
extern unsigned long rtp_pckts_pcap               _DEFVAL(0);
extern unsigned long rtp_bytes_pcap               _DEFVAL(0);
extern unsigned long rtp2_pckts                   _DEFVAL(0);
extern unsigned long rtp2_bytes                   _DEFVAL(0);
extern unsigned long rtp2_pckts_pcap              _DEFVAL(0);
extern unsigned long rtp2_bytes_pcap              _DEFVAL(0);
#ifdef RTP_STREAM
extern volatile unsigned long rtpstream_numthreads _DEFVAL(0);
extern volatile unsigned long rtpstream_bytes_in  _DEFVAL(0);
extern volatile unsigned long rtpstream_bytes_out _DEFVAL(0);
extern volatile unsigned long rtpstream_pckts     _DEFVAL(0);
#endif


/************* Rate Control & Contexts variables **************/

extern int           last_running_calls           _DEFVAL(0);
extern int           last_woken_calls             _DEFVAL(0);
extern int           last_paused_calls            _DEFVAL(0);
extern unsigned int  open_calls_allowed           _DEFVAL(0);
extern unsigned long last_report_time             _DEFVAL(0);
extern unsigned long last_dump_time               _DEFVAL(0);
extern unsigned long last_rate_increase_time      _DEFVAL(0);

/********************** Clock variables ***********************/

extern unsigned long clock_tick                   _DEFVAL(0);
extern unsigned long scheduling_loops             _DEFVAL(0);
extern unsigned long last_timer_cycle             _DEFVAL(0);

extern unsigned long watchdog_interval            _DEFVAL(400);
extern unsigned long watchdog_minor_threshold     _DEFVAL(500);
extern unsigned long watchdog_minor_maxtriggers   _DEFVAL(120);
extern unsigned long watchdog_major_threshold     _DEFVAL(3000);
extern unsigned long watchdog_major_maxtriggers   _DEFVAL(10);
extern unsigned long watchdog_reset               _DEFVAL(600000);


/********************* dynamic Id ************************* */
extern  int maxDynamicId    _DEFVAL(12000);  // max value for dynamicId; this value is reached
extern  int startDynamicId  _DEFVAL(10000);  // offset for first dynamicId  FIXME:in CmdLine
extern  int stepDynamicId   _DEFVAL(4);      // step of increment for dynamicId



#define GET_TIME(clock)       \
{                             \
  struct timezone tzp;        \
  gettimeofday (clock, &tzp); \
}

/*********************** Global Sockets  **********************/

extern struct sipp_socket *main_socket            _DEFVAL(NULL);
extern struct sipp_socket *main_remote_socket     _DEFVAL(NULL);
extern struct sipp_socket *tcp_multiplex          _DEFVAL(NULL);
extern int           media_socket                 _DEFVAL(0);
extern int           media_socket_video           _DEFVAL(0);

extern struct sockaddr_storage  local_sockaddr;
extern struct sockaddr_storage  localTwin_sockaddr;
extern int           user_port                    _DEFVAL(0);
extern char          hostname[80];
extern bool          is_ipv6                      _DEFVAL(false);

extern int           reset_number                 _DEFVAL(0);
extern bool          reset_close                  _DEFVAL(true);
extern int           reset_sleep                  _DEFVAL(1000);
extern bool          sendbuffer_warn              _DEFVAL(false);
/* A list of sockets pending reset. */
extern set<struct sipp_socket *> sockets_pending_reset;

extern struct addrinfo *local_addr_storage;

extern struct sipp_socket *twinSippSocket         _DEFVAL(NULL);
extern struct sipp_socket *localTwinSippSocket    _DEFVAL(NULL);
extern struct sockaddr_storage twinSipp_sockaddr;

/* 3pcc extended mode */
typedef struct _T_peer_infos {
    char                      peer_host[40];
    int                       peer_port;
    struct sockaddr_storage   peer_sockaddr;
    char                      peer_ip[40];
    struct sipp_socket        *peer_socket;
} T_peer_infos;

typedef std::map<std::string, char * > peer_addr_map;
extern peer_addr_map peer_addrs;
typedef std::map<std::string, T_peer_infos> peer_map;
extern peer_map      peers;
typedef std::map<struct sipp_socket *, std::string > peer_socket_map;
extern peer_socket_map peer_sockets;
extern struct sipp_socket *local_sockets[MAX_LOCAL_TWIN_SOCKETS];
extern int           local_nb                    _DEFVAL(0);
extern int           peers_connected             _DEFVAL(0);

extern struct sockaddr_storage remote_sockaddr;
extern short         use_remote_sending_addr      _DEFVAL(0);
extern struct sockaddr_storage remote_sending_sockaddr;

enum E_Alter_YesNo {
    E_ALTER_YES=0,
    E_ALTER_NO
};

#include "logger.hpp"

/********************* Utilities functions  *******************/

#include "strings.hpp"

void sipp_exit(int rc);

char *get_peer_addr(char *);

bool reconnect_allowed();
void reset_connection(struct sipp_socket *);
void close_calls(struct sipp_socket *);
int close_connections();
int open_connections();
void timeout_alarm(int);

/* extended 3PCC mode */
struct sipp_socket **get_peer_socket(char *);
bool is_a_peer_socket(struct sipp_socket *);
bool is_a_local_socket(struct sipp_socket *);
void connect_to_peer (char *, int , sockaddr_storage *, char *, struct sipp_socket **);
void connect_to_all_peers ();
void connect_local_twin_socket(char *);
void close_peer_sockets();
void close_local_sockets();
void free_peer_addr_map();

/********************* Reset global kludge  *******************/

#ifdef GLOBALS_FULL_DEFINITION
#undef extern
#endif

#endif // __SIPP__

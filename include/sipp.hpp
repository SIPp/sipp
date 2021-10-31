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
#include "config.h"
#include "defines.h"
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
#include <poll.h>
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
#include <unordered_map>
#include <math.h>
#ifdef __SUNOS
#include <stdarg.h>
#endif

/* Sipp includes */

#include "xp_parser.h"
#include "scenario.hpp"
#include "screen.hpp"
#include "task.hpp"
#include "listener.hpp"
#include "socket.hpp"
#include "socketowner.hpp"
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

/*
 * If this files is included in the Main, then extern definitions
 * are removed, and the DEFVAL macro becomes '= value;'. Else
 * extern definition does not contain default values assignment
 */

#ifdef GLOBALS_FULL_DEFINITION
#define MAYBE_EXTERN
#define DEFVAL(value) = value
#else
#define MAYBE_EXTERN extern
#define DEFVAL(value)
#endif

#ifndef __cplusplus
#error Unexpected include from non-cxx source
#endif

/************************** Constants **************************/

#define T_UDP                      0
#define T_TCP                      1
#define T_TLS                      2
#define T_SCTP                     3

#ifdef USE_TLS
#define DEFAULT_TLS_CERT           "cacert.pem"
#define DEFAULT_TLS_KEY            "cakey.pem"
#define DEFAULT_TLS_CA             ""
#define DEFAULT_TLS_CRL            ""
#endif

#define TRANSPORT_TO_STRING(p)     ((p==T_TCP) ? "TCP" : ((p==T_TLS)? "TLS" : ((p==T_UDP)? "UDP" : "SCTP")))

#define SIPP_MAXFDS                65536

#ifndef SIPP_MAX_MSG_SIZE
#define SIPP_MAX_MSG_SIZE 65536
#endif

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

#define MAX_PEER_SIZE              4096  /* 3pcc extended mode: max size of peer names */
#define MAX_LOCAL_TWIN_SOCKETS     10    /*3pcc extended mode:max number of peers from which
cmd messages are received */
#ifdef USE_TLS
#define DEFAULT_PREFERRED_AUDIO_CRYPTOSUITE ((char*)"AES_CM_128_HMAC_SHA1_80")
#define DEFAULT_PREFERRED_VIDEO_CRYPTOSUITE ((char*)"AES_CM_128_HMAC_SHA1_80")
#endif // USE_TLS

/******************** Default parameters ***********************/

#define DEFAULT_RATE                 10.0
#define DEFAULT_RATE_SCALE           1.0
#define DEFAULT_RATE_PERIOD_MS       1000
#define DEFAULT_TRANSPORT            T_UDP
#define DEFAULT_PORT                 5060
#define DEFAULT_MEDIA_PORT           6000
#define DEFAULT_3PCC_PORT            6060
#define DEFAULT_SERVICE              "service"
#define DEFAULT_AUTH_PASSWORD        "password"
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
#define DEFAULT_BEHAVIOR_BADCSEQ     8

#define DEFAULT_BEHAVIOR_ALL         (DEFAULT_BEHAVIOR_BYE | DEFAULT_BEHAVIOR_ABORTUNEXP | DEFAULT_BEHAVIOR_PINGREPLY | DEFAULT_BEHAVIOR_BADCSEQ)

#define DEFAULT_MIN_RTP_PORT         DEFAULT_MEDIA_PORT
#define DEFAULT_MAX_RTP_PORT         65535
#define DEFAULT_RTP_PAYLOAD          8
#define DEFAULT_RTP_THREADTASKS      20

/************ User controls and command line options ***********/

MAYBE_EXTERN int                duration                DEFVAL(0);
MAYBE_EXTERN double             rate                    DEFVAL(DEFAULT_RATE);
MAYBE_EXTERN double             rate_scale              DEFVAL(DEFAULT_RATE_SCALE);
MAYBE_EXTERN int                rate_increase           DEFVAL(0);
MAYBE_EXTERN int                rate_max                DEFVAL(0);
MAYBE_EXTERN unsigned long      rate_increase_freq      DEFVAL(DEFAULT_RATE_INCR_FREQ);
MAYBE_EXTERN bool               rate_quit               DEFVAL(true);
MAYBE_EXTERN int                users                   DEFVAL(-1);
MAYBE_EXTERN int                rate_period_ms          DEFVAL(DEFAULT_RATE_PERIOD_MS);
MAYBE_EXTERN int                sleeptime               DEFVAL(0);
MAYBE_EXTERN unsigned long      defl_recv_timeout       DEFVAL(0);
MAYBE_EXTERN unsigned long      defl_send_timeout       DEFVAL(0);
MAYBE_EXTERN unsigned long      global_timeout          DEFVAL(0);
MAYBE_EXTERN int                transport               DEFVAL(DEFAULT_TRANSPORT);
MAYBE_EXTERN bool               retrans_enabled         DEFVAL(1);
MAYBE_EXTERN int                rtcheck                 DEFVAL(RTCHECK_FULL);
MAYBE_EXTERN int                max_udp_retrans         DEFVAL(UDP_MAX_RETRANS);
MAYBE_EXTERN int                max_invite_retrans      DEFVAL(UDP_MAX_RETRANS_INVITE_TRANSACTION);
MAYBE_EXTERN int                max_non_invite_retrans  DEFVAL(UDP_MAX_RETRANS_NON_INVITE_TRANSACTION);
MAYBE_EXTERN unsigned long      default_behaviors       DEFVAL(DEFAULT_BEHAVIOR_ALL);
MAYBE_EXTERN unsigned long      deadcall_wait           DEFVAL(DEFAULT_DEADCALL_WAIT);
MAYBE_EXTERN bool               pause_msg_ign           DEFVAL(0);
MAYBE_EXTERN bool               auto_answer             DEFVAL(false);
MAYBE_EXTERN int                multisocket             DEFVAL(0);
MAYBE_EXTERN int                compression             DEFVAL(0);
MAYBE_EXTERN int                peripsocket             DEFVAL(0);
MAYBE_EXTERN int                peripfield              DEFVAL(0);
MAYBE_EXTERN bool               bind_local              DEFVAL(false);
MAYBE_EXTERN void             * monosocket_comp_state   DEFVAL(0);
MAYBE_EXTERN const char       * service                 DEFVAL(DEFAULT_SERVICE);
MAYBE_EXTERN const char       * auth_password           DEFVAL(DEFAULT_AUTH_PASSWORD);
MAYBE_EXTERN const char       * auth_username           DEFVAL(0);
MAYBE_EXTERN unsigned long      report_freq             DEFVAL(DEFAULT_REPORT_FREQ);
MAYBE_EXTERN unsigned long      report_freq_dumpLog     DEFVAL
(DEFAULT_REPORT_FREQ_DUMP_LOG);
MAYBE_EXTERN bool               periodic_rtd            DEFVAL(false);
MAYBE_EXTERN const char       * stat_delimiter          DEFVAL(";");

MAYBE_EXTERN bool               timeout_exit            DEFVAL(false);
MAYBE_EXTERN bool               timeout_error           DEFVAL(false);

MAYBE_EXTERN unsigned long      report_freq_dumpRtt     DEFVAL
(DEFAULT_FREQ_DUMP_RTT);

MAYBE_EXTERN unsigned           max_multi_socket        DEFVAL
(DEFAULT_MAX_MULTI_SOCKET);
MAYBE_EXTERN bool               skip_rlimit             DEFVAL(false);

MAYBE_EXTERN unsigned int       timer_resolution        DEFVAL(DEFAULT_TIMER_RESOLUTION);
MAYBE_EXTERN int                max_recv_loops          DEFVAL(MAX_RECV_LOOPS_PER_CYCLE);
MAYBE_EXTERN int                max_sched_loops         DEFVAL(MAX_SCHED_LOOPS_PER_CYCLE);

MAYBE_EXTERN unsigned int       global_t2               DEFVAL(DEFAULT_T2_TIMER_VALUE);

MAYBE_EXTERN char               local_ip[127];          /* also used for hostnames */
MAYBE_EXTERN char               local_ip_w_brackets[42]; /* with [brackets] in case of IPv6 */
MAYBE_EXTERN bool               local_ip_is_ipv6;
MAYBE_EXTERN int                local_port              DEFVAL(0);
#ifdef USE_SCTP
MAYBE_EXTERN char               multihome_ip[40];
MAYBE_EXTERN int                heartbeat               DEFVAL(0);
MAYBE_EXTERN int                assocmaxret             DEFVAL(0);
MAYBE_EXTERN int                pathmaxret              DEFVAL(0);
MAYBE_EXTERN int                pmtu                    DEFVAL(0);
MAYBE_EXTERN bool               gracefulclose           DEFVAL(true);
#endif
MAYBE_EXTERN char               control_ip[40];
MAYBE_EXTERN int                control_port            DEFVAL(0);
MAYBE_EXTERN int                buff_size               DEFVAL(65536);
MAYBE_EXTERN int                tcp_readsize            DEFVAL(65536);
MAYBE_EXTERN int                hasMedia                DEFVAL(0);
MAYBE_EXTERN int                min_rtp_port            DEFVAL(DEFAULT_MIN_RTP_PORT);
MAYBE_EXTERN int                max_rtp_port            DEFVAL(DEFAULT_MAX_RTP_PORT);
MAYBE_EXTERN int                rtp_default_payload     DEFVAL(DEFAULT_RTP_PAYLOAD);
MAYBE_EXTERN int                rtp_tasks_per_thread    DEFVAL(DEFAULT_RTP_THREADTASKS);
MAYBE_EXTERN int                rtp_buffsize            DEFVAL(65536);
MAYBE_EXTERN bool               rtpcheck_debug          DEFVAL(0);
#ifdef USE_TLS
MAYBE_EXTERN bool               srtpcheck_debug         DEFVAL(0);
#endif // USE_TLS
MAYBE_EXTERN double             audiotolerance          DEFVAL(1.0);
MAYBE_EXTERN double             videotolerance          DEFVAL(1.0);

MAYBE_EXTERN bool               rtp_echo_enabled        DEFVAL(0);
MAYBE_EXTERN char               media_ip[127];          /* also used for hostnames */
MAYBE_EXTERN int                media_port              DEFVAL(0);
MAYBE_EXTERN size_t             media_bufsize           DEFVAL(2048);
MAYBE_EXTERN bool               media_ip_is_ipv6        DEFVAL(false);
MAYBE_EXTERN char               remote_ip[127];         /* also used for hostnames */
MAYBE_EXTERN char               remote_ip_w_brackets[42]; /* with [brackets] in case of IPv6 */
MAYBE_EXTERN int                remote_port             DEFVAL(DEFAULT_PORT);
MAYBE_EXTERN unsigned int       pid                     DEFVAL(0);
MAYBE_EXTERN bool               print_all_responses     DEFVAL(false);
MAYBE_EXTERN unsigned long      stop_after              DEFVAL(0xffffffff);
MAYBE_EXTERN int                quitting                DEFVAL(0);
MAYBE_EXTERN int                interrupt               DEFVAL(0);
MAYBE_EXTERN bool               paused                  DEFVAL(false);
MAYBE_EXTERN int                lose_packets            DEFVAL(0);
MAYBE_EXTERN double             global_lost             DEFVAL(0.0);
MAYBE_EXTERN char               remote_host[255];
MAYBE_EXTERN char               twinSippHost[255];
MAYBE_EXTERN char               twinSippIp[40];
MAYBE_EXTERN char             * master_name;
MAYBE_EXTERN char             * slave_number;
MAYBE_EXTERN int                twinSippPort            DEFVAL(DEFAULT_3PCC_PORT);
MAYBE_EXTERN bool               twinSippMode            DEFVAL(false);
MAYBE_EXTERN bool               extendedTwinSippMode    DEFVAL(false);

MAYBE_EXTERN bool               nostdin                 DEFVAL(false);
MAYBE_EXTERN bool               backgroundMode          DEFVAL(false);
MAYBE_EXTERN bool               signalDump              DEFVAL(false);

MAYBE_EXTERN int                currentScreenToDisplay  DEFVAL
(DISPLAY_SCENARIO_SCREEN);
MAYBE_EXTERN int                currentRepartitionToDisplay  DEFVAL(1);
MAYBE_EXTERN unsigned int       base_cseq               DEFVAL(0);
MAYBE_EXTERN char             * auth_uri                DEFVAL(0);
MAYBE_EXTERN const char       * call_id_string          DEFVAL("%u-%p@%s");
typedef std::unordered_map<std::string, std::string> ParamMap;
MAYBE_EXTERN ParamMap           generic;

MAYBE_EXTERN bool               rtp_echo_state          DEFVAL(true);
MAYBE_EXTERN bool               callidSlash             DEFVAL(false);

/* TDM map */
MAYBE_EXTERN bool               use_tdmmap              DEFVAL(false);
MAYBE_EXTERN unsigned int       tdm_map_a               DEFVAL(0);
MAYBE_EXTERN unsigned int       tdm_map_b               DEFVAL(0);
MAYBE_EXTERN unsigned int       tdm_map_c               DEFVAL(0);
MAYBE_EXTERN unsigned int       tdm_map_x               DEFVAL(0);
MAYBE_EXTERN unsigned int       tdm_map_y               DEFVAL(0);
MAYBE_EXTERN unsigned int       tdm_map_z               DEFVAL(0);
MAYBE_EXTERN unsigned int       tdm_map_h               DEFVAL(0);
MAYBE_EXTERN bool               tdm_map[1024];

#ifdef USE_TLS
MAYBE_EXTERN const char       * tls_cert_name           DEFVAL(DEFAULT_TLS_CERT);
MAYBE_EXTERN const char       * tls_key_name            DEFVAL(DEFAULT_TLS_KEY);
MAYBE_EXTERN const char       * tls_ca_name             DEFVAL(DEFAULT_TLS_CA);
MAYBE_EXTERN const char       * tls_crl_name            DEFVAL(DEFAULT_TLS_CRL);
MAYBE_EXTERN double             tls_version             DEFVAL(0.0);
#endif

MAYBE_EXTERN char*              scenario_file           DEFVAL(NULL);
MAYBE_EXTERN char*              scenario_path           DEFVAL(NULL);

// extern field file management
typedef std::map<string, FileContents *> file_map;
MAYBE_EXTERN file_map inFiles;
typedef std::map<string, str_int_map *> file_index;
MAYBE_EXTERN char *ip_file DEFVAL(NULL);
MAYBE_EXTERN char *default_file DEFVAL(NULL);

// free user id list
MAYBE_EXTERN list<int> freeUsers;
MAYBE_EXTERN list<int> retiredUsers;
MAYBE_EXTERN AllocVariableTable *globalVariables        DEFVAL(NULL);
MAYBE_EXTERN AllocVariableTable *userVariables          DEFVAL(NULL);
typedef std::map<int, VariableTable *> int_vt_map;
MAYBE_EXTERN int_vt_map         userVarMap;

MAYBE_EXTERN SIPpSocket* new_sipp_socket(bool use_ipv6, int transport);
MAYBE_EXTERN int      sipp_bind_socket(SIPpSocket *socket, struct sockaddr_storage *saddr, int *port);
MAYBE_EXTERN void     sipp_customize_socket(SIPpSocket *socket);
MAYBE_EXTERN bool     test_socket         DEFVAL(true);

#include "time.hpp"

/************************ Statistics **************************/

MAYBE_EXTERN unsigned long last_report_calls            DEFVAL(0);
MAYBE_EXTERN unsigned long nb_net_send_errors           DEFVAL(0);
MAYBE_EXTERN unsigned long nb_net_cong                  DEFVAL(0);
MAYBE_EXTERN unsigned long nb_net_recv_errors           DEFVAL(0);
MAYBE_EXTERN bool          cpu_max                      DEFVAL(false);
MAYBE_EXTERN bool          outbound_congestion          DEFVAL(false);
MAYBE_EXTERN int           open_calls_user_setting      DEFVAL(0);
MAYBE_EXTERN int           resynch_send                 DEFVAL(0);
MAYBE_EXTERN int           resynch_recv                 DEFVAL(0);
MAYBE_EXTERN unsigned long rtp_pckts                    DEFVAL(0);
MAYBE_EXTERN unsigned long rtp_bytes                    DEFVAL(0);
MAYBE_EXTERN unsigned long rtp_pckts_pcap               DEFVAL(0);
MAYBE_EXTERN unsigned long rtp_bytes_pcap               DEFVAL(0);
MAYBE_EXTERN unsigned long rtp2_pckts                   DEFVAL(0);
MAYBE_EXTERN unsigned long rtp2_bytes                   DEFVAL(0);
MAYBE_EXTERN unsigned long rtp2_pckts_pcap              DEFVAL(0);
MAYBE_EXTERN unsigned long rtp2_bytes_pcap              DEFVAL(0);
MAYBE_EXTERN volatile unsigned long rtpstream_numthreads DEFVAL(0);
MAYBE_EXTERN volatile unsigned long rtpstream_abytes_in  DEFVAL(0);
MAYBE_EXTERN volatile unsigned long rtpstream_vbytes_in  DEFVAL(0);
MAYBE_EXTERN volatile unsigned long rtpstream_abytes_out DEFVAL(0);
MAYBE_EXTERN volatile unsigned long rtpstream_vbytes_out DEFVAL(0);
MAYBE_EXTERN volatile unsigned long rtpstream_apckts    DEFVAL(0);
MAYBE_EXTERN volatile unsigned long rtpstream_vpckts    DEFVAL(0);

/************* Rate Control & Contexts variables **************/

MAYBE_EXTERN int           last_running_calls           DEFVAL(0);
MAYBE_EXTERN int           last_woken_calls             DEFVAL(0);
MAYBE_EXTERN int           last_paused_calls            DEFVAL(0);
MAYBE_EXTERN unsigned int  open_calls_allowed           DEFVAL(0);
MAYBE_EXTERN unsigned long last_report_time             DEFVAL(0);
MAYBE_EXTERN unsigned long last_dump_time               DEFVAL(0);
MAYBE_EXTERN unsigned long last_rate_increase_time      DEFVAL(0);

/********************** Clock variables ***********************/

MAYBE_EXTERN unsigned long clock_tick                   DEFVAL(0);
MAYBE_EXTERN unsigned long scheduling_loops             DEFVAL(0);
MAYBE_EXTERN unsigned long last_timer_cycle             DEFVAL(0);

MAYBE_EXTERN unsigned long watchdog_interval            DEFVAL(400);
MAYBE_EXTERN unsigned long watchdog_minor_threshold     DEFVAL(500);
MAYBE_EXTERN unsigned long watchdog_minor_maxtriggers   DEFVAL(120);
MAYBE_EXTERN unsigned long watchdog_major_threshold     DEFVAL(3000);
MAYBE_EXTERN unsigned long watchdog_major_maxtriggers   DEFVAL(10);
MAYBE_EXTERN unsigned long watchdog_reset               DEFVAL(600000);


/********************* dynamic Id ************************* */
MAYBE_EXTERN  int maxDynamicId    DEFVAL(12000);  // max value for dynamicId; this value is reached
MAYBE_EXTERN  int startDynamicId  DEFVAL(10000);  // offset for first dynamicId  FIXME:in CmdLine
MAYBE_EXTERN  int stepDynamicId   DEFVAL(4);      // step of increment for dynamicId

#define GET_TIME(clock) \
{ \
    struct timezone tzp; \
    gettimeofday (clock, &tzp); \
}

/*********************** Global Sockets  **********************/

MAYBE_EXTERN SIPpSocket   *main_socket                  DEFVAL(NULL);
MAYBE_EXTERN SIPpSocket   *main_remote_socket           DEFVAL(NULL);
MAYBE_EXTERN SIPpSocket   *tcp_multiplex                DEFVAL(NULL);
MAYBE_EXTERN int media_socket_audio                     DEFVAL(0);
MAYBE_EXTERN int media_socket_video                     DEFVAL(0);

MAYBE_EXTERN struct sockaddr_storage local_sockaddr;
MAYBE_EXTERN struct sockaddr_storage localTwin_sockaddr;
MAYBE_EXTERN int           user_port                    DEFVAL(0);
MAYBE_EXTERN char          hostname[80];

MAYBE_EXTERN int           reset_number                 DEFVAL(0);
MAYBE_EXTERN bool          reset_close                  DEFVAL(true);
MAYBE_EXTERN int           reset_sleep                  DEFVAL(1000);
MAYBE_EXTERN bool          sendbuffer_warn              DEFVAL(false);
/* A list of sockets pending reset. */
MAYBE_EXTERN set<SIPpSocket*> sockets_pending_reset;

MAYBE_EXTERN struct sockaddr_storage local_addr_storage;

MAYBE_EXTERN SIPpSocket   *twinSippSocket               DEFVAL(NULL);
MAYBE_EXTERN SIPpSocket   *localTwinSippSocket          DEFVAL(NULL);
MAYBE_EXTERN struct sockaddr_storage twinSipp_sockaddr;

/* 3pcc extended mode */
typedef struct _T_peer_infos {
    char peer_host[40];
    int peer_port;
    struct sockaddr_storage peer_sockaddr;
    char peer_ip[40];
    SIPpSocket *peer_socket;
} T_peer_infos;

typedef std::map<std::string, char*> peer_addr_map;
MAYBE_EXTERN peer_addr_map peer_addrs;
typedef std::map<std::string, T_peer_infos> peer_map;
MAYBE_EXTERN peer_map      peers;
typedef std::map<SIPpSocket*, std::string> peer_socket_map;
MAYBE_EXTERN peer_socket_map peer_sockets;
MAYBE_EXTERN SIPpSocket *local_sockets[MAX_LOCAL_TWIN_SOCKETS];
MAYBE_EXTERN int           local_nb                     DEFVAL(0);
MAYBE_EXTERN int           peers_connected              DEFVAL(0);

MAYBE_EXTERN struct sockaddr_storage remote_sockaddr;
MAYBE_EXTERN short         use_remote_sending_addr      DEFVAL(0);
MAYBE_EXTERN struct sockaddr_storage remote_sending_sockaddr;

enum E_Alter_YesNo {
    E_ALTER_YES=0,
    E_ALTER_NO
};

#include "logger.hpp"

/********************* Utilities functions  *******************/

#include "strings.hpp"

void sipp_exit(int rc, int rtp_errors, int echo_errors);

char *get_peer_addr(char *);

bool reconnect_allowed();
void reset_connection(SIPpSocket *);
void close_calls(SIPpSocket *);
int close_connections();
int open_connections();
void timeout_alarm(int);

/* extended 3PCC mode */
SIPpSocket **get_peer_socket(char *);
bool is_a_peer_socket(SIPpSocket *);
bool is_a_local_socket(SIPpSocket *);
void connect_to_all_peers();
void connect_local_twin_socket(char *);
void close_peer_sockets();
void close_local_sockets();
void free_peer_addr_map();

/********************* Reset global kludge  *******************/

#endif // __SIPP__

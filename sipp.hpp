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
#include <sys/time.h>
#include <sys/poll.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <ctype.h>
#include <signal.h>
#include <time.h>
#include <vector>
#include <string>
#include <math.h>

#ifdef __HPUX
#include <alloca.h>
#endif

/* Sipp includes */

#include "xp_parser.h"
#include "scenario.hpp"
#include "screen.hpp"
#include "call.hpp"
#include "comp.h"
#include "stat.hpp"
#include "actions.hpp"
#include "variables.hpp"
/* Open SSL stuff */
#ifdef _USE_OPENSSL
#include "sslcommon.h" 
#endif


#ifndef __CYGWIN
#ifndef FD_SETSIZE
#define FD_SETSIZE 65000
#endif
#else
#ifndef FD_SETSIZE
#define FD_SETSIZE 1024
#endif
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

#define SIPP_VERSION               20060829
#define T_UDP                      0
#define T_TCP                      1
#ifdef _USE_OPENSSL
#define T_TLS                      2
#define DEFAULT_TLS_CERT           ((char *)"cacert.pem")
#define DEFAULT_TLS_KEY            ((char *)"cakey.pem")
#define DEFAULT_TLS_CRL            ((char *)"")

#endif
#define TRANSPORT_TO_STRING(p)     ((p==1) ? "TCP" : ((p==2)? "TLS" :"UDP"))

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
#define NB_UPDATE_PER_CYCLE        1

#define MAX_PATH                   250

/******************** Default parameters ***********************/

#define DEFAULT_RATE                 10.0
#define DEFAULT_RATE_PERIOD_S        1.0
#define DEFAULT_TRANSPORT            T_UDP
#define DEFAULT_PORT                 5060  
#ifdef __3PCC__
#define DEFAULT_3PCC_PORT            6060
#endif
#define DEFAULT_SERVICE              ((char *)"service")
#define DEFAULT_AUTH_PASSWORD        ((char *)"password")
#define DEFAULT_REPORT_FREQ          1000
#define DEFAULT_REPORT_FREQ_DUMP_LOG 60000
#define DEFAULT_TIMER_RESOLUTION     10
#define DEFAULT_FREQ_DUMP_RTT        200
#define DEFAULT_MAX_MULTI_SOCKET     50000
#define DEFAULT_CTRL_SOCKET_PORT     8888

/************ User controls and command line options ***********/

extern int                duration                _DEFVAL(0);
extern double             rate                    _DEFVAL(DEFAULT_RATE);
extern int	          rate_increase           _DEFVAL(0);
extern int	          rate_max	          _DEFVAL(0);
extern int                users                   _DEFVAL(0);
extern double             rate_period_s           _DEFVAL(DEFAULT_RATE_PERIOD_S);
extern unsigned long      defl_recv_timeout       _DEFVAL(0);
extern unsigned long      global_timeout          _DEFVAL(0);
extern int                transport               _DEFVAL(DEFAULT_TRANSPORT);
extern int                retrans_enabled         _DEFVAL(1);
extern int                max_udp_retrans         _DEFVAL(UDP_MAX_RETRANS);
extern int                default_behavior        _DEFVAL(1);
extern int                pause_msg_ign           _DEFVAL(0);
extern int                auto_answer             _DEFVAL(0);
extern int                multisocket             _DEFVAL(0);
extern int                compression             _DEFVAL(0);
extern int                peripsocket             _DEFVAL(0);
extern int                peripfield              _DEFVAL(0);
extern int                bind_local              _DEFVAL(0);
extern void             * monosocket_comp_state   _DEFVAL(0);
extern char             * service                 _DEFVAL(DEFAULT_SERVICE);
extern char             * auth_password           _DEFVAL(DEFAULT_AUTH_PASSWORD);
extern unsigned long      report_freq             _DEFVAL(DEFAULT_REPORT_FREQ);
extern unsigned long      report_freq_dumpLog     _DEFVAL
                                                (DEFAULT_REPORT_FREQ_DUMP_LOG);

extern bool               timeout_exit            _DEFVAL(false);

extern unsigned long      report_freq_dumpRtt     _DEFVAL
                                                (DEFAULT_FREQ_DUMP_RTT);

extern int                max_multi_socket        _DEFVAL
                                                (DEFAULT_MAX_MULTI_SOCKET);

extern int                timer_resolution        _DEFVAL(DEFAULT_TIMER_RESOLUTION);
extern int                max_recv_loops          _DEFVAL(MAX_RECV_LOOPS_PER_CYCLE);
extern int                update_nb               _DEFVAL(NB_UPDATE_PER_CYCLE);
 
extern char               local_ip[40];
extern char               local_ip_escaped[42];
extern bool               local_ip_is_ipv6;    
extern int                local_port              _DEFVAL(0);
extern int                buff_size               _DEFVAL(65535);
#ifdef PCAPPLAY
extern int                hasMedia                _DEFVAL(0);
#endif
extern bool               rtp_echo_enabled        _DEFVAL(0);
extern char               media_ip[40];
extern char               media_ip_escaped[42];
extern int                media_port              _DEFVAL(0);
extern size_t             media_bufsize           _DEFVAL(2048);
extern bool               media_ip_is_ipv6;    
extern char               remote_ip[40];
extern char               remote_ip_escaped[42];
extern int                remote_port             _DEFVAL(DEFAULT_PORT);
extern unsigned int       pid                     _DEFVAL(0);
extern int                print_all_responses     _DEFVAL(0);
extern unsigned long      stop_after              _DEFVAL(0xffffffff);
extern int                quitting                _DEFVAL(0);
extern int                interrupt               _DEFVAL(0);
extern int                paused                  _DEFVAL(0);
extern int                lose_packets            _DEFVAL(0);
extern char               remote_host[255]; 
#ifdef __3PCC__
extern char               twinSippHost[255];
extern char               twinSippIp[40];
extern int                twinSippPort            _DEFVAL(DEFAULT_3PCC_PORT);
extern bool               twinSippMode            _DEFVAL(false);
#endif
extern bool               backgroundMode          _DEFVAL(false);        
extern bool               signalDump              _DEFVAL(false);        

extern bool               ctrlEW                  _DEFVAL(false);

extern int                currentScreenToDisplay  _DEFVAL
                                                  (DISPLAY_SCENARIO_SCREEN);
extern int                currentRepartitionToDisplay  _DEFVAL(1);
extern unsigned int       base_cseq               _DEFVAL(0);
extern char             * auth_uri                _DEFVAL(0);
extern char             * call_id_string          _DEFVAL("%u-%p@%s");
extern char             **generic[100];

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
extern BIO                  *bio ;
extern SSL                  *ssl_tcp_multiplex ;
extern BIO                  *twinSipp_bio ;
extern SSL                  *twinSipp_ssl ;
extern char                 *tls_cert_name     _DEFVAL(DEFAULT_TLS_CERT) ;
extern char                 *tls_key_name      _DEFVAL(DEFAULT_TLS_KEY)  ;
extern char                 *tls_crl_name      _DEFVAL(DEFAULT_TLS_CRL)  ;

#endif

// extern field file management
typedef std::vector<std::string>    IN_FILE_CONTENTS;
extern IN_FILE_CONTENTS   fileContents;
extern int                numLinesInFile          _DEFVAL(0);

extern int      new_socket(bool P_use_ipv6, int P_type_socket, int * P_status);
extern int      delete_socket(int P_socket);
extern int      min_socket          _DEFVAL(65535);
extern int      select_socket       _DEFVAL(0);
extern bool     socket_close        _DEFVAL(true);
extern bool     test_socket         _DEFVAL(true);
extern bool     socket_open         _DEFVAL(true);
extern bool     maxSocketPresent    _DEFVAL(false);
extern int      *tab_multi_socket;

extern unsigned int getmilliseconds();

/************************ Statistics **************************/

extern unsigned long total_calls                  _DEFVAL(0);
extern unsigned long last_report_calls            _DEFVAL(0);
extern unsigned long nb_net_send_errors           _DEFVAL(0);
extern unsigned long nb_net_cong                  _DEFVAL(0);
extern unsigned long nb_net_recv_errors           _DEFVAL(0);
extern bool          cpu_max                      _DEFVAL(false);
extern bool          outbound_congestion          _DEFVAL(false);
extern int           open_calls_peak              _DEFVAL(0);
extern unsigned long open_calls_peak_time         _DEFVAL(0);
extern int           open_calls_user_setting      _DEFVAL(0);
extern int           nb_out_of_the_blue           _DEFVAL(0);
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

/************* Rate Control & Contexts variables **************/

extern int           open_calls                   _DEFVAL(0);
extern int           last_running_calls           _DEFVAL(0);
extern int           last_woken_calls             _DEFVAL(0);
extern int           last_paused_calls            _DEFVAL(0);
extern unsigned int  open_calls_allowed           _DEFVAL(0);
extern unsigned long last_rate_change_time        _DEFVAL(1);
extern unsigned long last_report_time             _DEFVAL(1);
extern unsigned long last_dump_time               _DEFVAL(1);
extern unsigned long calls_since_last_rate_change _DEFVAL(0);

/********************** Clock variables ***********************/

extern unsigned long clock_tick                   _DEFVAL(1);
extern unsigned long scheduling_loops             _DEFVAL(0);
extern unsigned long last_timer_cycle             _DEFVAL(0);

#define GET_TIME(clock)       \
{                             \
  struct timezone tzp;        \
  gettimeofday (clock, &tzp); \
}

/*********************** Global Sockets  **********************/

extern int           main_socket                  _DEFVAL(0);
extern int           tcp_multiplex                _DEFVAL(0);
extern int           media_socket                 _DEFVAL(0);
extern int           media_socket_video           _DEFVAL(0);

extern double        max_reconnections            _DEFVAL(0);
extern struct        sockaddr_storage   local_sockaddr;
extern struct        sockaddr_storage   localTwin_sockaddr;
extern int           user_port                    _DEFVAL(0);
extern char          hostname[80];
extern bool          is_ipv6                      _DEFVAL(false);
extern int           start_calls                  _DEFVAL(0);
extern double        reset_number                 _DEFVAL(0);

extern struct        addrinfo * local_addr_storage;

#ifdef __3PCC__
extern int           twinSippSocket               _DEFVAL(0);
extern int           localTwinSippSocket          _DEFVAL(0);
extern struct        sockaddr_storage twinSipp_sockaddr;
#endif

extern struct        sockaddr_storage remote_sockaddr;

extern short         use_remote_sending_addr      _DEFVAL(0);
extern struct        sockaddr_storage remote_sending_sockaddr;

enum E_Alter_YesNo
  {
    E_ALTER_YES=0,
    E_ALTER_NO
  };

/************************** Trace Files ***********************/

extern FILE * screenf                             _DEFVAL(0);
extern FILE * logfile                             _DEFVAL(0);
extern FILE * messagef                            _DEFVAL(0);
extern FILE * timeoutf                            _DEFVAL(0);
extern int    useMessagef                         _DEFVAL(0);
extern int    useScreenf                          _DEFVAL(0);
extern int    useLogf                             _DEFVAL(0);
extern int    useTimeoutf                         _DEFVAL(0);
extern int    dumpInFile                          _DEFVAL(0);
extern int    dumpInRtt                           _DEFVAL(0);
extern char * scenario_file;

#define TRACE_MSG(arg)      \
{                           \
  if(messagef) {            \
    FILE * s = messagef;    \
    fprintf arg;            \
    fflush(messagef);       \
  }                         \
}

#define LOG_MSG(arg)        \
{                           \
  if(logfile) {             \
    FILE * s = logfile;     \
    fprintf arg;            \
    fflush(logfile);        \
  }                         \
}

#define TRACE_TIMEOUT(arg)  \
{                           \
  if(timeoutf) {            \
    FILE * s = timeoutf;    \
    fprintf arg;            \
    fflush(timeoutf);       \
  }                         \
}

/********************* Mini-Parser Routines *******************/

int get_method(char *msg);
char * get_peer_tag(char *msg);
unsigned long int get_cseq_value(char *msg);
unsigned long get_reply_code(char *msg);

/********************** Network Interfaces ********************/

void sipp_customize_socket(int socket);
int send_message(int s, void ** comp_state, char * msg);
#ifdef _USE_OPENSSL
int send_message_tls(SSL *s, void ** comp_state, char * msg);
#endif

void pollset_remove(int idx);
int pollset_add(call * p_call, int socket);

#if defined (__hpux) || defined (__alpha) && !defined (__FreeBSD__)
#define sipp_socklen_t  int
#else
#define sipp_socklen_t  socklen_t
#endif

#define SOCK_ADDR_SIZE(a) \
  (((a)->ss_family == AF_INET) ? sizeof(struct sockaddr_in) \
                               : sizeof(struct sockaddr_in6))

#if defined(__cplusplus) && defined (__hpux)
#define _RCAST(type, val) (reinterpret_cast<type> (val))
#else
#define _RCAST(type, val) ((type)(val))
#endif

/********************* Utilities functions  *******************/

char *strcasestr2 ( char *__haystack, char *__needle);
int get_decimal_from_hex(char hex);

int reset_connections() ;
int close_calls();
int close_connections();
int open_connections();
void timeout_alarm(int);

/********************* Reset global kludge  *******************/

#ifdef GLOBALS_FULL_DEFINITION
#undef extern
#endif

#endif // __SIPP__

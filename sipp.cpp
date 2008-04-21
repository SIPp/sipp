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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *  Author : Richard GAYRAUD - 04 Nov 2003
 *           Marc LAMBERTON
 *           Olivier JACQUES
 *           Herve PELLAN
 *           David MANSUTTI
 *           Francois-Xavier Kowalski
 *           Gerard Lyonnaz
 *           From Hewlett Packard Company.
 *           F. Tarek Rogers
 *           Peter Higginson
 *           Vincent Luba
 *           Shriram Natarajan
 *           Guillaume Teissier from FTR&D
 *           Clement Chen
 *           Wolfgang Beck
 *           Charles P Wright from IBM Research
 */

#define GLOBALS_FULL_DEFINITION

#include "sipp.hpp"
#include "assert.h"

#ifdef _USE_OPENSSL
SSL_CTX  *sip_trp_ssl_ctx = NULL; /* For SSL cserver context */
SSL_CTX  *sip_trp_ssl_ctx_client = NULL; /* For SSL cserver context */
SSL_CTX  *twinSipp_sip_trp_ssl_ctx_client = NULL; /* For SSL cserver context */

enum ssl_init_status {
  SSL_INIT_NORMAL, /* 0   Normal completion    */
  SSL_INIT_ERROR   /* 1   Unspecified error    */
};

#define CALL_BACK_USER_DATA "ksgr"

int passwd_call_back_routine(char  *buf , int size , int flag, void *passwd)
{
  strncpy(buf, (char *)(passwd), size);
  buf[size - 1] = '\0';
  return(strlen(buf));
}
#endif

unsigned long calls_since_last_rate_change = 0;
bool do_hide = true;
bool show_index = false;

static struct sipp_socket *sipp_allocate_socket(bool use_ipv6, int transport, int fd, int accepting);
struct sipp_socket *ctrl_socket = NULL;
struct sipp_socket *stdin_socket = NULL;

int command_mode = 0;
char *command_buffer = NULL;

/* These could be local to main, but for the option processing table. */
static int argiFileName;

/***************** Option Handling Table *****************/
struct sipp_option {
	const char *option;
	const char *help;
	int type;
	void *data;
	/* Pass 0: Help and other options that should exit immediately. */
	/* Pass 1: All other options. */
	/* Pass 2: Scenario parsing. */
	int pass;
};

#define SIPP_OPTION_HELP	   1
#define SIPP_OPTION_INT		   2
#define SIPP_OPTION_SETFLAG	   3
#define SIPP_OPTION_UNSETFLAG	   4
#define SIPP_OPTION_STRING	   5
#define SIPP_OPTION_ARGI 	   6
#define SIPP_OPTION_TIME_SEC	   7
#define SIPP_OPTION_FLOAT	   8
#define SIPP_OPTION_BOOL	  10 
#define SIPP_OPTION_VERSION	  11
#define SIPP_OPTION_TRANSPORT	  12
#define SIPP_OPTION_NEED_SSL	  13
#define SIPP_OPTION_IP		  14
#define SIPP_OPTION_MAX_SOCKET	  15
#define SIPP_OPTION_CSEQ	  16
#define SIPP_OPTION_SCENARIO	  17
#define SIPP_OPTION_RSA		  18
#define SIPP_OPTION_LIMIT	  19
#define SIPP_OPTION_USERS	  20
#define SIPP_OPTION_KEY		  21
#define SIPP_OPTION_3PCC	  22
#define SIPP_OPTION_TDMMAP	  23
#define SIPP_OPTION_TIME_MS	  24
#define SIPP_OPTION_SLAVE_CFG     25
#define SIPP_OPTION_3PCC_EXTENDED 26
#define SIPP_OPTION_INPUT_FILE	  27
#define SIPP_OPTION_TIME_MS_LONG  28
#define SIPP_OPTION_LONG          29
#define SIPP_OPTION_LONG_LONG     30
#define SIPP_OPTION_DEFAULTS      31
#define SIPP_OPTION_OOC_SCENARIO  32
#define SIPP_OPTION_INDEX_FILE    33

/* Put Each option, its help text, and type in this table. */
struct sipp_option options_table[] = {
	{"v", "Display version and copyright information.", SIPP_OPTION_VERSION, NULL, 0},

	{"h", NULL, SIPP_OPTION_HELP, NULL, 0},
	{"help", NULL, SIPP_OPTION_HELP, NULL, 0},

	{"aa", "Enable automatic 200 OK answer for INFO, UPDATE and NOTIFY messages.", SIPP_OPTION_SETFLAG, &auto_answer, 1},
#ifdef _USE_OPENSSL
	{"auth_uri", "Force the value of the URI for authentication.\n"
                     "By default, the URI is composed of remote_ip:remote_port.", SIPP_OPTION_STRING, &auth_uri, 1},
#else
	{"auth_uri", NULL, SIPP_OPTION_NEED_SSL, NULL, 1},
#endif

	{"base_cseq", "Start value of [cseq] for each call.", SIPP_OPTION_CSEQ, NULL, 1},
	{"bg", "Launch SIPp in background mode.", SIPP_OPTION_SETFLAG, &backgroundMode, 1},
	{"bind_local", "Bind socket to local IP address, i.e. the local IP address is used as the source IP address.  If SIPp runs in server mode it will only listen on the local IP address instead of all IP addresses.", SIPP_OPTION_SETFLAG, &bind_local, 1},
	{"buff_size", "Set the send and receive buffer size.", SIPP_OPTION_INT, &buff_size, 1},

	{"cid_str", "Call ID string (default %u-%p@%s).  %u=call_number, %s=ip_address, %p=process_number, %%=% (in any order).", SIPP_OPTION_STRING, &call_id_string, 1},
	{"ci", "Set the local control IP address", SIPP_OPTION_IP, control_ip, 1},
	{"cp", "Set the local control port number. Default is 8888.", SIPP_OPTION_INT, &control_port, 1},

	{"d", "Controls the length of calls. More precisely, this controls the duration of 'pause' instructions in the scenario, if they do not have a 'milliseconds' section. Default value is 0 and default unit is milliseconds.", SIPP_OPTION_TIME_MS, &duration, 1},
	{"deadcall_wait", "How long the Call-ID and final status of calls should be kept to improve message and error logs (default unit is ms).", SIPP_OPTION_TIME_MS, &deadcall_wait, 1},
	{"default_behaviors", "Set the default behaviors that SIPp will use.  Possbile values are:\n"
		"- all\tUse all default behaviors\n"
		"- none\tUse no default behaviors\n"
		"- bye\tSend byes for aborted calls\n"
		"- abortunexp\tAbort calls on unexpected messages\n"
		"- pingreply\tReply to ping requests\n"
		"If a behavior is prefaced with a -, then it is turned off.  Example: all,-bye\n",
		SIPP_OPTION_DEFAULTS, &default_behaviors, 1},

	{"f", "Set the statistics report frequency on screen. Default is 1 and default unit is seconds.", SIPP_OPTION_TIME_SEC, &report_freq, 1},
	{"fd", "Set the statistics dump log report frequency. Default is 60 and default unit is seconds.", SIPP_OPTION_TIME_SEC, &report_freq_dumpLog, 1},

	{"i", "Set the local IP address for 'Contact:','Via:', and 'From:' headers. Default is primary host IP address.\n", SIPP_OPTION_IP, local_ip, 1},
	{"inf", "Inject values from an external CSV file during calls into the scenarios.\n"
                "First line of this file say whether the data is to be read in sequence (SEQUENTIAL), random (RANDOM), or user (USER) order.\n"
		"Each line corresponds to one call and has one or more ';' delimited data fields. Those fields can be referred as [field0], [field1], ... in the xml scenario file.  Several CSV files can be used simultaneously (syntax: -inf f1.csv -inf f2.csv ...)", SIPP_OPTION_INPUT_FILE, NULL, 1},
	{"infindex", "file field\nCreate an index of file using field.  For example -inf users.csv -infindex users.csv 0 creates an index on the first key.", SIPP_OPTION_INDEX_FILE, NULL, 1 },

	{"ip_field", "Set which field from the injection file contains the IP address from which the client will send its messages.\n"
                     "If this option is omitted and the '-t ui' option is present, then field 0 is assumed.\n"
		     "Use this option together with '-t ui'", SIPP_OPTION_INT, &peripfield, 1},


	{"l", "Set the maximum number of simultaneous calls. Once this limit is reached, traffic is decreased until the number of open calls goes down. Default:\n"
	      "  (3 * call_duration (s) * rate).", SIPP_OPTION_LIMIT, NULL, 1},

	{"lost", "Set the number of packets to lose by default (scenario specifications override this value).", SIPP_OPTION_FLOAT, &global_lost, 1},
	{"m", "Stop the test and exit when 'calls' calls are processed", SIPP_OPTION_LONG, &stop_after, 1},
	{"mi", "Set the local media IP address", SIPP_OPTION_IP, media_ip, 1},
        {"master","3pcc extended mode: indicates the master number", SIPP_OPTION_3PCC_EXTENDED, &master_name, 1},
	{"max_recv_loops", "Set the maximum number of messages received read per cycle. Increase this value for high traffic level.  The default value is 1000.", SIPP_OPTION_INT, &max_recv_loops, 1},
	{"max_sched_loops", "Set the maximum number of calsl run per event loop. Increase this value for high traffic level.  The default value is 1000.", SIPP_OPTION_INT, &max_sched_loops, 1},
	{"max_reconnect", "Set the the maximum number of reconnection.", SIPP_OPTION_INT, &reset_number, 1},
	{"max_retrans", "Maximum number of UDP retransmissions before call ends on timeout.  Default is 5 for INVITE transactions and 7 for others.", SIPP_OPTION_INT, &max_udp_retrans, 1},
	{"max_invite_retrans", "Maximum number of UDP retransmissions for invite transactions before call ends on timeout.", SIPP_OPTION_INT, &max_invite_retrans, 1},
	{"max_non_invite_retrans", "Maximum number of UDP retransmissions for non-invite transactions before call ends on timeout.", SIPP_OPTION_INT, &max_non_invite_retrans, 1},
	{"max_log_size", "What is the limit for error and message log file sizes.", SIPP_OPTION_LONG_LONG, &max_log_size, 1},
	{"max_socket", "Set the max number of sockets to open simultaneously. This option is significant if you use one socket per call. Once this limit is reached, traffic is distributed over the sockets already opened. Default value is 50000", SIPP_OPTION_MAX_SOCKET, NULL, 1},

	{"mb", "Set the RTP echo buffer size (default: 2048).", SIPP_OPTION_INT, &media_bufsize, 1},
	{"mp", "Set the local RTP echo port number. Default is 6000.", SIPP_OPTION_INT, &user_media_port, 1},

	{"nd", "No Default. Disable all default behavior of SIPp which are the following:\n"
	        "- On UDP retransmission timeout, abort the call by sending a BYE or a CANCEL\n"
	        "- On receive timeout with no ontimeout attribute, abort the call by sending a BYE or a CANCEL\n"
	        "- On unexpected BYE send a 200 OK and close the call\n"
	        "- On unexpected CANCEL send a 200 OK and close the call\n"
	        "- On unexpected PING send a 200 OK and continue the call\n"
	        "- On any other unexpected message, abort the call by sending a BYE or a CANCEL\n",
		SIPP_OPTION_UNSETFLAG, &default_behaviors, 1},
	{"nr", "Disable retransmission in UDP mode.", SIPP_OPTION_UNSETFLAG, &retrans_enabled, 1},

	{"nostdin", "Disable stdin.\n", SIPP_OPTION_SETFLAG, &nostdin, 1},

	{"p", "Set the local port number.  Default is a random free port chosen by the system.", SIPP_OPTION_INT, &user_port, 1},
	{"pause_msg_ign", "Ignore the messages received during a pause defined in the scenario ", SIPP_OPTION_SETFLAG, &pause_msg_ign, 1},
	{"periodic_rtd", "Reset response time partition counters each logging interval.", SIPP_OPTION_SETFLAG, &periodic_rtd, 1},

	{"r", "Set the call rate (in calls per seconds).  This value can be"
	      "changed during test by pressing '+','_','*' or '/'. Default is 10.\n"
	      "pressing '+' key to increase call rate by 1 * rate_scale,\n"
              "pressing '-' key to decrease call rate by 1 * rate_scale,\n"
              "pressing '*' key to increase call rate by 10 * rate_scale,\n"
              "pressing '/' key to decrease call rate by 10 * rate_scale.\n"
              "If the -rp option is used, the call rate is calculated with the period in ms given by the user.", SIPP_OPTION_FLOAT, &rate, 1},
	{"rp", "Specify the rate period for the call rate.  Default is 1 second and default unit is milliseconds.  This allows you to have n calls every m milliseconds (by using -r n -rp m).\n"
               "Example: -r 7 -rp 2000 ==> 7 calls every 2 seconds.\n         -r 10 -rp 5s => 10 calls every 5 seconds.", SIPP_OPTION_TIME_MS, &rate_period_ms, 1},
	{"rate_scale", "Control the units for the '+', '-', '*', and '/' keys.", SIPP_OPTION_FLOAT, &rate_scale, 1},
	{"rate_increase", "Specify the rate increase every -fd units (default is seconds).  This allows you to increase the load for each independent logging period.\n"
                      "Example: -rate_increase 10 -fd 10s\n"
                      "  ==> increase calls by 10 every 10 seconds.", SIPP_OPTION_INT, &rate_increase, 1},
	{"rate_max", "If -rate_increase is set, then quit after the rate reaches this value.\n"
                      "Example: -rate_increase 10 -rate_max 100\n"
                      "  ==> increase calls by 10 until 100 cps is hit.", SIPP_OPTION_INT, &rate_max, 1},
	{"no_rate_quit", "If -rate_increase is set, do not quit after the rate reaches -rate_max.", SIPP_OPTION_UNSETFLAG, &rate_quit, 1},
	{"recv_timeout", "Global receive timeout. Default unit is milliseconds. If the expected message is not received, the call times out and is aborted.", SIPP_OPTION_TIME_MS_LONG, &defl_recv_timeout, 1},
	{"send_timeout", "Global send timeout. Default unit is milliseconds. If a message is not sent (due to congestion), the call times out and is aborted.", SIPP_OPTION_TIME_MS_LONG, &defl_send_timeout, 1},
	{"reconnect_close", "Should calls be closed on reconnect?", SIPP_OPTION_BOOL, &reset_close, 1},
	{"reconnect_sleep", "How long (in milliseconds) to sleep between the close and reconnect?", SIPP_OPTION_TIME_MS, &reset_sleep, 1},
	{"ringbuffer_files", "How many error/message files should be kept after rotation?", SIPP_OPTION_INT, &ringbuffer_files, 1},
	{"ringbuffer_size", "How large should error/message files be before they get rotated?", SIPP_OPTION_LONG_LONG, &ringbuffer_size, 1},
	{"rsa", "Set the remote sending address to host:port for sending the messages.", SIPP_OPTION_RSA, NULL, 1},
	{"rtp_echo", "Enable RTP echo. RTP/UDP packets received on port defined by -mp are echoed to their sender.\n"
                     "RTP/UDP packets coming on this port + 2 are also echoed to their sender (used for sound and video echo).",
		     SIPP_OPTION_SETFLAG, &rtp_echo_enabled, 1},
	{"rtt_freq", "freq is mandatory. Dump response times every freq calls in the log file defined by -trace_rtt. Default value is 200.",
		     SIPP_OPTION_LONG, &report_freq_dumpRtt, 1},
	{"s", "Set the username part of the resquest URI. Default is 'service'.", SIPP_OPTION_STRING, &service, 1},
	{"sd", "Dumps a default scenario (embeded in the sipp executable)", SIPP_OPTION_SCENARIO, NULL, 0},
	{"sf", "Loads an alternate xml scenario file.  To learn more about XML scenario syntax, use the -sd option to dump embedded scenarios. They contain all the necessary help.", SIPP_OPTION_SCENARIO, NULL, 2},
	{"oocsf", "Load out-of-call scenario.", SIPP_OPTION_OOC_SCENARIO, NULL, 2},
	{"oocsn", "Load out-of-call scenario.", SIPP_OPTION_OOC_SCENARIO, NULL, 2},
	{"skip_rlimit", "Do not perform rlimit tuning of file descriptor limits.  Default: false.", SIPP_OPTION_SETFLAG, &skip_rlimit, 1},
	{"slave", "3pcc extended mode: indicates the slave number", SIPP_OPTION_3PCC_EXTENDED, &slave_number, 1},
	{"slave_cfg", "3pcc extended mode: indicates the file where the master and slave addresses are stored", SIPP_OPTION_SLAVE_CFG, NULL, 1},
	{"sn", "Use a default scenario (embedded in the sipp executable). If this option is omitted, the Standard SipStone UAC scenario is loaded.\n"
               "Available values in this version:\n\n"
               "- 'uac'      : Standard SipStone UAC (default).\n"
               "- 'uas'      : Simple UAS responder.\n"
               "- 'regexp'   : Standard SipStone UAC - with regexp and variables.\n"
               "- 'branchc'  : Branching and conditional branching in scenarios - client.\n"
               "- 'branchs'  : Branching and conditional branching in scenarios - server.\n\n"
               "Default 3pcc scenarios (see -3pcc option):\n\n"
               "- '3pcc-C-A' : Controller A side (must be started after all other 3pcc scenarios)\n"
               "- '3pcc-C-B' : Controller B side.\n"
               "- '3pcc-A'   : A side.\n"
               "- '3pcc-B'   : B side.\n", SIPP_OPTION_SCENARIO, NULL, 2},

	{"stat_delimiter", "Set the delimiter for the statistics file", SIPP_OPTION_STRING, &stat_delimiter, 1},
	{"stf", "Set the file name to use to dump statistics", SIPP_OPTION_ARGI, &argiFileName, 1},

	{"t", "Set the transport mode:\n"
              "- u1: UDP with one socket (default),\n"
              "- un: UDP with one socket per call,\n"
              "- ui: UDP with one socket per IP address The IP addresses must be defined in the injection file.\n"
              "- t1: TCP with one socket,\n"
              "- tn: TCP with one socket per call,\n"
              "- l1: TLS with one socket,\n"
              "- ln: TLS with one socket per call,\n"
              "- c1: u1 + compression (only if compression plugin loaded),\n"
              "- cn: un + compression (only if compression plugin loaded).  This plugin is not provided with sipp.\n"
	      , SIPP_OPTION_TRANSPORT, NULL, 1},

	{"timeout", "Global timeout. Default unit is seconds.  If this option is set, SIPp quits after nb units (-timeout 20s quits after 20 seconds).", SIPP_OPTION_TIME_SEC, &global_timeout, 1},
	{"timer_resol", "Set the timer resolution. Default unit is milliseconds.  This option has an impact on timers precision."
                      "Small values allow more precise scheduling but impacts CPU usage."
                      "If the compression is on, the value is set to 50ms. The default value is 10ms.", SIPP_OPTION_TIME_MS, &timer_resolution, 1},

	{"sendbuffer_warn", "Produce warnings instead of errors on SendBuffer failures.", SIPP_OPTION_BOOL, &sendbuffer_warn, 1},

	{"trace_msg", "Displays sent and received SIP messages in <scenario file name>_<pid>_messages.log", SIPP_OPTION_SETFLAG, &useMessagef, 1},
  {"trace_shortmsg", "Displays sent and received SIP messages as CSV in <scenario file name>_<pid>_shortmessages.log", SIPP_OPTION_SETFLAG, &useShortMessagef, 1},
	{"trace_screen", "Dump statistic screens in the <scenario_name>_<pid>_screens.log file when quitting SIPp. Useful to get a final status report in background mode (-bg option).", SIPP_OPTION_SETFLAG, &useScreenf, 1},
	{"trace_err", "Trace all unexpected messages in <scenario file name>_<pid>_errors.log.", SIPP_OPTION_SETFLAG, &print_all_responses, 1},
//	{"trace_timeout", "Displays call ids for calls with timeouts in <scenario file name>_<pid>_timeout.log", SIPP_OPTION_SETFLAG, &useTimeoutf, 1},
	{"trace_stat", "Dumps all statistics in <scenario_name>_<pid>.csv file. Use the '-h stat' option for a detailed description of the statistics file content.", SIPP_OPTION_SETFLAG, &dumpInFile, 1},
	{"trace_counts", "Dumps individual message counts in a CSV file.", SIPP_OPTION_SETFLAG, &useCountf, 1},
	{"trace_rtt", "Allow tracing of all response times in <scenario file name>_<pid>_rtt.csv.", SIPP_OPTION_SETFLAG, &dumpInRtt, 1},
	{"trace_logs", "Allow tracing of <log> actions in <scenario file name>_<pid>_logs.log.", SIPP_OPTION_SETFLAG, &useLogf, 1},

	{"users", "Instead of starting calls at a fixed rate, begin 'users' calls at startup, and keep the number of calls constant.", SIPP_OPTION_USERS, NULL, 1},

#ifdef _USE_OPENSSL
	{"ap", "Set the password for authentication challenges. Default is 'password", SIPP_OPTION_STRING, &auth_password, 1},
	{"tls_cert", "Set the name for TLS Certificate file. Default is 'cacert.pem", SIPP_OPTION_STRING, &tls_cert_name, 1},
	{"tls_key", "Set the name for TLS Private Key file. Default is 'cakey.pem'", SIPP_OPTION_STRING, &tls_key_name, 1},
	{"tls_crl", "Set the name for Certificate Revocation List file. If not specified, X509 CRL is not activated.", SIPP_OPTION_STRING, &tls_crl_name, 1},
#else
	{"ap", NULL, SIPP_OPTION_NEED_SSL, NULL, 1},
	{"tls_cert", NULL, SIPP_OPTION_NEED_SSL, NULL, 1},
	{"tls_key", NULL, SIPP_OPTION_NEED_SSL, NULL, 1},
	{"tls_crl", NULL, SIPP_OPTION_NEED_SSL, NULL, 1},
#endif
	{"3pcc", "Launch the tool in 3pcc mode (\"Third Party call control\"). The passed ip address is depending on the 3PCC role.\n"
                 "- When the first twin command is 'sendCmd' then this is the address of the remote twin socket.  SIPp will try to connect to this address:port to send the twin command (This instance must be started after all other 3PCC scenarii).\n"
                 "    Example: 3PCC-C-A scenario.\n"
                 "- When the first twin command is 'recvCmd' then this is the address of the local twin socket. SIPp will open this address:port to listen for twin command.\n"
		 "    Example: 3PCC-C-B scenario.", SIPP_OPTION_3PCC, NULL, 1},
	{"tdmmap", "Generate and handle a table of TDM circuits.\n"
                   "A circuit must be available for the call to be placed.\n"
                   "Format: -tdmmap {0-3}{99}{5-8}{1-31}", SIPP_OPTION_TDMMAP, NULL, 1},
	{"key", "keyword value\nSet the generic parameter named \"keyword\" to \"value\".", SIPP_OPTION_KEY, NULL, 1},
};

struct sipp_option *find_option(const char *option) {
	int i;
	int max = sizeof(options_table)/sizeof(options_table[0]);

	/* Allow options to start with '-' or '--' */
	if (option[0] != '-') {
	  return NULL;
	}
	option++;
	if (option[0] == '-') {
	  option++;
	}

	for (i = 0; i < max; i++) {
	  if (!strcmp(options_table[i].option, option)) {
	    return &(options_table[i]);
	  }
	}

	return NULL;
};

/***************** System Portability Features *****************/

unsigned long long getmicroseconds()
{
  struct timeval LS_system_time;
  unsigned long long VI_micro;
  static unsigned long long VI_micro_base = 0;

  gettimeofday(&LS_system_time, NULL);
  VI_micro = (((unsigned long long) LS_system_time.tv_sec) * 1000000LL) + LS_system_time.tv_usec;
  if (!VI_micro_base) VI_micro_base = VI_micro - 1;
  VI_micro = VI_micro - VI_micro_base;

  return VI_micro;
}

unsigned long getmilliseconds()
{
  return getmicroseconds() / 1000LL;
}


#ifdef _USE_OPENSSL
/****** SSL error handling                         *************/
const char *sip_tls_error_string(SSL *ssl, int size) {
  int err;
  err=SSL_get_error(ssl, size);
  switch(err) {
    case SSL_ERROR_NONE:
      return "No error";
    case SSL_ERROR_WANT_WRITE:
      return "SSL_read returned SSL_ERROR_WANT_WRITE";
    case SSL_ERROR_WANT_READ:
      return "SSL_read returned SSL_ERROR_WANT_READ";
    case SSL_ERROR_WANT_X509_LOOKUP:
      return "SSL_read returned SSL_ERROR_WANT_X509_LOOKUP";
      break;
    case SSL_ERROR_SYSCALL:
      if(size<0) { /* not EOF */
	return strerror(errno);
      } else { /* EOF */
        return "SSL socket closed on SSL_read";
      }
  }
  return "Unknown SSL Error.";
}

/****** Certificate Verification Callback FACILITY *************/
int sip_tls_verify_callback(int ok , X509_STORE_CTX *store)
{
  char data[512];
  
  if (!ok) {
     X509 *cert = X509_STORE_CTX_get_current_cert(store);

     X509_NAME_oneline(X509_get_issuer_name(cert),
                                   data,512);
     WARNING("TLS verification error for issuer: '%s'", data);
     X509_NAME_oneline(X509_get_subject_name(cert),
                                   data,512);
     WARNING("TLS verification error for subject: '%s'", data);
  }
  return ok;
}

/***********  Load the CRL's into SSL_CTX **********************/
int sip_tls_load_crls( SSL_CTX *ctx , char *crlfile)
{
  X509_STORE          *store;
  X509_LOOKUP         *lookup;

  /*  Get the X509_STORE from SSL context */
  if (!(store = SSL_CTX_get_cert_store(ctx))) {
    return (-1);
  }

  /* Add lookup file to X509_STORE */
  if (!(lookup = X509_STORE_add_lookup(store,X509_LOOKUP_file()))) {
    return (-1);
  }

  /* Add the CRLS to the lookpup object */
  if (X509_load_crl_file(lookup,crlfile,X509_FILETYPE_PEM) != 1) {
    return (-1);
  }

  /* Set the flags of the store so that CRLS's are consulted */
#if OPENSSL_VERSION_NUMBER >= 0x00907000L
  X509_STORE_set_flags( store,X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
#else
#warning This version of OpenSSL (<0.9.7) cannot handle CRL files in capath
  ERROR("This version of OpenSSL (<0.9.7) cannot handle CRL files in capath");
#endif

  return (1);
}

/************* Prepare the SSL context ************************/
static ssl_init_status FI_init_ssl_context (void)
{
  sip_trp_ssl_ctx = SSL_CTX_new( TLSv1_method() ); 
  if ( sip_trp_ssl_ctx == NULL ) {
    ERROR("FI_init_ssl_context: SSL_CTX_new with TLSv1_method failed");
    return SSL_INIT_ERROR;
  }

  sip_trp_ssl_ctx_client = SSL_CTX_new( TLSv1_method() );
  if ( sip_trp_ssl_ctx_client == NULL)
  {
    ERROR("FI_init_ssl_context: SSL_CTX_new with TLSv1_method failed");
    return SSL_INIT_ERROR;
  }

  /*  Load the trusted CA's */
  SSL_CTX_load_verify_locations(sip_trp_ssl_ctx, tls_cert_name, NULL);
  SSL_CTX_load_verify_locations(sip_trp_ssl_ctx_client, tls_cert_name, NULL);
  
  /*  CRL load from application specified only if specified on the command line */
  if (strlen(tls_crl_name) != 0) {
    if(sip_tls_load_crls(sip_trp_ssl_ctx,tls_crl_name) == -1) {
      ERROR("FI_init_ssl_context: Unable to load CRL file (%s)", tls_crl_name);
      return SSL_INIT_ERROR;
    }
  
    if(sip_tls_load_crls(sip_trp_ssl_ctx_client,tls_crl_name) == -1) {
      ERROR("FI_init_ssl_context: Unable to load CRL (client) file (%s)", tls_crl_name);
      return SSL_INIT_ERROR;
    }
    /* The following call forces to process the certificates with the */
    /* initialised SSL_CTX                                            */
    SSL_CTX_set_verify(sip_trp_ssl_ctx,
                       SSL_VERIFY_PEER |
                       SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       sip_tls_verify_callback);

    SSL_CTX_set_verify(sip_trp_ssl_ctx_client,
                       SSL_VERIFY_PEER |
                       SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       sip_tls_verify_callback);
  }


  /* Selection Cipher suits - load the application specified ciphers */
  SSL_CTX_set_default_passwd_cb_userdata(sip_trp_ssl_ctx,
                                             (void *)CALL_BACK_USER_DATA );
  SSL_CTX_set_default_passwd_cb_userdata(sip_trp_ssl_ctx_client,
                                             (void *)CALL_BACK_USER_DATA );
  SSL_CTX_set_default_passwd_cb( sip_trp_ssl_ctx,
                                             passwd_call_back_routine );
  SSL_CTX_set_default_passwd_cb( sip_trp_ssl_ctx_client,
                                             passwd_call_back_routine );

  if ( SSL_CTX_use_certificate_file(sip_trp_ssl_ctx,
                                        tls_cert_name,
                                        SSL_FILETYPE_PEM ) != 1 ) {
    ERROR("FI_init_ssl_context: SSL_CTX_use_certificate_file failed");
    return SSL_INIT_ERROR;
  }

  if ( SSL_CTX_use_certificate_file(sip_trp_ssl_ctx_client,
                                        tls_cert_name,
                                        SSL_FILETYPE_PEM ) != 1 ) {
    ERROR("FI_init_ssl_context: SSL_CTX_use_certificate_file (client) failed");
    return SSL_INIT_ERROR;
  }
  if ( SSL_CTX_use_PrivateKey_file(sip_trp_ssl_ctx,
                                       tls_key_name,
                                       SSL_FILETYPE_PEM ) != 1 ) {
    ERROR("FI_init_ssl_context: SSL_CTX_use_PrivateKey_file failed");
    return SSL_INIT_ERROR;
  }

  if ( SSL_CTX_use_PrivateKey_file(sip_trp_ssl_ctx_client,
                                       tls_key_name,
                                       SSL_FILETYPE_PEM ) != 1 ) {
    ERROR("FI_init_ssl_context: SSL_CTX_use_PrivateKey_file (client) failed");
    return SSL_INIT_ERROR;
  }

  return SSL_INIT_NORMAL;
}

int send_nowait_tls(SSL *ssl, const void *msg, int len, int flags)
{
  int initial_fd_flags;
  int rc;
  int fd;
  int fd_flags;
  if ( (fd = SSL_get_fd(ssl)) == -1 ) {
    return (-1);
  }
  fd_flags = fcntl(fd, F_GETFL , NULL);
  initial_fd_flags = fd_flags;
  fd_flags |= O_NONBLOCK;
  fcntl(fd, F_SETFL , fd_flags);
  rc = SSL_write(ssl,msg,len);
  if ( rc <= 0 ) {
    return(rc);
  }
  fcntl(fd, F_SETFL , initial_fd_flags);
  return rc;
}
#endif 

int send_nowait(int s, const void *msg, int len, int flags)
{
#if defined(MSG_DONTWAIT) && !defined(__SUNOS)
  return send(s, msg, len, flags | MSG_DONTWAIT);
#else
  int fd_flags = fcntl(s, F_GETFL , NULL);
  int initial_fd_flags;
  int rc;

  initial_fd_flags = fd_flags;
  //  fd_flags &= ~O_ACCMODE; // Remove the access mode from the value
  fd_flags |= O_NONBLOCK;
  fcntl(s, F_SETFL , fd_flags);
  
  rc = send(s, msg, len, flags);

  fcntl(s, F_SETFL , initial_fd_flags);

  return rc;
#endif 
}

char * get_inet_address(struct sockaddr_storage * addr)
{
  static char * ip_addr = NULL;

  if (!ip_addr) {
    ip_addr = (char *)malloc(1024*sizeof(char));
  }
  if (getnameinfo(_RCAST(struct sockaddr *, addr),
                  SOCK_ADDR_SIZE(addr),
                  ip_addr,
                  1024,
                  NULL,
                  0,
                  NI_NUMERICHOST) != 0) {
    strcpy(ip_addr, "addr not supported");
  }

  return ip_addr;
}

void get_host_and_port(char * addr, char * host, int * port)
{
  /* Separate the port number (if any) from the host name.
   * Thing is, the separator is a colon (':').  The colon may also exist
   * in the host portion if the host is specified as an IPv6 address (see
   * RFC 2732).  If that's the case, then we need to skip past the IPv6
   * address, which should be contained within square brackets ('[',']').
   */
  char *p;
  p = strchr( addr, '[' );                      /* Look for '['.            */
  if( p != NULL ) {                             /* If found, look for ']'.  */
    p = strchr( p, ']' );
  }
  if( p == NULL ) {                             /* If '['..']' not found,   */
    p = addr;                                   /* scan the whole string.   */
  } else {                                      /* If '['..']' found,       */
    char *p1;                                   /* extract the remote_host  */
    char *p2;
    p1 = strchr( addr, '[' );
    p2 = strchr( addr, ']' );
    *p2 = '\0';
    strcpy(host, p1 + 1);
    *p2 = ']';
  }
  /* Starting at <p>, which is either the start of the host substring
   * or the end of the IPv6 address, find the last colon character.
   */
  p = strchr( p, ':' );
  if( NULL != p ) {
    *p = '\0';
    *port = atol(p + 1);
  } else {
    *port = 0;
  }
}

static unsigned char tolower_table[256];

void init_tolower_table() {
  for (int i = 0; i < 256; i++) {
    tolower_table[i] = tolower(i);
  }
}

/* This is simpler than doing a regular tolower, because there are no branches.
 * We also inline it, so that we don't have function call overheads.
 *
 * An alternative to a table would be to do (c | 0x20), but that only works if
 * we are sure that we are searching for characters (or don't care if they are
 * not characters. */
unsigned char inline mytolower(unsigned char c) {
  return tolower_table[c];
}

char * strcasestr2(char *s, char *find) {
  char c, sc;
  size_t len;

  if ((c = *find++) != 0) {
    c = mytolower((unsigned char)c);
    len = strlen(find);
    do {
      do {
        if ((sc = *s++) == 0)
        return (NULL);
      } while ((char)mytolower((unsigned char)sc) != c);
    } while (strncasecmp(s, find, len) != 0);
    s--;
  }
  return ((char *)s);
}

char * strncasestr(char *s, char *find, size_t n) {
  char *end = s + n;
  char c, sc;
  size_t len;

  if ((c = *find++) != 0) {
    c = mytolower((unsigned char)c);
    len = strlen(find);
    end -= (len - 1);
    do {
      do {
        if ((sc = *s++) == 0)
	  return (NULL);
	if (s >= end)
	  return (NULL);
      } while ((char)mytolower((unsigned char)sc) != c);
    } while (strncasecmp(s, find, len) != 0);
    s--;
  }
  return ((char *)s);
}

int get_decimal_from_hex(char hex) {
  if (isdigit(hex))
    return hex - '0';
  else
    return tolower(hex) - 'a' + 10;
}


/******************** Recv Poll Processing *********************/

int                  pollnfds;
unsigned int	     call_sockets;
struct pollfd        pollfiles[SIPP_MAXFDS];
struct sipp_socket  *sockets[SIPP_MAXFDS];

static int pending_messages = 0;

map<string, struct sipp_socket *>     map_perip_fd;

/***************** Check of the message received ***************/

bool sipMsgCheck (const char *P_msg, int P_msgSize, struct sipp_socket *socket) {
  const char C_sipHeader[] = "SIP/2.0" ;

  if (socket == twinSippSocket || socket == localTwinSippSocket ||
      is_a_peer_socket(socket) || is_a_local_socket(socket))
	return true;

  if (strstr(P_msg, C_sipHeader) !=  NULL) {
    return true ;
  }

  return false ;
}

/************** Statistics display & User control *************/

void print_stats_in_file(FILE * f, int last)
{
  int index;
  static char temp_str[256];
  int divisor;

#define SIPP_ENDL "\r\n"

  /* We are not initialized yet. */
  if (!display_scenario) {
    return;
  }

  /* Optional timestamp line for files only */
  if(f != stdout) {
    time_t tim;
    time(&tim);
    fprintf(f, "  Timestamp: %s" SIPP_ENDL, ctime(&tim));
  }
  
  /* Header line with global parameters */
  if (users >= 0) {
    sprintf(temp_str, "%d (%d ms)", users, duration);
  } else {
    sprintf(temp_str, "%3.1f(%d ms)/%5.3fs", rate, duration, (double)rate_period_ms / 1000.0);
  }
  unsigned long long total_calls = display_scenario->stats->GetStat(CStat::CPT_C_IncomingCallCreated) + display_scenario->stats->GetStat(CStat::CPT_C_OutgoingCallCreated);
  if( toolMode == MODE_SERVER) {
    fprintf
      (f,
       "  Port   Total-time  Total-calls  Transport" 
       SIPP_ENDL
       "  %-5d %6d.%02d s     %8llu  %s"
       SIPP_ENDL SIPP_ENDL,
       local_port,
       clock_tick / 1000, (clock_tick % 1000) / 10,
       total_calls,
       TRANSPORT_TO_STRING(transport));
  } else {
    if (users >= 0) {
      fprintf(f, "     Users (length)");
    } else {
      fprintf(f, "  Call-rate(length)");
    }
    fprintf(f, "   Port   Total-time  Total-calls  Remote-host" SIPP_ENDL
       "%19s   %-5d %6d.%02d s     %8llu  %s:%d(%s)" SIPP_ENDL SIPP_ENDL,
       temp_str,
       local_port,
       clock_tick / 1000, (clock_tick % 1000) / 10,
       total_calls,
       remote_ip,
       remote_port,
       TRANSPORT_TO_STRING(transport));
  }
  
  /* 1st line */
  if(total_calls < stop_after) {
    sprintf(temp_str, "%llu new calls during %lu.%03lu s period ",
	display_scenario->stats->GetStat(CStat::CPT_PD_IncomingCallCreated) +
	display_scenario->stats->GetStat(CStat::CPT_PD_OutgoingCallCreated),
	(clock_tick-last_report_time) / 1000,
	((clock_tick-last_report_time) % 1000));
  } else {
    sprintf(temp_str, "Call limit reached (-m %lu), %lu.%03lu s period ",
            stop_after,
            (clock_tick-last_report_time) / 1000, 
            ((clock_tick-last_report_time) % 1000));
  }
  divisor = scheduling_loops; if(!divisor) { divisor = 1; }
  fprintf(f,"  %-38s %d ms scheduler resolution" 
         SIPP_ENDL,
         temp_str,
         (clock_tick-last_report_time) / divisor);

  /* 2nd line */
  if( toolMode == MODE_SERVER) { 
    sprintf(temp_str, "%llu calls", display_scenario->stats->GetStat(CStat::CPT_C_CurrentCall));
  } else {
    sprintf(temp_str, "%llu calls (limit %d)", display_scenario->stats->GetStat(CStat::CPT_C_CurrentCall), open_calls_allowed);
  }
  fprintf(f,"  %-38s Peak was %llu calls, after %llu s" SIPP_ENDL,
         temp_str, 
         display_scenario->stats->GetStat(CStat::CPT_C_CurrentCallPeak),
         display_scenario->stats->GetStat(CStat::CPT_C_CurrentCallPeakTime));
  fprintf(f,"  %d Running, %d Paused, %d Woken up" SIPP_ENDL,
	 last_running_calls, last_paused_calls, last_woken_calls);
  last_woken_calls = 0;

  /* 3rd line dead call msgs, and optional out-of-call msg */
  sprintf(temp_str,"%llu dead call msg (discarded)",
      display_scenario->stats->GetStat(CStat::CPT_G_C_DeadCallMsgs));
  fprintf(f,"  %-37s", temp_str);
  if( toolMode != MODE_SERVER) { 
    sprintf(temp_str,"%llu out-of-call msg (discarded)",
            display_scenario->stats->GetStat(CStat::CPT_G_C_OutOfCallMsgs));
    fprintf(f,"  %-37s", temp_str);
  }
  fprintf(f,SIPP_ENDL);

  if(compression) {
    fprintf(f,"  Comp resync: %d sent, %d recv" , 
           resynch_send, resynch_recv);
    fprintf(f,SIPP_ENDL);
  }

  /* 4th line , sockets and optional errors */ 
  sprintf(temp_str,"%d open sockets", 
          pollnfds);
  fprintf(f,"  %-38s", temp_str);
  if(nb_net_recv_errors || nb_net_send_errors || nb_net_cong) {
    fprintf(f,"  %d/%d/%d %s errors (send/recv/cong)" SIPP_ENDL,
           nb_net_send_errors, 
           nb_net_recv_errors,
           nb_net_cong,
           TRANSPORT_TO_STRING(transport));
  } else {
    fprintf(f,SIPP_ENDL);
  }

#ifdef PCAPPLAY
  /* if has media abilities */
  if (hasMedia != 0) {
    sprintf(temp_str, "%lu Total RTP pckts sent ",
            rtp_pckts_pcap);
    if (clock_tick-last_report_time) {
       fprintf(f,"  %-38s %d.%03d last period RTP rate (kB/s)" SIPP_ENDL,
              temp_str,
              (rtp_bytes_pcap)/(clock_tick-last_report_time),
              (rtp_bytes_pcap)%(clock_tick-last_report_time));
    }
    rtp_bytes_pcap = 0;
    rtp2_bytes_pcap = 0;
  }
#endif

  /* 5th line, RTP echo statistics */
  if (rtp_echo_enabled && (media_socket > 0)) {
    sprintf(temp_str, "%lu Total echo RTP pckts 1st stream",
            rtp_pckts);

    // AComment: Fix for random coredump when using RTP echo
    if (clock_tick-last_report_time) {
       fprintf(f,"  %-38s %d.%03d last period RTP rate (kB/s)" SIPP_ENDL,
              temp_str,
              (rtp_bytes)/(clock_tick-last_report_time),
              (rtp_bytes)%(clock_tick-last_report_time));
    }
    /* second stream statitics: */
    sprintf(temp_str, "%lu Total echo RTP pckts 2nd stream",
            rtp2_pckts);

    // AComment: Fix for random coredump when using RTP echo
    if (clock_tick-last_report_time) {
      fprintf(f,"  %-38s %d.%03d last period RTP rate (kB/s)" SIPP_ENDL,
	      temp_str,
	      (rtp2_bytes)/(clock_tick-last_report_time),
	      (rtp2_bytes)%(clock_tick-last_report_time));
    }
    rtp_bytes = 0;
    rtp2_bytes = 0;
  }

  /* Scenario counters */
  fprintf(f,SIPP_ENDL);
  if(!lose_packets) {
    fprintf(f,"                                 "
           "Messages  Retrans   Timeout   Unexpected-Msg" 
           SIPP_ENDL);
  } else {
    fprintf(f,"                                 "
           "Messages  Retrans   Timeout   Unexp.    Lost" 
           SIPP_ENDL);
  }
  for(index = 0;
      index < display_scenario->length;
      index ++) {
    message *curmsg = display_scenario->messages[index];

    if(do_hide && curmsg->hide) {
      continue;
    }
    if (show_index) {
	fprintf(f, "%-02d:", index);
    }
    
    if(SendingMessage *src = curmsg -> send_scheme) {
      if (src->isResponse()) {
	sprintf(temp_str, "%d", src->getCode());
      } else {
	sprintf(temp_str, "%s", src->getMethod());
      }

      if(toolMode == MODE_SERVER) {
        fprintf(f,"  <---------- %-10s ", temp_str);
      } else {
        fprintf(f,"  %10s ----------> ", temp_str);
      }
      if (curmsg -> start_rtd) {
	fprintf(f, " B-RTD%d ", curmsg -> start_rtd);
      } else if (curmsg -> stop_rtd) {
	fprintf(f, " E-RTD%d ", curmsg -> stop_rtd);
      } else {
	fprintf(f, "        ");
      }

      if(curmsg -> retrans_delay) {
        fprintf(f,"%-9d %-9d %-9d %-9s" ,
               curmsg -> nb_sent,
               curmsg -> nb_sent_retrans,
               curmsg -> nb_timeout,
               "" /* Unexpected */);
      } else {
        fprintf(f,"%-9d %-9d %-9s %-9s" ,
               curmsg -> nb_sent,
               curmsg -> nb_sent_retrans,
               "", /* Timeout. */
               "" /* Unexpected. */);
      }
    } else if(curmsg -> recv_response) {
      if(toolMode == MODE_SERVER) {
	fprintf(f,"  ----------> %-10d ", curmsg -> recv_response);
      } else { 
	fprintf(f,"  %10d <---------- ", curmsg -> recv_response);
      }

      if (curmsg -> start_rtd) {
	fprintf(f, " B-RTD%d ", curmsg -> start_rtd);
      } else if (curmsg -> stop_rtd) {
	fprintf(f, " E-RTD%d ", curmsg -> stop_rtd);
      } else {
	fprintf(f, "        ");
      }

      if(curmsg->retrans_delay) {
        fprintf(f,"%-9ld %-9ld %-9ld %-9ld" ,
               curmsg->nb_recv,
               curmsg->nb_recv_retrans,
               curmsg->nb_timeout,
               curmsg->nb_unexp);
      } else {
        fprintf(f,"%-9ld %-9ld %-9ld %-9ld" ,
               curmsg -> nb_recv,
               curmsg -> nb_recv_retrans,
               curmsg -> nb_timeout,
               curmsg -> nb_unexp);
      }
    } else if (curmsg -> pause_distribution ||
	       (curmsg -> pause_variable != -1)) {
      char *desc = curmsg->pause_desc;
      if (!desc) {
	desc = (char *)malloc(24);
	if (curmsg->pause_distribution) {
	  desc[0] = '\0';
	  curmsg->pause_distribution->timeDescr(desc, 23);
	} else {
	  snprintf(desc, 23, "$%s", display_scenario->allocVars->getName(curmsg->pause_variable));
	}
	desc[23] = '\0';
	curmsg->pause_desc = desc;
      }
      int len = strlen(desc) < 9 ? 9 : strlen(desc);

      if(toolMode == MODE_SERVER) {
	fprintf(f,"  [%9s] Pause%*s", desc, 23 - len > 0 ? 23 - len : 0, "");
      } else {
	fprintf(f,"       Pause [%9s]%*s", desc, 18 - len > 0 ? 18 - len : 0, "");
      }

      fprintf(f,"%-9d", curmsg->sessions);
      fprintf(f,"                     %-9d" , curmsg->nb_unexp);
    } else if(curmsg -> recv_request) {
      if(toolMode == MODE_SERVER) {
	fprintf(f,"  ----------> %-10s ", curmsg -> recv_request);
      } else {
	fprintf(f,"  %10s <---------- ", curmsg -> recv_request);
      }

      if (curmsg -> start_rtd) {
	fprintf(f, " B-RTD%d ", curmsg -> start_rtd);
      } else if (curmsg -> stop_rtd) {
	fprintf(f, " E-RTD%d ", curmsg -> stop_rtd);
      } else {
	fprintf(f, "        ");
      }

      fprintf(f,"%-9ld %-9ld %-9ld %-9ld" ,
	  curmsg -> nb_recv,
	  curmsg -> nb_recv_retrans,
	  curmsg -> nb_timeout,
	  curmsg -> nb_unexp);
    }
    else if(curmsg -> M_type == MSG_TYPE_NOP) {
      if (curmsg->display_str) {
	fprintf(f," %s", curmsg->display_str);
      } else {
	fprintf(f,"              [ NOP ]              ");
      }
    }
    else if(curmsg -> M_type == MSG_TYPE_RECVCMD) {
      fprintf(f,"    [ Received Command ]         ");
      if(curmsg->retrans_delay) {
        fprintf(f,"%-9ld %-9s %-9ld %-9s" ,
                curmsg->M_nbCmdRecv,
                "",
                curmsg->nb_timeout,
                "");
      } else {
         fprintf(f,"%-9ld %-9s           %-9s" ,
                curmsg -> M_nbCmdRecv,
                "",
                "");
      }
    } else if(curmsg -> M_type == MSG_TYPE_SENDCMD) {
      fprintf(f,"        [ Sent Command ]         ");
      fprintf(f,"%-9d %-9s           %-9s" ,
             curmsg -> M_nbCmdSent,
             "",
             "");
    }
    else {
      ERROR("Scenario command not implemented in display\n");
    }
    
    if(lose_packets && (curmsg -> nb_lost)) {
      fprintf(f," %-9d" SIPP_ENDL,
             curmsg -> nb_lost);
    } else {
      fprintf(f,SIPP_ENDL);
    }
    
    if(curmsg -> crlf) {
      fprintf(f,SIPP_ENDL);
    }
  }
}

void print_count_file(FILE *f, int header) {
  char temp_str[256];

  if (header) {
    fprintf(f, "CurrentTime%sElapsedTime%s", stat_delimiter, stat_delimiter);
  } else {
    struct timeval currentTime, startTime;
    GET_TIME(&currentTime);
    display_scenario->stats->getStartTime(&startTime);
    unsigned long globalElapsedTime = CStat::computeDiffTimeInMs (&currentTime, &startTime);
    fprintf(f, "%s%s", CStat::formatTime(&currentTime), stat_delimiter);
    fprintf(f, "%s%s", CStat::msToHHMMSSmmm(globalElapsedTime), stat_delimiter);
  }

  for(int index = 0; index < main_scenario->length; index ++) {
    message *curmsg = main_scenario->messages[index];
    if(curmsg->hide) {
      continue;
    }

    if(SendingMessage *src = curmsg -> send_scheme) {
      if(header) {
	if (src->isResponse()) {
	  sprintf(temp_str, "%d_%d_", index, src->getCode());
	} else {
	  sprintf(temp_str, "%d_%s_", index, src->getMethod());
	}

	fprintf(f, "%sSent%s", temp_str, stat_delimiter);
	fprintf(f, "%sRetrans%s", temp_str, stat_delimiter);
	if(curmsg -> retrans_delay) {
	  fprintf(f, "%sTimeout%s", temp_str, stat_delimiter);
	}
	if(lose_packets) {
	  fprintf(f, "%sLost%s", temp_str, stat_delimiter);
	}
      } else {
	fprintf(f, "%d%s", curmsg->nb_sent, stat_delimiter);
	fprintf(f, "%d%s", curmsg->nb_sent_retrans, stat_delimiter);
	if(curmsg -> retrans_delay) {
	  fprintf(f, "%d%s", curmsg->nb_timeout, stat_delimiter);
	}
	if(lose_packets) {
	  fprintf(f, "%d%s", curmsg->nb_lost, stat_delimiter);
	}
      }
    } else if(curmsg -> recv_response) {
      if(header) {
	sprintf(temp_str, "%d_%d_", index, curmsg->recv_response);

	fprintf(f, "%sRecv%s", temp_str, stat_delimiter);
	fprintf(f, "%sRetrans%s", temp_str, stat_delimiter);
	fprintf(f, "%sTimeout%s", temp_str, stat_delimiter);
	fprintf(f, "%sUnexp%s", temp_str, stat_delimiter);
	if(lose_packets) {
	  fprintf(f, "%sLost%s", temp_str, stat_delimiter);
	}
      } else {
	fprintf(f, "%d%s", curmsg->nb_recv, stat_delimiter);
	fprintf(f, "%d%s", curmsg->nb_recv_retrans, stat_delimiter);
	fprintf(f, "%d%s", curmsg->nb_timeout, stat_delimiter);
	fprintf(f, "%d%s", curmsg->nb_unexp, stat_delimiter);
	if(lose_packets) {
	  fprintf(f, "%d%s", curmsg->nb_lost, stat_delimiter);
	}
      }
    } else if(curmsg -> recv_request) {
      if(header) {
	sprintf(temp_str, "%d_%s_", index, curmsg->recv_request);

	fprintf(f, "%sRecv%s", temp_str, stat_delimiter);
	fprintf(f, "%sRetrans%s", temp_str, stat_delimiter);
	fprintf(f, "%sTimeout%s", temp_str, stat_delimiter);
	fprintf(f, "%sUnexp%s", temp_str, stat_delimiter);
	if(lose_packets) {
	  fprintf(f, "%sLost%s", temp_str, stat_delimiter);
	}
      } else {
	fprintf(f, "%d%s", curmsg->nb_recv, stat_delimiter);
	fprintf(f, "%d%s", curmsg->nb_recv_retrans, stat_delimiter);
	fprintf(f, "%d%s", curmsg->nb_timeout, stat_delimiter);
	fprintf(f, "%d%s", curmsg->nb_unexp, stat_delimiter);
	if(lose_packets) {
	  fprintf(f, "%d%s", curmsg->nb_lost, stat_delimiter);
	}
      }
    } else if (curmsg -> pause_distribution ||
	curmsg -> pause_variable) {

      if(header) {
	sprintf(temp_str, "%d_Pause_", index);
	fprintf(f, "%sSessions%s", temp_str, stat_delimiter);
	fprintf(f, "%sUnexp%s", temp_str, stat_delimiter);
      } else {
	fprintf(f, "%d%s", curmsg->sessions, stat_delimiter);
	fprintf(f, "%d%s", curmsg->nb_unexp, stat_delimiter);
      }
    } else if(curmsg -> M_type == MSG_TYPE_NOP) {
      /* No output. */
    }  else if(curmsg -> M_type == MSG_TYPE_RECVCMD) {
      if(header) {
	sprintf(temp_str, "%d_RecvCmd", index);
	fprintf(f, "%s%s", temp_str, stat_delimiter);
	fprintf(f, "%s_Timeout%s", temp_str, stat_delimiter);
      } else {
	fprintf(f, "%d%s", curmsg->M_nbCmdRecv, stat_delimiter);
	fprintf(f, "%d%s", curmsg->nb_timeout, stat_delimiter);
      }
    } else if(curmsg -> M_type == MSG_TYPE_SENDCMD) {
      if(header) {
	sprintf(temp_str, "%d_SendCmd", index);
	fprintf(f, "%s%s", temp_str);
      } else {
	fprintf(f, "%d%s", curmsg->M_nbCmdSent, stat_delimiter);
      }
    } else {
      ERROR("Unknown count file message type:");
    }
  }
  fprintf(f, "\n");
  fflush(f);
}

void print_header_line(FILE *f, int last)
{  
  switch(currentScreenToDisplay)
    {
    case DISPLAY_STAT_SCREEN :
      fprintf(f,"----------------------------- Statistics Screen ------- [1-9]: Change Screen --" SIPP_ENDL);
      break;
    case DISPLAY_REPARTITION_SCREEN :
      fprintf(f,"---------------------------- Repartition Screen ------- [1-9]: Change Screen --" SIPP_ENDL);
      break;
    case DISPLAY_VARIABLE_SCREEN  :
      fprintf(f,"----------------------------- Variables Screen -------- [1-9]: Change Screen --" SIPP_ENDL);
      break;
    case DISPLAY_TDM_MAP_SCREEN  :
      fprintf(f,"------------------------------ TDM map Screen --------- [1-9]: Change Screen --" SIPP_ENDL);
      break;
    case DISPLAY_SECONDARY_REPARTITION_SCREEN :
      fprintf(f,"--------------------------- Repartition %d Screen ------ [1-9]: Change Screen --" SIPP_ENDL, currentRepartitionToDisplay);
      break;
    case DISPLAY_SCENARIO_SCREEN :
    default:
      fprintf(f,"------------------------------ Scenario Screen -------- [1-9]: Change Screen --" SIPP_ENDL);
      break;
    }
}

void print_bottom_line(FILE *f, int last)
{
  if(last) {
    fprintf(f,"------------------------------ Test Terminated --------------------------------" SIPP_ENDL);
  } else if(quitting) {
    fprintf(f,"------- Waiting for active calls to end. Press [q] again to force exit. -------" SIPP_ENDL );
  } else if(paused) {
    fprintf(f,"----------------- Traffic Paused - Press [p] again to resume ------------------" SIPP_ENDL );
  } else if(cpu_max) {
    fprintf(f,"-------------------------------- CPU CONGESTED ---------------------------------" SIPP_ENDL);
  } else if(outbound_congestion) {
    fprintf(f,"------------------------------ OUTBOUND CONGESTION -----------------------------" SIPP_ENDL);
  } else {
    switch(toolMode)
      {
      case MODE_SERVER :
        fprintf(f,"------------------------------ Sipp Server Mode -------------------------------" SIPP_ENDL);
        break;
      case MODE_3PCC_CONTROLLER_B :
        fprintf(f,"----------------------- 3PCC Mode - Controller B side -------------------------" SIPP_ENDL);
        break;
      case MODE_3PCC_A_PASSIVE :
        fprintf(f,"------------------ 3PCC Mode - Controller A side (passive) --------------------" SIPP_ENDL);
        break;
      case MODE_3PCC_CONTROLLER_A :
        fprintf(f,"----------------------- 3PCC Mode - Controller A side -------------------------" SIPP_ENDL);
        break;
      case MODE_MASTER :
        fprintf(f,"-----------------------3PCC extended mode - Master side -------------------------" SIPP_ENDL);
        break;
      case MODE_MASTER_PASSIVE :
        fprintf(f,"------------------ 3PCC extended mode - Master side (passive) --------------------" SIPP_ENDL);
        break;
      case MODE_SLAVE :
        fprintf(f,"----------------------- 3PCC extended mode - Slave side -------------------------" SIPP_ENDL);
        break; 
      case MODE_CLIENT :
      default:
        fprintf(f,"------ [+|-|*|/]: Adjust rate ---- [q]: Soft exit ---- [p]: Pause traffic -----" SIPP_ENDL);
        break;
      }
  }
  fprintf(f,SIPP_ENDL);
  fflush(stdout);
}

void print_tdm_map()
{
  int interval = 0;
  int i = 0;
  int in_use = 0;
  interval = (tdm_map_a+1) * (tdm_map_b+1) * (tdm_map_c+1);

  printf("TDM Circuits in use:"  SIPP_ENDL);
  while (i<interval) {
    if (tdm_map[i]) {
      printf("*");
      in_use++;
    } else {
      printf(".");
    }
    i++;
    if (i%(tdm_map_c+1) == 0) printf(SIPP_ENDL);
  }
  printf(SIPP_ENDL);
  printf("%d/%d circuits (%d%%) in use", in_use, interval, int(100*in_use/interval));
  printf(SIPP_ENDL);
  for(int i=0; i<(display_scenario->length + 8 - int(interval/(tdm_map_c+1))); i++) {
    printf(SIPP_ENDL);
  }
}

void print_variable_list()
{
  CActions  * actions;
  CAction   * action;
  int i,j;
  int printed = 0;
  bool found;

  printf("Action defined Per Message :" SIPP_ENDL);
  printed++;
  found = false;
  for(i=0; i<display_scenario->length; i++)
  {
    message *curmsg = display_scenario->messages[i];
    actions = curmsg->M_actions;
    if(actions != NULL)
    {
      switch(curmsg->M_type)
      {
	case MSG_TYPE_RECV:
	  printf("=> Message[%d] (Receive Message) - "
	      "[%d] action(s) defined :" SIPP_ENDL,
	      i,
	      actions->getActionSize());
	  printed++;
	  break;
	case MSG_TYPE_RECVCMD:
	  printf("=> Message[%d] (Receive Command Message) - "
	      "[%d] action(s) defined :" SIPP_ENDL,
	      i,
	      actions->getActionSize());
	  printed++;
	  break;
	default:
	  printf("=> Message[%d] - [%d] action(s) defined :" SIPP_ENDL,
	      i,
	      actions->getActionSize());
	  printed++;
	  break;
      }

      for(int j=0; j<actions->getActionSize(); j++)
      {
	action = actions->getAction(j);
	if(action != NULL)
	{
	  printf("   --> action[%d] = ", j);
	  action->afficheInfo();
	  printf(SIPP_ENDL);
	  printed++;
	  found = true;
	}
      }
    }
  }
  if(!found) {
	printed++;
	printf("=> No action found on any messages"SIPP_ENDL);
  }
  
  printf(SIPP_ENDL);
  for(i=0; i<(display_scenario->length + 5 - printed); i++) {
    printf(SIPP_ENDL);
  }
}

/* Function to dump all available screens in a file */
void print_screens(void)
{
  int oldScreen = currentScreenToDisplay;
  int oldRepartition = currentRepartitionToDisplay;

  currentScreenToDisplay = DISPLAY_SCENARIO_SCREEN;  
  print_header_line(   screenf, 0);
  print_stats_in_file( screenf, 0);
  print_bottom_line(   screenf, 0);

  currentScreenToDisplay = DISPLAY_STAT_SCREEN;  
  print_header_line(   screenf, 0);
  display_scenario->stats->displayStat(screenf);
  print_bottom_line(   screenf, 0);

  currentScreenToDisplay = DISPLAY_REPARTITION_SCREEN;
  print_header_line(   screenf, 0);
  display_scenario->stats->displayRepartition(screenf);
  print_bottom_line(   screenf, 0);

  currentScreenToDisplay = DISPLAY_SECONDARY_REPARTITION_SCREEN;
  for (int i = 1; i <= MAX_RTD_INFO_LENGTH; i++) {
    currentRepartitionToDisplay = i;
    print_header_line(   screenf, 0);
    display_scenario->stats->displaySecondaryRepartition(screenf, i-1);
    print_bottom_line(   screenf, 0);
  }

  currentScreenToDisplay = oldScreen;
  currentRepartitionToDisplay = oldRepartition;
}

void print_statistics(int last)
{
  static int first = 1;

  if(backgroundMode == false && display_scenario) {
    if(!last) {
      screen_clear();
    }

    if(first) {
      first = 0;
      printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
             "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    }
    if (command_mode) {
	printf(SIPP_ENDL);
    }
    print_header_line(stdout,last);
    switch(currentScreenToDisplay) {
      case DISPLAY_STAT_SCREEN :
        display_scenario->stats->displayStat(stdout);
        break;
      case DISPLAY_REPARTITION_SCREEN :
        display_scenario->stats->displayRepartition(stdout);
        break;
      case DISPLAY_VARIABLE_SCREEN  :
        print_variable_list();
        break;
      case DISPLAY_TDM_MAP_SCREEN  :
        print_tdm_map();
        break;
      case DISPLAY_SECONDARY_REPARTITION_SCREEN :
	display_scenario->stats->displaySecondaryRepartition(stdout, currentRepartitionToDisplay - 1);
	break;
      case DISPLAY_SCENARIO_SCREEN :
      default:
        print_stats_in_file(stdout, last);
        break;
    }
    print_bottom_line(stdout,last);
    if (!last && screen_last_error[0]) {
	char *errstart = screen_last_error;
	int colonsleft = 4;/* We want to skip the time. */
	while (*errstart && colonsleft) {
	  if (*errstart == ':') {
		colonsleft--;
	  }
	  errstart++;
	}
	while (isspace(*errstart)) {
	  errstart++;
	}
	if (strlen(errstart) > 60) {
	  printf("Last Error: %.60s..." SIPP_ENDL, errstart);
	} else {
	  printf("Last Error: %s" SIPP_ENDL, errstart);
	}
	fflush(stdout);
    }
    if (command_mode) {
	printf("Command: %s", command_buffer ? command_buffer : "");
	fflush(stdout);
    }
    if(last) { fprintf(stdout,"\n"); }
  }
}

void set_rate(double new_rate)
{
  if(toolMode == MODE_SERVER) {
    rate = 0;
    open_calls_allowed = 0;
  }

  rate = new_rate;
  if(rate < 0) {
    rate = 0;
  }

  last_rate_change_time = clock_tick;
  calls_since_last_rate_change = 0;

  if(!open_calls_user_setting) {

    int call_duration_min =  display_scenario->duration;

    if(duration > call_duration_min) call_duration_min = duration;

    if(call_duration_min < 1000) call_duration_min = 1000;

    open_calls_allowed = (int)((3.0 * rate * call_duration_min) / (double)rate_period_ms);
    if(!open_calls_allowed) {
      open_calls_allowed = 1;
    }
  }
}

void set_users(int new_users)
{
  if (new_users < 0) {
    new_users = 0;
  }
  assert(users >= 0);

  if(toolMode == MODE_SERVER) {
    rate = 0;
    open_calls_allowed = 0;
  }

  if (users < new_users ) {
    while (users < new_users) {
      int userid;
      if (!retiredUsers.empty()) {
	userid = retiredUsers.back();
	retiredUsers.pop_back();
      } else {
	userid = users + 1;
	userVarMap[userid] = new VariableTable(userVariables);
      }
      freeUsers.push_front(userid);
      users++;
    }
  }

  users = open_calls_allowed = new_users;

  last_rate_change_time = clock_tick;
  calls_since_last_rate_change = 0;

  assert(open_calls_user_setting);
}

void sipp_sigusr1(int /* not used */)
{
  /* Smooth exit: do not place any new calls and exit */
  quitting+=10;
}

void sipp_sigusr2(int /* not used */)
{
  if (!signalDump) {
     signalDump = true ;
  }
}

bool process_key(int c) {
    switch (c) {
    case '1':
      currentScreenToDisplay = DISPLAY_SCENARIO_SCREEN;
      print_statistics(0);
      break;

    case '2':
      currentScreenToDisplay = DISPLAY_STAT_SCREEN;
      print_statistics(0);
      break;

    case '3':
      currentScreenToDisplay = DISPLAY_REPARTITION_SCREEN;
      print_statistics(0);
      break;

    case '4':
      currentScreenToDisplay = DISPLAY_VARIABLE_SCREEN;
      print_statistics(0);
      break;

    case '5':
      if (use_tdmmap) {
        currentScreenToDisplay = DISPLAY_TDM_MAP_SCREEN;
        print_statistics(0);
      }
      break;

    /* Screens 6, 7, 8, 9  are for the extra RTD repartitions. */
    case '6':
    case '7':
    case '8':
    case '9':
      currentScreenToDisplay = DISPLAY_SECONDARY_REPARTITION_SCREEN;
      currentRepartitionToDisplay = (c - '6') + 1;
      print_statistics(0);
      break;

    case '+':
      if (users >= 0) {
	set_users((int)(users + 1 * rate_scale));
      } else {
	set_rate(rate + 1 * rate_scale);
      }
      print_statistics(0);
      break;

    case '-':
      if (users >= 0) {
	set_users((int)(users - 1 * rate_scale));
      } else {
	set_rate(rate - 1 * rate_scale);
      }
      print_statistics(0);
      break;

    case '*':
      if (users >= 0) {
	set_users((int)(users + 10 * rate_scale));
      } else {
	set_rate(rate + 10 * rate_scale);
      }
      print_statistics(0);
      break;

    case '/':
      if (users >= 0) {
	set_users((int)(users - 10 * rate_scale));
      } else {
	set_rate(rate - 10 * rate_scale);
      }
      print_statistics(0);
      break;

    case 'p':
      if(paused) { 
	paused = 0;
	if (users >= 0) {
	  set_users(users);
	} else {
	  set_rate(rate);
	}
      } else {
	paused = 1;
      }
      print_statistics(0);
      break;

    case 's':
      if (screenf) {
	print_screens();
      }
      break;

    case 'q':
      quitting+=10;
      print_statistics(0);
      break;

    case 'Q':
      /* We are going to break, so we never have a chance to press q twice. */
      quitting+=20;
      print_statistics(0);
      break;
    }
    return false;
}

void trim(char *s) {
  char *p = s;
  while(isspace(*p)) {
    p++;
  }
  int l = strlen(p);
  for (int i = l - 1; i >= 0 && isspace(p[i]); i--) {
    p[i] = '\0';
  }
  memmove(s, p, l + 1);
}

void process_set(char *what) {
  char *rest = strchr(what, ' ');
  if (rest) {
	*rest++ = '\0';
	trim(rest);
  } else {
	WARNING("The set command requires two arguments (attribute and value)");
	return;
  }

  if (!strcmp(what, "rate")) {
    char *end;
    double drest = strtod(rest, &end);

    if (users >= 0) {
      WARNING("Rates can not be set in a user-based benchmark.");
    } else if (*end) {
      WARNING("Invalid rate value: \"%s\"", rest);
    } else {
      set_rate(drest);
    }
  } else if (!strcmp(what, "rate-scale")) {
    char *end;
    double drest = strtod(rest, &end);
    if (*end) {
      WARNING("Invalid rate-scale value: \"%s\"", rest);
    } else {
      rate_scale = drest;
    }
  } else if (!strcmp(what, "users")) {
    char *end;
    int urest = strtol(rest, &end, 0);

    if (users < 0) {
      WARNING("Users can not be changed at run time for a rate-based benchmark.");
    } else if (*end) {
      WARNING("Invalid users value: \"%s\"", rest);
    } else if (urest < 0) {
      WARNING("Invalid users value: \"%s\"", rest);
    } else {
      set_users(urest);
    }
  } else if (!strcmp(what, "limit")) {
    char *end;
    unsigned long lrest = strtoul(rest, &end, 0);
    if (*end) {
      WARNING("Invalid rate-scale value: \"%s\"", rest);
    } else {
      open_calls_allowed = lrest;
      open_calls_user_setting = 1;
    }
  } else if (!strcmp(what, "display")) {
    if (!strcmp(rest, "main")) {
      display_scenario = main_scenario;
    } else if (!strcmp(rest, "ooc")) {
      display_scenario = ooc_scenario;
    } else {
	WARNING("Unknown display scenario: %s", rest);
    }
  } else if (!strcmp(what, "hide")) {
    if (!strcmp(rest, "true")) {
      do_hide = true;
    } else if (!strcmp(rest, "false")) {
      do_hide = false;
    } else {
      WARNING("Invalid bool: %s", rest);
    }
  } else if (!strcmp(what, "index")) {
    if (!strcmp(rest, "true")) {
      show_index = true;
    } else if (!strcmp(rest, "false")) {
      show_index = false;
    } else {
      WARNING("Invalid bool: %s", rest);
    }
  } else {
    WARNING("Unknown set attribute: %s", what);
  }
}

void process_trace(char *what) {
  bool on = false;
  char *rest = strchr(what, ' ');
  if (rest) {
	*rest++ = '\0';
	trim(rest);
  } else {
	WARNING("The trace command requires two arguments (log and [on|off])");
	return;
  }

  if (!strcmp(rest, "on")) {
	on = true;
  }
  else if (!strcmp(rest, "off")) {
	on = false;
  }
  else if (!strcmp(rest, "true")) {
	on = true;
  }
  else if (!strcmp(rest, "false")) {
	on = false;
  }
  else {
	WARNING("The trace command's second argument must be on or off.");
	return;
  }

  if (!strcmp(what, "error")) {
    if (on == !!print_all_responses) {
      return;
    }
    if (on) {
      print_all_responses = 1;
    } else {
      print_all_responses = 0;
      if (screen_errorf) {
	fflush(screen_errorf);
	fclose(screen_errorf);
	screen_errorf = NULL;
	errorf_overwrite = false;
      }
    }
  } else if (!strcmp(what, "logs")) {
    if (on == !!logfile) {
      return;
    }
    if (on) {
      useLogf = 1;
      rotate_logfile();
    } else {
      useLogf = 0;
      fflush(logfile);
      fclose(logfile);
      logfile = NULL;
      logfile_overwrite = false;
    }
  } else if (!strcmp(what, "messages")) {
    if (on == !!messagef) {
      return;
    }
    if (on) {
      useMessagef = 1;
      rotate_logfile();
    } else {
      useMessagef = 0;
      fflush(messagef);
      fclose(messagef);
      messagef = NULL;
      messagef_overwrite = false;
    }
  } else if (!strcmp(what, "shortmessages")) {
    if (on == !!shortmessagef) {
      return;
    }

    if (on) {
      useShortMessagef = 1;
      rotate_shortmessagef();
    } else {
      useShortMessagef = 0;
      fflush(shortmessagef);
      fclose(shortmessagef);
      shortmessagef = NULL;
      shortmessagef_overwrite = false;
    }
  } else {
    WARNING("Unknown log file: %s", what);
  }
}

void process_dump(char *what) {
  if (!strcmp(what, "tasks")) {
    dump_tasks();
  } else {
    WARNING("Unknown dump type: %s", what);
  }
}

bool process_command(char *command) {
  trim(command);

  char *rest = strchr(command, ' ');
  if (rest) {
	*rest++ = '\0';
	trim(rest);
  }

  if (!strcmp(command, "set")) {
	process_set(rest);
  } else if (!strcmp(command, "trace")) {
	process_trace(rest);
  } else if (!strcmp(command, "dump")) {
	process_dump(rest);
  } else {
	WARNING("Unrecognized command: \"%s\"", command);
  }

  return false;
}


int handle_ctrl_socket() {
  unsigned char bufrcv [SIPP_MAX_MSG_SIZE];

  int ret = recv(ctrl_socket->ss_fd,bufrcv,sizeof(bufrcv) - 1,0);
  if (ret <= 0) {
    return ret;
  }

  if (bufrcv[0] == 'c') {
    /* No 'c', but we need one for '\0'. */
    char *command = (char *)malloc(ret);
    if (!command) {
      ERROR("Out of memory allocated command buffer.");
    }
    memcpy(command, bufrcv + 1, ret - 1);
    command[ret - 1] = '\0';
    process_command(command);
    free(command);
  } else {
    process_key(bufrcv[0]);
  }
}

void setup_ctrl_socket() {
  int ret;
  int port, firstport;
  int try_counter = 60;
  struct sockaddr_storage ctl_sa;

  int sock = socket(AF_INET,SOCK_DGRAM,0);
  if (sock == -1) {
    ERROR_NO("Unable to create remote control socket!");
  }

  if (control_port) {
    port = control_port;
    /* If the user specified the control port, then we must assume they know
     * what they want, and should not cycle. */
    try_counter = 1;
  } else {
    /* Allow 60 control sockets on the same system */
    /* (several SIPp instances)                   */
    port = DEFAULT_CTRL_SOCKET_PORT;
  }
  firstport = port;

  memset(&ctl_sa,0,sizeof(struct sockaddr_storage));
  if (control_ip[0]) {
    struct addrinfo hints;
    struct addrinfo *addrinfo;

    memset((char*)&hints, 0, sizeof(hints));
    hints.ai_flags  = AI_PASSIVE;
    hints.ai_family = PF_UNSPEC;

    if (getaddrinfo(control_ip, NULL, &hints, &addrinfo) != 0) {
      ERROR("Unknown control address '%s'.\n"
	  "Use 'sipp -h' for details", control_ip);
    }

    memcpy(&ctl_sa, addrinfo->ai_addr, SOCK_ADDR_SIZE(_RCAST(struct sockaddr_storage *,addrinfo->ai_addr)));
    freeaddrinfo(addrinfo);
  } else {
    ((struct sockaddr_in *)&ctl_sa)->sin_family = AF_INET;
    ((struct sockaddr_in *)&ctl_sa)->sin_addr.s_addr = INADDR_ANY;
  }

  while (try_counter) {
    ((struct sockaddr_in *)&ctl_sa)->sin_port = htons(port);
    if (!bind(sock,(struct sockaddr *)&ctl_sa,sizeof(struct sockaddr_in))) {
      /* Bind successful */
      break;
    }
    try_counter--;
    port++;
  }

  if (try_counter == 0) {
    if (control_port) {
      ERROR("Unable to bind remote control socket to UDP port %d: %s",
                  control_port, strerror(errno));
    } else {
      WARNING("Unable to bind remote control socket (tried UDP ports %d-%d): %s",
                  firstport, port - 1, strerror(errno));
    }
    return;
  }

  ctrl_socket = sipp_allocate_socket(0, T_UDP, sock, 0);
  if (!ctrl_socket) {
    ERROR_NO("Could not setup control socket!\n");
  }
}

void setup_stdin_socket() {
  fcntl(fileno(stdin), F_SETFL, fcntl(fileno(stdin), F_GETFL) | O_NONBLOCK);
  stdin_socket = sipp_allocate_socket(0, T_UDP, fileno(stdin), 0);
  if (!stdin_socket) {
    ERROR_NO("Could not setup keyboard (stdin) socket!\n");
  }
}

void handle_stdin_socket() {
  int c;
  int chars = 0;

  if (feof(stdin)) {
    sipp_close_socket(stdin_socket);
    stdin_socket = NULL;
    return;
  }

  while (((c = screen_readkey()) != -1)) {
    chars++;
    if (command_mode) {
      if (c == '\n') {
	bool quit = process_command(command_buffer);
	if (quit) {
	  return;
	}
	command_buffer[0] = '\0';
	command_mode = 0;
	printf(SIPP_ENDL);
      }
#ifndef __SUNOS
      else if (c == KEY_BACKSPACE || c == KEY_DC)
#else
      else if (c == 14)
#endif
      {
	int command_len = strlen(command_buffer);
	if (command_len > 0) {
	  command_buffer[command_len--] = '\0';
	}
      } else {
	int command_len = strlen(command_buffer);
	command_buffer = (char *)realloc(command_buffer, command_len + 2);
	command_buffer[command_len++] = c;
	command_buffer[command_len] = '\0';
	putchar(c);
	fflush(stdout);
      }
    } else if (c == 'c') {
      command_mode = 1;
      command_buffer = (char *)realloc(command_buffer, 1);
      command_buffer[0] = '\0';
      printf("Command: ");
      fflush(stdout);
    } else {
      process_key(c);
    }
  }
  if (chars == 0) {
    /* We did not read any characters, even though we should have. */
    sipp_close_socket(stdin_socket);
    stdin_socket = NULL;
  }
}

/*************************** Mini SIP parser ***************************/

char * get_peer_tag(char *msg)
{
  char        * to_hdr;
  char        * ptr; 
  char        * end_ptr;
  static char   tag[MAX_HEADER_LEN];
  int           tag_i = 0;
  
  to_hdr = strstr(msg, "\r\nTo:");
  if(!to_hdr) to_hdr = strstr(msg, "\r\nto:");
  if(!to_hdr) to_hdr = strstr(msg, "\r\nTO:");
  if(!to_hdr) to_hdr = strstr(msg, "\r\nt:");
  if(!to_hdr) {
    ERROR("No valid To: header in reply");
  }

  // Remove CRLF
  to_hdr += 2;

  end_ptr = strchr(to_hdr,'\n');

  ptr = strchr(to_hdr, '>');
  if (!ptr) {
    return NULL;
  }
  
  ptr = strchr(to_hdr, ';'); 
  
  if(!ptr) {
    return NULL;
  }
  
  to_hdr = ptr;

  ptr = strstr(to_hdr, "tag");
  if(!ptr) { ptr = strstr(to_hdr, "TAG"); }
  if(!ptr) { ptr = strstr(to_hdr, "Tag"); }

  if(!ptr) {
    return NULL;
  }

  if (ptr>end_ptr) {
    return NULL ;
  }
  
  ptr = strchr(ptr, '='); 
  
  if(!ptr) {
    ERROR("Invalid tag param in To: header");
  }

  ptr ++;

  while((*ptr)         && 
        (*ptr != ' ')  && 
        (*ptr != ';')  && 
        (*ptr != '\t') && 
        (*ptr != '\t') && 
        (*ptr != '\r') &&  
        (*ptr != '\n') && 
        (*ptr)) {
    tag[tag_i++] = *(ptr++);
  }
  tag[tag_i] = 0;
  
  return tag;
}

char * get_incoming_header_content(char* message, char * name)
{
  /* non reentrant. consider accepting char buffer as param */
  static char last_header[MAX_HEADER_LEN * 10];
  char * src, *dest, *ptr;

  /* returns empty string in case of error */
  memset(last_header, 0, sizeof(last_header));

  if((!message) || (!strlen(message))) {
    return last_header;
  }

  src = message;
  dest = last_header;
  
  /* for safety's sake */
  if (NULL == name || NULL == strrchr(name, ':')) {
      return last_header;
  }

  while(src = strstr(src, name)) {

      /* just want the header's content */
      src += strlen(name);

    ptr = strchr(src, '\n');
    
    /* Multiline headers always begin with a tab or a space
     * on the subsequent lines */
    while((ptr) &&
          ((*(ptr+1) == ' ' ) ||
           (*(ptr+1) == '\t')    )) {
      ptr = strchr(ptr + 1, '\n'); 
    }

    if(ptr) { *ptr = 0; }
    // Add "," when several headers are present
    if (dest != last_header) {
      dest += sprintf(dest, ",");
    }
    dest += sprintf(dest, "%s", src);
    if(ptr) { *ptr = '\n'; }
    
    src++;
  }
  
  if(dest == last_header) {
    return last_header;
  }

  *(dest--) = 0;

  /* Remove trailing whitespaces, tabs, and CRs */
  while ((dest > last_header) && 
         ((*dest == ' ') || (*dest == '\r')|| (*dest == '\t'))) {
    *(dest--) = 0;
  }

  /* remove enclosed CRs in multilines */
  while(ptr = strchr(last_header, '\r')) {
    /* Use strlen(ptr) to include trailing zero */
    memmove(ptr, ptr+1, strlen(ptr));
  }

  return last_header;
}

char * get_incoming_first_line(char * message)
{
  /* non reentrant. consider accepting char buffer as param */
  static char last_header[MAX_HEADER_LEN * 10];
  char * src, *dest, *ptr;

  /* returns empty string in case of error */
  memset(last_header, 0, sizeof(last_header));

  if((!message) || (!strlen(message))) {
    return last_header;
  }

  src = message;
  dest = last_header;
  
  int i=0;
  while (*src){
    if((*src=='\n')||(*src=='\r')){
      break;
    }
    else
    {
      last_header[i]=*src;
    }
    i++;
    src++;
  }
  
  return last_header;
}


char * get_call_id(char *msg)
{
  static char call_id[MAX_HEADER_LEN];
  char * ptr1, * ptr2, * ptr3, backup;
  bool short_form;

  call_id[0] = '\0';

  short_form = false;

  ptr1 = strstr(msg, "Call-ID:");
  if(!ptr1) { ptr1 = strstr(msg, "Call-Id:"); }
  if(!ptr1) { ptr1 = strstr(msg, "Call-id:"); }
  if(!ptr1) { ptr1 = strstr(msg, "call-Id:"); }
  if(!ptr1) { ptr1 = strstr(msg, "call-id:"); }
  if(!ptr1) { ptr1 = strstr(msg, "CALL-ID:"); }
  // For short form, we need to make sure we start from beginning of line
  // For others, no need to
  if(!ptr1) { ptr1 = strstr(msg, "\r\ni:"); short_form = true;}
  if(!ptr1) {
    WARNING("(1) No valid Call-ID: header in reply '%s'", msg);
    return call_id;
  }
  
  if (short_form) {
    ptr1 += 4;
  } else {
    ptr1 += 8;
  }
  
  while((*ptr1 == ' ') || (*ptr1 == '\t')) { ptr1++; }
  
  if(!(*ptr1)) {
    WARNING("(2) No valid Call-ID: header in reply");
    return call_id;
  }
  
  ptr2 = ptr1;

  while((*ptr2) && 
        (*ptr2 != ' ') && 
        (*ptr2 != '\t') && 
        (*ptr2 != '\r') && 
        (*ptr2 != '\n')) { 
    ptr2 ++;
  } 

  if(!*ptr2) {
    WARNING("(3) No valid Call-ID: header in reply");
    return call_id;
  }

  backup = *ptr2;
  *ptr2 = 0;
  if ((ptr3 = strstr(ptr1, "///")) != 0) ptr1 = ptr3+3;
  strcpy(call_id, ptr1);
  *ptr2 = backup;
  return (char *) call_id;
}

unsigned long int get_cseq_value(char *msg) {
  char *ptr1;
 

  // no short form for CSeq:
  ptr1 = strstr(msg, "\r\nCSeq:");
  if(!ptr1) { ptr1 = strstr(msg, "\r\nCSEQ:"); }
  if(!ptr1) { ptr1 = strstr(msg, "\r\ncseq:"); }
  if(!ptr1) { ptr1 = strstr(msg, "\r\nCseq:"); }
  if(!ptr1) { WARNING("No valid Cseq header in request %s", msg); return 0;}
 
  ptr1 += 7;
 
  while((*ptr1 == ' ') || (*ptr1 == '\t')) {++ptr1;}
 
  if(!(*ptr1)) { WARNING("No valid Cseq data in header"); return 0;}
 
  return strtoul(ptr1, NULL, 10);
}

unsigned long get_reply_code(char *msg)
{
  while((msg) && (*msg != ' ') && (*msg != '\t')) msg ++;
  while((msg) && ((*msg == ' ') || (*msg == '\t'))) msg ++;

  if ((msg) && (strlen(msg)>0)) {
    return atol(msg);
  } else {
    return 0;
  }
}

/*************************** I/O functions ***************************/

/* Allocate a socket buffer. */
struct socketbuf *alloc_socketbuf(char *buffer, size_t size, int copy, struct sockaddr_storage *dest) {
  struct socketbuf *socketbuf;

  socketbuf = (struct socketbuf *)malloc(sizeof(struct socketbuf));
  if (!socketbuf) {
	ERROR("Could not allocate socket buffer!\n");
  }
  if (copy) {
    socketbuf->buf = (char *)malloc(size);
    if (!socketbuf->buf) {
      ERROR("Could not allocate socket buffer data!\n");
    }
    memcpy(socketbuf->buf, buffer, size);
  } else {
    socketbuf->buf = buffer;
  }
  socketbuf->len = size;
  socketbuf->offset = 0;
  if (dest) {
    memcpy(&socketbuf->addr, dest, SOCK_ADDR_SIZE(dest));
  }
  socketbuf->next = NULL;

  return socketbuf;
}

/* Free a poll buffer. */
void free_socketbuf(struct socketbuf *socketbuf) {
  free(socketbuf->buf);
  free(socketbuf);
}

size_t decompress_if_needed(int sock, char *buff,  size_t len, void **st)
{
  if(compression && len) {
    if (useMessagef == 1) {	  
    struct timeval currentTime;
    GET_TIME (&currentTime);
    TRACE_MSG("----------------------------------------------- %s\n"
               "Compressed message received, header :\n"
               "0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x "
               "0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n",
               CStat::formatTime(&currentTime, true),
               buff[0] , buff[1] , buff[2] , buff[3],
               buff[4] , buff[5] , buff[6] , buff[7],
               buff[8] , buff[9] , buff[10], buff[11],
               buff[12], buff[13], buff[14], buff[15]);
    }
    
    int rc = comp_uncompress(st,
                             buff, 
                             (unsigned int *) &len);
    
    switch(rc) {
    case COMP_OK:
      TRACE_MSG("Compressed message decompressed properly.\n");
      break;

    case COMP_REPLY:
      TRACE_MSG("Compressed message KO, sending a reply (resynch).\n");
      sendto(sock,
             buff, 
             len, 
             0,
             (sockaddr *)(void *)&remote_sockaddr,
             SOCK_ADDR_SIZE(&remote_sockaddr));
      resynch_send++;
      return 0;

    case COMP_DISCARD:
      TRACE_MSG("Compressed message discarded by pluggin.\n");
      resynch_recv++;
      return 0;

    default:
    case COMP_KO:
      ERROR("Compression pluggin error");
      return 0;
    }
  }
  return len;
}

void sipp_customize_socket(struct sipp_socket *socket)
{
  unsigned int buffsize = buff_size;

  /* Allows fast TCP reuse of the socket */
  if (socket->ss_transport == T_TCP || socket->ss_transport == T_TLS ) {
    int sock_opt = 1;

    if (setsockopt(socket->ss_fd, SOL_SOCKET, SO_REUSEADDR, (void *)&sock_opt,
                   sizeof (sock_opt)) == -1) {
      ERROR_NO("setsockopt(SO_REUSEADDR) failed");
    }

#ifndef SOL_TCP
#define SOL_TCP 6
#endif
    if (setsockopt(socket->ss_fd, SOL_TCP, TCP_NODELAY, (void *)&sock_opt,
                    sizeof (sock_opt)) == -1) {
      {
        ERROR_NO("setsockopt(TCP_NODELAY) failed");
      }
    }

    {
      struct linger linger;

      linger.l_onoff = 1;
      linger.l_linger = 1;
      if (setsockopt (socket->ss_fd, SOL_SOCKET, SO_LINGER,
                      &linger, sizeof (linger)) < 0) {
        ERROR_NO("Unable to set SO_LINGER option");
      }
    }
  }

    /* Increase buffer sizes for this sockets */
  if(setsockopt(socket->ss_fd,
                SOL_SOCKET,
                SO_SNDBUF,
                &buffsize,
                sizeof(buffsize))) {
    ERROR_NO("Unable to set socket sndbuf");
  }

  buffsize = buff_size;
  if(setsockopt(socket->ss_fd,
                SOL_SOCKET,
                SO_RCVBUF,
                &buffsize,
                sizeof(buffsize))) {
    ERROR_NO("Unable to set socket rcvbuf");
  }
}

static ssize_t socket_write_primitive(struct sipp_socket *socket, char *buffer, size_t len, struct sockaddr_storage *dest) {
  ssize_t rc;

  /* Refuse to write to invalid sockets. */
  if (socket->ss_invalid) {
    WARNING("Returning EPIPE on invalid socket: %p (%d)\n", socket, socket->ss_fd);
    errno = EPIPE;
    return -1;
  }

  /* Always check congestion before sending. */
  if (socket->ss_congested) {
    errno = EWOULDBLOCK;
    return -1;
  }

  switch(socket->ss_transport) {
    case T_TLS:
#ifdef _USE_OPENSSL
      rc = send_nowait_tls(socket->ss_ssl, buffer, len, 0);
#else
      errno = EOPNOTSUPP;
      rc = -1;
#endif
      break;
    case T_TCP:
      rc = send_nowait(socket->ss_fd, buffer, len, 0);
      break;
    case T_UDP:
      if(compression) {
	static char comp_msg[SIPP_MAX_MSG_SIZE];
	strcpy(comp_msg, buffer);
	if(comp_compress(&socket->ss_comp_state,
	      comp_msg,
	      (unsigned int *) &len) != COMP_OK) {
	  ERROR("Compression pluggin error");
	}
	buffer = (char *)comp_msg;

	TRACE_MSG("---\nCompressed message len: %d\n", len);
      }

      rc = sendto(socket->ss_fd, buffer, len, 0, (struct sockaddr *)dest, SOCK_ADDR_SIZE(dest));

      break;
    default:
      ERROR("Internal error, unknown transport type %d\n", socket->ss_transport);
  }

  return rc;
}

/* This socket is congestion, mark its as such and add it to the poll files. */
int enter_congestion(struct sipp_socket *socket, int again) {
  socket->ss_congested = true;

  TRACE_MSG("Problem %s on socket  %d and poll_idx  is %d \n",
	again == EWOULDBLOCK ? "EWOULDBLOCK" : "EAGAIN",
	socket->ss_fd, socket->ss_pollidx);

  pollfiles[socket->ss_pollidx].events |= POLLOUT;

  nb_net_cong++;
  return -1;
}


static int write_error(struct sipp_socket *socket, int ret) {
  const char *errstring = strerror(errno);

#ifndef EAGAIN
  int again = (errno == EWOULDBLOCK) ? errno : 0;
#else
  int again = ((errno == EAGAIN) || (errno == EWOULDBLOCK)) ? errno : 0;

  /* Scrub away EAGAIN from the rest of the code. */
  if (errno == EAGAIN) {
	errno = EWOULDBLOCK;
  }
#endif

  if(again) {
    return enter_congestion(socket, again);
  }

  if (socket->ss_transport == T_TCP && errno == EPIPE) {
    nb_net_send_errors++;
    close(socket->ss_fd);
    socket->ss_fd = -1;
    sockets_pending_reset.insert(socket);
    if (reconnect_allowed()) {
      WARNING("Broken pipe on TCP connection, remote peer "
	  "probably closed the socket");
    } else {
      ERROR("Broken pipe on TCP connection, remote peer "
	  "probably closed the socket");
    }
    return -1;
  }

#ifdef _USE_OPENSSL
  if (socket->ss_transport == T_TLS) {
    errstring = sip_tls_error_string(socket->ss_ssl, ret);
  }
#endif

  WARNING("Unable to send %s message: %s", TRANSPORT_TO_STRING(socket->ss_transport), errstring);
  nb_net_send_errors++;
  return -1;
}

static int read_error(struct sipp_socket *socket, int ret) {
  const char *errstring = strerror(errno);
#ifdef _USE_OPENSSL
  if (socket->ss_transport == T_TLS) {
    errstring = sip_tls_error_string(socket->ss_ssl, ret);
  }
#endif

  assert(ret <= 0);

#ifdef EAGAIN
  /* Scrub away EAGAIN from the rest of the code. */
  if (errno == EAGAIN) {
    errno = EWOULDBLOCK;
  }
#endif

  /* We have only non-blocking reads, so this should not occur. */
  assert(errno != EAGAIN);

  if (socket->ss_transport == T_TCP || socket->ss_transport == T_TLS) {
    if (ret == 0) {
      /* The remote side closed the connection. */
      if(socket->ss_control) {
        if(localTwinSippSocket) sipp_close_socket(localTwinSippSocket);
        if (extendedTwinSippMode) {
          close_peer_sockets();
          close_local_sockets();
          free_peer_addr_map();
          WARNING("One of the twin instances has ended -> exiting");
          quitting += 20;
          }else if(twinSippMode) {
           if(twinSippSocket) sipp_close_socket(twinSippSocket);
           if(toolMode == MODE_3PCC_CONTROLLER_B) {
             WARNING("3PCC controller A has ended -> exiting");
             quitting += 20;
           }else {
             quitting = 1;
           }
        }
      }else {
	/* The socket was closed "cleanly", but we may have calls that need to
	 * be destroyed.  Also, if these calls are not complete, and attempt to
	 * send again we may "ressurect" the socket by reconnecting it.*/
        sipp_socket_invalidate(socket);
        if (reset_close) {
	  close_calls(socket);
	}
      }
      return 0;
    }

    close(socket->ss_fd);
    socket->ss_fd = -1;
    sockets_pending_reset.insert(socket);

    nb_net_recv_errors++;
    if (reconnect_allowed()) {
      WARNING("Error on TCP connection, remote peer probably closed the socket: %s", errstring);
    } else {
      ERROR("Error on TCP connection, remote peer probably closed the socket: %s", errstring);
    }
    return -1;
  }

  WARNING("Unable to receive %s message: %s", TRANSPORT_TO_STRING(socket->ss_transport), errstring);
  nb_net_recv_errors++;
  return -1;
}

/* Flush any output buffers for this socket. */
static int flush_socket(struct sipp_socket *socket) {
  struct socketbuf *buf;
  int ret;

  while ((buf = socket->ss_out)) {
    ssize_t size = buf->len - buf->offset;
    ret = socket_write_primitive(socket, buf->buf + buf->offset, size, &buf->addr);
    TRACE_MSG("Wrote %d of %d bytes in an output buffer.", ret, size);
    if (ret == size) {
      /* Everything is great, throw away this buffer. */
      socket->ss_out = buf->next;
      free_socketbuf(buf);
    } else if (ret <= 0) {
      /* Handle connection closes and errors. */
      return write_error(socket, ret);
    } else {
      /* We have written more of the partial buffer. */
      buf->offset += ret;
      errno = EWOULDBLOCK;
      enter_congestion(socket, EWOULDBLOCK);
      return -1;
    }
  }

  return 0;
}

void buffer_write(struct sipp_socket *socket, char *buffer, size_t len, struct sockaddr_storage *dest) {
  struct socketbuf *buf = socket->ss_out;
  struct socketbuf *prev = buf;

  if (!buf) {
	socket->ss_out = alloc_socketbuf(buffer, len, DO_COPY, dest);
	TRACE_MSG("Added first buffered message to socket %d\n", socket->ss_fd);
	return;
  }

  while(buf->next) {
	prev = buf;
	buf = buf->next;
  }

  prev->next = alloc_socketbuf(buffer, len, DO_COPY, dest);
  TRACE_MSG("Appended buffered message to socket %d\n", socket->ss_fd);
}

void buffer_read(struct sipp_socket *socket, struct socketbuf *newbuf) {
  struct socketbuf *buf = socket->ss_in;
  struct socketbuf *prev = buf;

  if (!buf) {
	socket->ss_in = newbuf;
	return;
  }

  while(buf->next) {
	prev = buf;
	buf = buf->next;
  }

  prev->next = newbuf;
}

/* Write data to a socket. */
int write_socket(struct sipp_socket *socket, char *buffer, ssize_t len, int flags, struct sockaddr_storage *dest) {
  int rc;

  if (socket->ss_out) {
    rc = flush_socket(socket);
    TRACE_MSG("Attempted socket flush returned %d\r\n", rc);
    if (rc < 0) {
      if ((errno == EWOULDBLOCK) && (flags & WS_BUFFER)) {
	buffer_write(socket, buffer, len, dest);
	return len;
      } else {
	return rc;
      }
    }
  }

  rc = socket_write_primitive(socket, buffer, len, dest);

  if (rc == len) {
    /* Everything is great. */
    if (useMessagef == 1) {
      struct timeval currentTime;
      GET_TIME (&currentTime);
      TRACE_MSG("----------------------------------------------- %s\n"
	    "%s %smessage sent (%d bytes):\n\n%.*s\n",
	    CStat::formatTime(&currentTime, true),
	    TRANSPORT_TO_STRING(socket->ss_transport),
	    socket->ss_control ? "control " : "",
	    len, len, buffer);
    }
  } else if (rc <= 0) {
    if ((errno == EWOULDBLOCK) && (flags & WS_BUFFER)) {
      buffer_write(socket, buffer, len, dest);
      return len;
    }
    if (useMessagef == 1) {
      struct timeval currentTime;
      GET_TIME (&currentTime);
      TRACE_MSG("----------------------------------------------- %s\n"
	    "Error sending %s message:\n\n%.*s\n",
	    CStat::formatTime(&currentTime, true),
	    TRANSPORT_TO_STRING(socket->ss_transport),
	    len, buffer);
    }
    return write_error(socket, errno);
  } else {
    /* We have a truncated message, which must be handled internally to the write function. */
    if (useMessagef == 1) {
      struct timeval currentTime;
      GET_TIME (&currentTime);
      TRACE_MSG("----------------------------------------------- %s\n"
	    "Truncation sending %s message (%d of %d sent):\n\n%.*s\n",
	    CStat::formatTime(&currentTime, true),
	    TRANSPORT_TO_STRING(socket->ss_transport),
	    rc, len, len, buffer);
    }
    buffer_write(socket, buffer + rc, len - rc, dest);
  }

  return rc;
}

/****************************** Network Interface *******************/

/* Our message detection states: */
#define CFM_NORMAL 0 /* No CR Found, searchign for \r\n\r\n. */
#define CFM_CONTROL 1 /* Searching for 27 */
#define CFM_CR 2 /* CR Found, Searching for \n\r\n */
#define CFM_CRLF 3 /* CRLF Found, Searching for \r\n */
#define CFM_CRLFCR 4 /* CRLFCR Found, Searching for \n */
#define CFM_CRLFCRLF 5 /* We've found the end of the headers! */

void merge_socketbufs(struct socketbuf *socketbuf) {
  struct socketbuf *next = socketbuf->next;
  int newsize;
  char *newbuf;

  if (!next) {
    return;
  }

  if (next->offset) {
    ERROR("Internal error: can not merge a socketbuf with a non-zero offset.");
  }

  if (socketbuf->offset) {
    memmove(socketbuf->buf, socketbuf->buf + socketbuf->offset, socketbuf->len - socketbuf->offset);
    socketbuf->len -= socketbuf->offset;
    socketbuf->offset = 0;
  }

  newsize = socketbuf->len + next->len;

  newbuf = (char *)realloc(socketbuf->buf, newsize);
  if (!newbuf) {
    ERROR("Could not allocate memory to merge socket buffers!");
  }
  memcpy(newbuf + socketbuf->len, next->buf, next->len);
  socketbuf->buf = newbuf;
  socketbuf->len = newsize;
  socketbuf->next = next->next;
  free_socketbuf(next);
}

/* Check for a message in the socket and return the length of the first
 * message.  If this is UDP, the only check is if we have buffers.  If this is
 * TCP or TLS we need to parse out the content-length. */
static int check_for_message(struct sipp_socket *socket) {
  struct socketbuf *socketbuf = socket->ss_in;
  int state = socket->ss_control ? CFM_CONTROL : CFM_NORMAL;
  const char *l;

  if (!socketbuf)
    return 0;

  if (socket->ss_transport == T_UDP) {
    return socketbuf->len;
  }

  int len = 0;

  while (socketbuf->offset + len < socketbuf->len) {
    char c = socketbuf->buf[socketbuf->offset + len];

    switch(state) {
      case CFM_CONTROL:
	/* For CMD Message the escape char is the end of message */
	if (c == 27) {
	  return len + 1; /* The plus one includes the control character. */
	}
	break;
      case CFM_NORMAL:
	if (c == '\r') {
	  state = CFM_CR;
	}
	break;
      case CFM_CR:
	if (c == '\n') {
	  state = CFM_CRLF;
	} else {
	  state = CFM_NORMAL;
	}
	break;
      case CFM_CRLF:
	if (c == '\r') {
	  state = CFM_CRLFCR;
	} else {
	  state = CFM_NORMAL;
	}
	break;
      case CFM_CRLFCR:
	if (c == '\n') {
	  state = CFM_CRLFCRLF;
	} else {
	  state = CFM_NORMAL;
	}
	break;
    }

    /* Head off failing because the buffer does not contain the whole header. */
    if (socketbuf->offset + len == socketbuf->len - 1) {
      merge_socketbufs(socketbuf);
    }

    if (state == CFM_CRLFCRLF) {
      break;
    }

    len++;
  }

  /* We did not find the end-of-header marker. */
  if (state != CFM_CRLFCRLF) {
    return 0;
  }

  /* Find the content-length header. */
  if ((l = strncasestr(socketbuf->buf + socketbuf->offset, "\r\nContent-Length:", len))) {
    l += strlen("\r\nContent-Length:");
  } else if ((l = strncasestr(socketbuf->buf + socketbuf->offset, "\r\nl:", len))) {
    l += strlen("\r\nl:");
  } else {
    /* There is no header, so the content-length is zero. */
    return len + 1;
  }

  /* Skip spaces. */
  while(isspace(*l)) {
    if (*l == '\r' || *l == '\n') {
      /* We ran into an end-of-line, so there is no content-length. */
      return len + 1;
    }
    l++;
  }

  /* Do the integer conversion, we only allow '\r' or spaces after the integer. */
  char *endptr;
  int content_length = strtol(l, &endptr, 10);
  if (*endptr != '\r' && !isspace(*endptr)) {
    content_length = 0;
  }

  /* Now that we know how large this message is, we make sure we have the whole thing. */
  do
  {
    /* It is in this buffer. */
    if (socketbuf->offset + len + content_length < socketbuf->len) {
      return len + content_length + 1;
    }
    if (socketbuf->next == NULL) {
      /* There is no buffer to merge, so we fail. */
      return 0;
    }
    /* We merge ourself with the next buffer. */
    merge_socketbufs(socketbuf);
  }
  while (1);
}

/* Pull up to tcp_readsize data bytes out of the socket into our local buffer. */
static int empty_socket(struct sipp_socket *socket) {
  int readsize = socket->ss_transport == T_UDP ? SIPP_MAX_MSG_SIZE : tcp_readsize;
  struct socketbuf *socketbuf;
  char *buffer;
  int ret;
  /* Where should we start sending packets to, ideally we should begin to parse
   * the Via, Contact, and Route headers.  But for now SIPp always sends to the
   * host specified on the command line; or for UAS mode to the address that
   * sent the last message. */
  sipp_socklen_t addrlen = sizeof(struct sockaddr_storage);

  buffer = (char *)malloc(readsize);
  if (!buffer) {
    ERROR("Could not allocate memory for read!");
  }
  socketbuf = alloc_socketbuf(buffer, readsize, NO_COPY, NULL);

  switch(socket->ss_transport) {
    case T_TCP:
    case T_UDP:
      ret = recvfrom(socket->ss_fd, buffer, readsize, 0, (struct sockaddr *)&socketbuf->addr,  &addrlen);
      break;
    case T_TLS:
#ifdef _USE_OPENSSL
      ret = SSL_read(socket->ss_ssl, buffer, readsize);
      /* XXX: Check for clean shutdown. */
#else
      ERROR("TLS support is not enabled!");
#endif
      break;
  }
  if (ret <= 0) {
    free_socketbuf(socketbuf);
    return ret;
  }

  socketbuf->len = ret;

  buffer_read(socket, socketbuf);

  /* Do we have a complete SIP message? */
  if (!socket->ss_msglen) {
    if (int msg_len = check_for_message(socket)) {
      socket->ss_msglen = msg_len;
      pending_messages++;
    }
  }

  return ret;
}

void sipp_socket_invalidate(struct sipp_socket *socket) {
  int pollidx;

  if (socket->ss_invalid) {
    return;
  }

#ifdef _USE_OPENSSL
  if (SSL *ssl = socket->ss_ssl) {
    SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
    SSL_free(ssl);
  }
#endif

  shutdown(socket->ss_fd, SHUT_RDWR);
  close(socket->ss_fd);
  socket->ss_fd = -1;

  if((pollidx = socket->ss_pollidx) >= pollnfds) {
    ERROR("Pollset error: index %d is greater than number of fds %d!", pollidx, pollnfds);
  }

  if (socket->ss_call_socket) {
    call_sockets--;
  }

  socket->ss_invalid = true;
  socket->ss_pollidx = -1;

  /* Adds call sockets in the array */
  assert(pollnfds > 0);

  pollnfds--;
  pollfiles[pollidx] = pollfiles[pollnfds];
  sockets[pollidx] = sockets[pollnfds];
  sockets[pollidx]->ss_pollidx = pollidx;
}

void sipp_close_socket (struct sipp_socket *socket) {
  int count = --socket->ss_count;

  if (count > 0) {
    return;
  }

  sipp_socket_invalidate(socket);
  free(socket);
}

static ssize_t read_message(struct sipp_socket *socket, char *buf, size_t len, struct sockaddr_storage *src) {
  size_t avail;

  if (!socket->ss_msglen)
    return 0;
  if (socket->ss_msglen > len)
    ERROR("There is a message waiting in a socket that is bigger (%zd bytes) than the read size.", socket->ss_msglen);

  len = socket->ss_msglen;

  avail = socket->ss_in->len - socket->ss_in->offset;
  if (avail > len) {
    avail = len;
  }

  memcpy(buf, socket->ss_in->buf + socket->ss_in->offset, avail);
  memcpy(src, &socket->ss_in->addr, SOCK_ADDR_SIZE(&socket->ss_in->addr));

  /* Update our buffer and return value. */
  buf[avail] = '\0';
  /* For CMD Message the escape char is the end of message */ 
  if((socket->ss_control) && buf[avail-1] == 27 ) buf[avail-1] = '\0';

  socket->ss_in->offset += avail;

  /* Have we emptied the buffer? */
  if (socket->ss_in->offset == socket->ss_in->len) {
    struct socketbuf *next = socket->ss_in->next;
    free_socketbuf(socket->ss_in);
    socket->ss_in = next;
  }

  if (int msg_len = check_for_message(socket)) {
    socket->ss_msglen = msg_len;
  } else {
    socket->ss_msglen = 0;
    pending_messages--;
  }

  if (useMessagef == 1) {
    struct timeval currentTime;
    GET_TIME (&currentTime);
    TRACE_MSG("----------------------------------------------- %s\n"
	  "%s %smessage received [%d] bytes :\n\n%s\n",
	  CStat::formatTime(&currentTime, true),
	  TRANSPORT_TO_STRING(socket->ss_transport),
	  socket->ss_control ? "control " : "",
	  avail, buf);
  }

  return avail;
}

void process_message(struct sipp_socket *socket, char *msg, ssize_t msg_size, struct sockaddr_storage *src) {
  // TRACE_MSG(" msg_size %d and pollset_index is %d \n", msg_size, pollset_index));
  if(msg_size <= 0) {
    return;
  }
  if (sipMsgCheck(msg, msg_size, socket) == false) {
    WARNING("non SIP message discarded");
    return;
  }

  char *call_id = get_call_id(msg);
  if (call_id[0] == '\0') {
    WARNING("SIP message without Call-ID discarded");
    return;
  }
  listener *listener_ptr = get_listener(call_id);
 
  if (useShortMessagef == 1) {
              struct timeval currentTime;
              GET_TIME (&currentTime);
              TRACE_SHORTMSG("%s\tS\t%s\tCSeq:%s\t%s\n",
              CStat::formatTime(&currentTime),call_id, get_incoming_header_content(msg,"CSeq:"), get_incoming_first_line(msg));
          } 

  if(!listener_ptr)
  {
    if(toolMode == MODE_SERVER)
    {
      if (quitting >= 1) {
	CStat::globalStat(CStat::E_OUT_OF_CALL_MSGS);
	TRACE_MSG("Discarded message for new calls while quitting\n");
	return;
      }

      // Adding a new INCOMING call !
      main_scenario->stats->computeStat(CStat::E_CREATE_INCOMING_CALL);
      listener_ptr = new call(call_id, socket, src);
      if (!listener_ptr) {
	ERROR("Out of memory allocating a call!");
      }
    }
    else if(toolMode == MODE_3PCC_CONTROLLER_B || toolMode == MODE_3PCC_A_PASSIVE
	|| toolMode == MODE_MASTER_PASSIVE || toolMode == MODE_SLAVE)
    {
      // Adding a new OUTGOING call !
      main_scenario->stats->computeStat(CStat::E_CREATE_OUTGOING_CALL);
      call *new_ptr = new call(call_id, is_ipv6, 0, use_remote_sending_addr ? &remote_sending_sockaddr : &remote_sockaddr);
      if (!new_ptr) {
	ERROR("Out of memory allocating a call!");
      }

      outbound_congestion = false;
      if((socket != main_socket) &&
	  (socket != tcp_multiplex) &&
	  (socket != localTwinSippSocket) &&
	  (socket != twinSippSocket) &&
	  (!is_a_local_socket(socket))) {
	new_ptr->associate_socket(socket);
	socket->ss_count++;
      } else {
	/* We need to hook this call up to a real *call* socket. */
	if (!multisocket) {
	  switch(transport) {
	    case T_UDP:
	      new_ptr->associate_socket(main_socket);
	      main_socket->ss_count++;
	      break;
	    case T_TCP:
	    case T_TLS:
	      new_ptr->associate_socket(tcp_multiplex);
	      tcp_multiplex->ss_count++;
	      break;
	  }
	}
      }
      listener_ptr = new_ptr;
    }
    else // mode != from SERVER and 3PCC Controller B
    {
      // This is a message that is not relating to any known call
      if (auto_answer == true) {
	// If auto answer mode, try to answer the incoming message
	// with automaticResponseMode
	// call is discarded before exiting the block
	if(!get_reply_code(msg)){
	  ooc_scenario->stats->computeStat(CStat::E_CREATE_INCOMING_CALL);
	  /* This should have the real address that the message came from. */
	  call *call_ptr = new call(ooc_scenario, socket, src, call_id, 0 /* no user. */, socket->ss_ipv6, true);
	  if (!call_ptr) {
	    ERROR("Out of memory allocating a call!");
	  }
	  CStat::globalStat(CStat::E_AUTO_ANSWERED);
	  call_ptr->process_incoming(msg);
	} else {
	  /* We received a response not relating to any known call */
	  /* Do nothing, even if in auto answer mode */
	  CStat::globalStat(CStat::E_OUT_OF_CALL_MSGS);
	}
      } else {
	CStat::globalStat(CStat::E_OUT_OF_CALL_MSGS);
	WARNING("Discarding message which can't be mapped to a known SIPp call:\n%s", msg);
      }
    }
  }

  /* If the call was not created above, we just drop this message. */
  if (!listener_ptr) {
    return;
  }

  if((socket == localTwinSippSocket) || (socket == twinSippSocket) || (is_a_local_socket(socket)))
  {
    listener_ptr -> process_twinSippCom(msg);
  }
  else
  {
    listener_ptr -> process_incoming(msg);
  }
}

void pollset_process()
{
  int rs; /* Number of times to execute recv().
	     For TCP with 1 socket per call:
	         no. of events returned by poll
	     For UDP and TCP with 1 global socket:
	         recv_count is a flag that stays up as
	         long as there's data to read */

  int loops = max_recv_loops;

  /* What index should we try reading from? */
  static int read_index;

  /* We need to process any messages that we have left over. */
  while (pending_messages && (loops-- > 0)) {
    clock_tick = getmilliseconds();
    if (sockets[read_index]->ss_msglen) {
	struct sockaddr_storage src;
	char msg[SIPP_MAX_MSG_SIZE];
	ssize_t len = read_message(sockets[read_index], msg, sizeof(msg), &src);
	if (len > 0) {
	  process_message(sockets[read_index], msg, len, &src);
	} else {
	  assert(0);
	}
      }
    read_index = (read_index + 1) % pollnfds;
  }

  /* Don't read more data if we still have some left over. */
  if (pending_messages) {
    return;
  }

  /* Get socket events. */
  rs = poll(pollfiles, pollnfds,  1);
  if((rs < 0) && (errno == EINTR)) {
    return;
  }

  /* We need to flush all sockets and pull data into all of our buffers. */
  for(int poll_idx = 0; rs > 0 && poll_idx < pollnfds; poll_idx++) {
    struct sipp_socket *sock = sockets[poll_idx];
    int events = 0;
    int ret = 0;

    assert(sock);

    if(pollfiles[poll_idx].revents & POLLOUT) {
      /* We can flush this socket. */
      TRACE_MSG("Exit problem event on socket %d \n", sock->ss_fd);
      pollfiles[poll_idx].events &= ~POLLOUT;
      sock->ss_congested = false;

      flush_socket(sock);
      events++;
    }

    if(pollfiles[poll_idx].revents & POLLIN) {
      /* We can empty this socket. */
      if ((transport == T_TCP || transport == T_TLS) && sock == main_socket) {
	struct sipp_socket *new_sock = sipp_accept_socket(sock);
	if (!new_sock) {
	  ERROR_NO("Accepting new TCP connection.\n");
	}
      } else if (sock == ctrl_socket) {
	handle_ctrl_socket();
      } else if (sock == stdin_socket) {
	handle_stdin_socket();
      } else if (sock == localTwinSippSocket) {
	if (toolMode == MODE_3PCC_CONTROLLER_B) {
	  twinSippSocket = sipp_accept_socket(sock);
	  if (!twinSippMode) {
	    ERROR_NO("Accepting new TCP connection on Twin SIPp Socket.\n");
	  }
	  twinSippSocket->ss_control = 1;
	} else {
	  /*3pcc extended mode: open a local socket
	    which will be used for reading the infos sent by this remote
	    twin sipp instance (slave or master) */
	  if(local_nb == MAX_LOCAL_TWIN_SOCKETS) {
	    ERROR("Max number of twin instances reached\n");
	  }

	  struct sipp_socket *localSocket = sipp_accept_socket(sock);
	  localSocket->ss_control = 1;
	  local_sockets[local_nb] = localSocket;
	  local_nb++;
	  if(!peers_connected){
	    connect_to_all_peers();
	  }
	}
      } else {
	if ((ret = empty_socket(sock)) <= 0) {
	  read_error(sock, ret);
	}
      }
      events++;
    }

    pollfiles[poll_idx].revents = 0;
    if (events) {
      rs--;
    }
  }

  /* We need to process any new messages that we read. */
  while (pending_messages && (loops-- > 0)) {
    clock_tick = getmilliseconds();

    if (sockets[read_index]->ss_msglen) {
      char msg[SIPP_MAX_MSG_SIZE];
      struct sockaddr_storage src;
      ssize_t len;

      len = read_message(sockets[read_index], msg, sizeof(msg), &src);
      if (len > 0) {
	process_message(sockets[read_index], msg, len, &src);
      } else {
	assert(0);
      }
    }
    read_index = (read_index + 1) % pollnfds;
  }

  cpu_max = loops <= 0;
}

void timeout_alarm(int param){
  quitting = 1;
  timeout_exit = true;
}

/* Send loop & trafic generation*/

void traffic_thread()
{
  unsigned int calls_to_open = 0;
  unsigned int new_time;
  unsigned int last_time;
  bool         firstPass;

  /* create the file */
  char         L_file_name [MAX_PATH];
  sprintf (L_file_name, "%s_%d_screen.log", scenario_file, getpid());


  firstPass = true;
  last_time = getmilliseconds();
 
  /* Arm the global timer if needed */
  if (global_timeout > 0) { 
    signal(SIGALRM, timeout_alarm);
    alarm(global_timeout / 1000);
  }
  
  while(1) {
    scheduling_loops ++;

    /* update local time, except if resetted*/
    new_time = getmilliseconds();

    clock_tick = new_time;
    last_time = new_time;

    if (signalDump) {
       /* Screen dumping in a file */
       if (screenf) {
          print_screens();
       } else {
         /* If the -trace_screen option has not been set, */
         /* create the file at this occasion              */
         screenf = fopen(L_file_name, "a");
	 if (!screenf) {
            WARNING("Unable to create '%s'", L_file_name);
         }
	 print_screens();
	 fclose(screenf);
	 screenf = 0;
       }

       if(dumpInRtt) {
          main_scenario->stats->dumpDataRtt ();
       }

       signalDump = false ;
    }

    while (sockets_pending_reset.begin() != sockets_pending_reset.end()) {
	reset_connection(*(sockets_pending_reset.begin()));
	sockets_pending_reset.erase(sockets_pending_reset.begin());
    }

    if ((!quitting) && (!paused)) {
      long l=0;
      unsigned long long  current_calls = main_scenario->stats->GetStat(CStat::CPT_C_CurrentCall);
      unsigned long long total_calls = main_scenario->stats->GetStat(CStat::CPT_C_IncomingCallCreated) + main_scenario->stats->GetStat(CStat::CPT_C_OutgoingCallCreated);

      if (users >= 0) {
	calls_to_open = ((l = (users - current_calls)) > 0) ? l : 0;
      } else {
	calls_to_open = (unsigned int)
              ((l=(long)floor(((clock_tick - last_rate_change_time) * rate/rate_period_ms)
              - calls_since_last_rate_change))>0?l:0);
      }


      if( (toolMode == MODE_CLIENT)
          || (toolMode == MODE_3PCC_CONTROLLER_A)
          || (toolMode == MODE_MASTER)
          )
        {
	  int first_open_tick = clock_tick;
          while((calls_to_open--) && 
                (!open_calls_allowed || current_calls < open_calls_allowed) &&
                (total_calls < stop_after)) 
            {
	      /* Associate a user with this call, if we are in users mode. */
	      int userid = 0;
	      if (users >= 0) {
		userid = freeUsers.back();
		freeUsers.pop_back();
	      }

              // adding a new OUTGOING CALL
              main_scenario->stats->computeStat(CStat::E_CREATE_OUTGOING_CALL);
              call * call_ptr = call::add_call(userid, is_ipv6, use_remote_sending_addr ? &remote_sending_sockaddr : &remote_sockaddr);
              if(!call_ptr) {
		ERROR("Out of memory allocating call!");
	      }

	      calls_since_last_rate_change++;

	      outbound_congestion = false;

	      if (!multisocket) {
		switch(transport) {
		  case T_UDP:
		    call_ptr->associate_socket(main_socket);
		    main_socket->ss_count++;
		    break;
		  case T_TCP:
		  case T_TLS:
		    call_ptr->associate_socket(tcp_multiplex);
		    tcp_multiplex->ss_count++;
		    break;
		}
	      }

	      call_ptr -> run();

	      while (sockets_pending_reset.begin() != sockets_pending_reset.end()) {
		reset_connection(*(sockets_pending_reset.begin()));
		sockets_pending_reset.erase(sockets_pending_reset.begin());
	      }

	      new_time = getmilliseconds();
	      /* Never spend more than half of our time processing new call requests. */
	      if (new_time > (first_open_tick + (timer_resolution < 2 ? 1 : (timer_resolution / 2)))) {
		break;
	      }
            }

	  if(open_calls_allowed && (current_calls >= open_calls_allowed)) {
	    set_rate(rate);
	  }
        }

        // Quit after asked number of calls is reached
        if(total_calls >= stop_after) {
          quitting = 1;
        }
    } else if (quitting) {
      if (quitting > 11) {
        /* Force exit: abort all calls */
	abort_all_tasks();
      }
      /* Quitting and no more openned calls, close all */
      if(!main_scenario->stats->GetStat(CStat::CPT_C_CurrentCall)) {
	/* We can have calls that do not count towards our open-call count (e.g., dead calls). */
	abort_all_tasks();
	print_statistics(0);

        // Dump the latest statistics if necessary
        if(dumpInFile) {
          main_scenario->stats->dumpData();
        }
	if (useCountf) {
	  print_count_file(countf, 0);
	}

        if(dumpInRtt) {
          main_scenario->stats->dumpDataRtt();
        }

        /* Screen dumping in a file if asked */
        if(screenf) {
          print_screens();
        }

	for (int i = 0; i < pollnfds; i++) {
	  sipp_close_socket(sockets[i]);
	}

        screen_exit(EXIT_TEST_RES_UNKNOWN);
      }
    }

    new_time = getmilliseconds();
    clock_tick = new_time;
    last_time = new_time;

    /* Schedule all pending calls and process their timers */
    task_list *running_tasks;
    if((clock_tick - last_timer_cycle) > timer_resolution) {

      /* Just for the count. */
      running_tasks = get_running_tasks();
      last_running_calls = running_tasks->size();

      /* If we have expired paused calls, move them to the run queue. */
      last_woken_calls += expire_paused_tasks();

      last_paused_calls = paused_tasks_count();

      last_timer_cycle = clock_tick;
    }

    /* We should never get so busy with running calls that we can't process some messages. */
    int loops = max_sched_loops;

    /* Now we process calls that are on the run queue. */
    running_tasks = get_running_tasks();

    /* Workaround hpux problem with iterators. Deleting the
     * current object when iterating breaks the iterator and
     * leads to iterate again on the destroyed (deleted)
     * object. Thus, we have to wait ont step befere actual
     * deletion of the object*/
    task * last = NULL;

    task_list::iterator iter;
    for(iter = running_tasks->begin(); iter != running_tasks->end(); iter++) {
      if(last) {
	last -> run();
	while (sockets_pending_reset.begin() != sockets_pending_reset.end()) {
	  reset_connection(*(sockets_pending_reset.begin()));
	  sockets_pending_reset.erase(sockets_pending_reset.begin());
	}
      }
      last = *iter;
      if (--loops <= 0) {
	break;
      }
    }
    if(last) {
      last -> run();
      while (sockets_pending_reset.begin() != sockets_pending_reset.end()) {
	reset_connection(*(sockets_pending_reset.begin()));
	sockets_pending_reset.erase(sockets_pending_reset.begin());
      }
    }

    /* Update the clock. */
    new_time = getmilliseconds();
    clock_tick = new_time ;
    last_time = new_time;

    /* Receive incoming messages */
    pollset_process();
    new_time = getmilliseconds();
    clock_tick = new_time ;
    last_time = new_time;

    if(firstPass)
      {
        // dumping (to create file on disk) and showing 
        // screen at the beginning even if the report
        // period is not reach
        firstPass = false;
	if (report_freq > 0) {
	  print_statistics(0);
	}
        /* Dumping once to create the file on disk */
        if(dumpInFile)
          {
            main_scenario->stats->dumpData();
          }

	if (useCountf) {
	    print_count_file(countf, 0);
	}

        if(dumpInRtt)
          {
            main_scenario->stats->dumpDataRtt();
          }

      }

    if(report_freq && ((clock_tick - last_report_time) >= report_freq))
      {
        print_statistics(0);
        display_scenario->stats->computeStat(CStat::E_RESET_PD_COUNTERS);
        last_report_time  = clock_tick;
        scheduling_loops = 0;
      }

    // FIXME - Should we recompute time ? print stat take 
    // a lot of time, so the clock_time is no more 
    // the current time !
    if((clock_tick - last_dump_time) >= report_freq_dumpLog)  {
      if(dumpInFile) {
	main_scenario->stats->dumpData();
      }
      if (useCountf) {
	print_count_file(countf, 0);
      }
      main_scenario->stats->computeStat(CStat::E_RESET_PL_COUNTERS);
      last_dump_time  = clock_tick;
      if (rate_increase) {
	rate += rate_increase;
	if (rate_max && (rate > rate_max)) {
	  rate = rate_max;
	  if (rate_quit) {
	    quitting += 10;
	  }
	}
	set_rate(rate);
      }
    }
  }
}

/*************** RTP ECHO THREAD ***********************/
/* param is a pointer to RTP socket */

void rtp_echo_thread (void * param)
{
  char *msg = (char*)alloca(media_bufsize);
  size_t nr, ns;
  sipp_socklen_t len;
  struct sockaddr_storage remote_rtp_addr;


   int                   rc;
   sigset_t              mask;
   sigfillset(&mask); /* Mask all allowed signals */
   rc = pthread_sigmask(SIG_BLOCK, &mask, NULL);

  for (;;) {
    len = sizeof(remote_rtp_addr);
    nr = recvfrom(*(int *)param, 
                  msg, 
                  media_bufsize, 0, 
                  (sockaddr *)(void *) &remote_rtp_addr, 
                  &len);

    if (((long)nr) < 0) {
      WARNING("%s %i",
                 "Error on RTP echo reception - stopping echo - errno=", 
                 errno);
      return;
    }
    ns = sendto(*(int *)param, msg, nr, 
                0, (sockaddr *)(void *) &remote_rtp_addr, 
                len);

    if (ns != nr) {
      WARNING("%s %i",
                 "Error on RTP echo transmission - stopping echo - errno=", 
                 errno);
      return;
    }
    
    if (*(int *)param==media_socket) {    
    rtp_pckts++;
    rtp_bytes += ns;
  }
    else {
      /* packets on the second RTP stream */
      rtp2_pckts++;
      rtp2_bytes += ns;
    }
  }
}

/* Wrap the help text. */
char *wrap(const char *in, int offset, int size) {
  int pos = 0;
  int i, j;
  int l = strlen(in);
  int alloced = l + 1;
  char *out = (char *)malloc(alloced);
  int indent = 0;

  if (!out) {
    ERROR_NO("malloc");
  }

  for (i = j = 0; i < l; i++) {
    out[j++] = in[i];
    if (in[i] == '\n') {
      out = (char *)realloc(out, alloced += offset);
      if (!out) {
        ERROR_NO("realloc");
      }
      pos = 0;
      for (int k = 0; k < offset; k++) {
        out[j++] = ' ';
      }
      if (indent) {
        indent = 0;
      }
    }
    if (in[i] == '-' && i > 0 && in[i - 1] == '\n') {
      indent = 1;
    }
    if (++pos > size) {
      int k;
      for (k = j - 1; k > 0 && !isspace(out[k]); k--);
      int useoffset = offset;

      if (indent) {
        useoffset += 2;
      }

      if (k == 0 || out[k] == '\n') {
        pos = 0;
        out[j++] = '\n';
        out = (char *)realloc(out, alloced += useoffset);
        if (!out) {
          ERROR_NO("realloc");
        }
        for (k = 0; k < useoffset; k++) {
          out[j++] = ' ';
        }
      } else {
        int m;

        out[j] = '\0';
        //printf("Before wrapping (pos = %d, k = %d, j = %d):\n%-*s%s\n", pos, k, j, offset, "", out);

        out[k] = '\n';
        pos = j - k;
        k++;
        out[j] = '\0';
        out = (char *)realloc(out, alloced += useoffset);
        if (!out) {
          ERROR_NO("realloc");
        }
        for (m = 0; m < useoffset; m++) {
          if (k + useoffset + m < alloced) {
            out[k + useoffset + m] = out[k + m];
          }
          out[k + m] = ' ';
        }
        j += useoffset;
        out[j] = '\0';
        //printf("After wrapping (pos = %d, k = %d):\n%-*s%s\n", pos, k, offset, "", out);
      }
    }
  }
  out[j] = '\0';

  return out;
}

/* Help screen */
void help() 
{
  int i, max;

  printf
    ("\n"
     "Usage:\n"
     "\n"
     "  sipp remote_host[:remote_port] [options]\n"
     "\n"
     "  Available options:\n"
     "\n");

  /* We automatically generate the help messages based on the options array.
   * This should hopefully encourage people to write help text when they
   * introduce a new option and keep the code a bit cleaner. */
    max = sizeof(options_table)/sizeof(options_table[0]);
    for (i = 0; i < max; i++) {
      char *formatted;
      if (!options_table[i].help) {
        continue;
      }
      formatted = wrap(options_table[i].help, 22, 57);
      printf("   -%-16s: %s\n\n", options_table[i].option, formatted);
      free(formatted);
    }

    printf
    (
     "Signal handling:\n"
     "\n"
     "   SIPp can be controlled using posix signals. The following signals\n"
     "   are handled:\n"
     "   USR1: Similar to press 'q' keyboard key. It triggers a soft exit\n"
     "         of SIPp. No more new calls are placed and all ongoing calls\n"
     "         are finished before SIPp exits.\n"
     "         Example: kill -SIGUSR1 732\n"
     "   USR2: Triggers a dump of all statistics screens in\n"
     "         <scenario_name>_<pid>_screens.log file. Especially useful \n"
     "         in background mode to know what the current status is.\n"
     "         Example: kill -SIGUSR2 732\n"
     "\n"
     "Exit code:\n"
     "\n"
     "   Upon exit (on fatal error or when the number of asked calls (-m\n"
     "   option) is reached, sipp exits with one of the following exit\n"
     "   code:\n"
     "    0: All calls were successful\n"
     "    1: At least one call failed\n"
     "   97: exit on internal command. Calls may have been processed\n"
     "   99: Normal exit without calls processed\n"
     "   -1: Fatal error\n"
     "\n"
     "\n"
     "Example:\n"
     "\n"
     "   Run sipp with embedded server (uas) scenario:\n"
     "     ./sipp -sn uas\n"
     "   On the same host, run sipp with embedded client (uac) scenario\n"
     "     ./sipp -sn uac 127.0.0.1\n"
     "\n");
}


void help_stats() 
{
  printf(
"\n"
"  The  -trace_stat option dumps all statistics in the\n"
"  <scenario_name.csv> file. The dump starts with one header\n" 
"  line with all counters. All following lines are 'snapshots' of \n"
"  statistics counter given the statistics report frequency\n"
"  (-fd option). This file can be easily imported in any\n"
"  spreadsheet application, like Excel.\n"
"\n"
"  In counter names, (P) means 'Periodic' - since last\n"
"  statistic row and (C) means 'Cumulated' - since sipp was\n"
"  started.\n"
"\n"
"  Available statistics are:\n"
"\n"
"  - StartTime: \n"
"    Date and time when the test has started.\n"
"\n"
"  - LastResetTime:\n"
"    Date and time when periodic counters where last reseted.\n"
"\n"
"  - CurrentTime:\n"
"    Date and time of the statistic row.\n"
"\n"
"  - ElapsedTime:\n"
"    Elapsed time.\n"
"\n"
"  - CallRate:\n"
"    Call rate (calls per seconds).\n"
"\n"
"  - IncomingCall:\n"
"    Number of incoming calls.\n"
"\n"
"  - OutgoingCall:\n"
"    Number of outgoing calls.\n"
"\n"
"  - TotalCallCreated:\n"
"    Number of calls created.\n"
"\n"
"  - CurrentCall:\n"
"    Number of calls currently ongoing.\n"
"\n"
"  - SuccessfulCall:\n"
"    Number of successful calls.\n"
"\n"
"  - FailedCall:\n"
"    Number of failed calls (all reasons).\n"
"\n"
"  - FailedCannotSendMessage:\n"
"    Number of failed calls because Sipp cannot send the\n"
"    message (transport issue).\n"
"\n"
"  - FailedMaxUDPRetrans:\n"
"    Number of failed calls because the maximum number of\n"
"    UDP retransmission attempts has been reached.\n"
"\n"
"  - FailedUnexpectedMessage:\n"
"    Number of failed calls because the SIP message received\n"
"    is not expected in the scenario.\n"
"\n"
"  - FailedCallRejected:\n"
"    Number of failed calls because of Sipp internal error.\n"
"    (a scenario sync command is not recognized or a scenario\n"
"    action failed or a scenario variable assignment failed).\n"
"\n"
"  - FailedCmdNotSent:\n"
"    Number of failed calls because of inter-Sipp\n"
"    communication error (a scenario sync command failed to\n"
"    be sent).\n"
"\n"
"  - FailedRegexpDoesntMatch:\n"
"    Number of failed calls because of regexp that doesn't\n"
"    match (there might be several regexp that don't match\n"
"    during the call but the counter is increased only by\n"
"    one).\n"
"\n"
"  - FailedRegexpHdrNotFound:\n"
"    Number of failed calls because of regexp with hdr    \n"
"    option but no matching header found.\n"
"\n"
"  - OutOfCallMsgs:\n"
"    Number of SIP messages received that cannot be associated\n"
"    to an existing call.\n"
"\n"
"  - AutoAnswered:\n"
"    Number of unexpected specific messages received for new Call-ID.\n"
"    The message has been automatically answered by a 200 OK\n"
"    Currently, implemented for 'PING' message only.\n"
"\n");
}

/************* exit handler *****************/

void print_last_stats()
{
  interrupt = 1;
  // print last current screen
  print_statistics(1);
  // and print statistics screen
  currentScreenToDisplay = DISPLAY_STAT_SCREEN;
  print_statistics(1);
}

void freeInFiles() {
  for (file_map::iterator file_it = inFiles.begin(); file_it != inFiles.end(); file_it++) {
    delete file_it->second;
  }
}

void freeUserVarMap() {
  for (int_vt_map::iterator vt_it = userVarMap.begin(); vt_it != userVarMap.end(); vt_it++) {
    vt_it->second->putTable();
    userVarMap[vt_it->first] = NULL;
  }
}

void releaseGlobalAllocations()
{
  int i,j;
  message * L_ptMsg = NULL;

  delete main_scenario;
  delete ooc_scenario;
  free_default_messages();
  freeInFiles();
  freeUserVarMap();
  delete globalVariables;
}

void stop_all_traces()
{
  if(messagef) messagef = NULL;
  if(logfile) logfile = NULL;
 // if(timeoutf) timeoutf = NULL; TODO: finish the -trace_timeout option implementation
  if(dumpInRtt) dumpInRtt = 0;
  if(dumpInFile) dumpInFile = 0;
  
}

char* remove_pattern(char* P_buffer, char* P_extensionPattern) {

  char *L_ptr = P_buffer;

  if (P_extensionPattern == NULL) {
    return P_buffer ;
  }

  if (P_buffer == NULL) {
    return P_buffer ;
  }

  L_ptr = strstr(P_buffer, P_extensionPattern) ;
  if (L_ptr != NULL) {
    *L_ptr = '\0' ;
  }

  return P_buffer ;
}

static struct sipp_socket *sipp_allocate_socket(bool use_ipv6, int transport, int fd, int accepting) {
  struct sipp_socket *ret = NULL;

  ret = (struct sipp_socket *)malloc(sizeof(struct sipp_socket));
  if (!ret) {
    ERROR("Could not allocate a sipp_socket structure.");
  }
  memset(ret, 0, sizeof(struct sipp_socket));


  ret->ss_transport = transport;
  ret->ss_control = false;
  ret->ss_ipv6 = use_ipv6;
  ret->ss_fd = fd;
  ret->ss_comp_state = NULL;
  ret->ss_count = 1;

  /* Initialize all sockets with our destination address. */
  memcpy(&ret->ss_remote_sockaddr, &remote_sockaddr, sizeof(ret->ss_remote_sockaddr));

#ifdef _USE_OPENSSL
  ret->ss_ssl = NULL;

  if ( transport == T_TLS ) {
    if ((ret->ss_bio = BIO_new_socket(fd,BIO_NOCLOSE)) == NULL) {
      ERROR("Unable to create BIO object:Problem with BIO_new_socket()\n");
    }

    if (!(ret->ss_ssl = SSL_new(accepting ? sip_trp_ssl_ctx : sip_trp_ssl_ctx_client))) {
      ERROR("Unable to create SSL object : Problem with SSL_new() \n");
    }

    SSL_set_bio(ret->ss_ssl,ret->ss_bio,ret->ss_bio);
  }
#endif

  ret->ss_in = NULL;
  ret->ss_out = NULL;
  ret->ss_msglen = 0;
  ret->ss_congested = false;
  ret->ss_invalid = false;

  /* Store this socket in the tables. */
  ret->ss_pollidx = pollnfds++;
  sockets[ret->ss_pollidx] = ret;
  pollfiles[ret->ss_pollidx].fd      = ret->ss_fd;
  pollfiles[ret->ss_pollidx].events  = POLLIN | POLLERR;
  pollfiles[ret->ss_pollidx].revents = 0;

  return ret;
}

static struct sipp_socket *sipp_allocate_socket(bool use_ipv6, int transport, int fd) {
	return sipp_allocate_socket(use_ipv6, transport, fd, 0);
}

int socket_fd(bool use_ipv6, int transport) {
  int socket_type;
  int fd;

  switch(transport) {
    case T_UDP:
      socket_type = SOCK_DGRAM;
      break;
    case T_TLS:
#ifndef _USE_OPENSSL
      ERROR("You do not have TLS support enabled!\n");
#endif
    case T_TCP:
      socket_type = SOCK_STREAM;
      break;
  }

  if((fd = socket(use_ipv6 ? AF_INET6 : AF_INET, socket_type, 0))== -1) {
    ERROR("Unable to get a %s socket", TRANSPORT_TO_STRING(transport));
  }

  return fd;
}

struct sipp_socket *new_sipp_socket(bool use_ipv6, int transport) {
  struct sipp_socket *ret;
  int fd = socket_fd(use_ipv6, transport);

  ret  = sipp_allocate_socket(use_ipv6, transport, fd);
  if (!ret) {
    close(fd);
    ERROR("Could not allocate new socket structure!");
  }
  return ret;
}

struct sipp_socket *new_sipp_call_socket(bool use_ipv6, int transport, bool *existing) {
  struct sipp_socket *sock = NULL;
  static int next_socket;
  if (call_sockets >= max_multi_socket - 1) {  // we must take the main socket into account
    /* Find an existing socket that matches transport and ipv6 parameters. */
    int first = next_socket;
    do
    {
      int test_socket = next_socket;
      next_socket = (next_socket + 1) % pollnfds;

      assert(sockets[test_socket]->ss_call_socket >= 0);
      if (sockets[test_socket]->ss_call_socket) {
	sock = sockets[test_socket];
	sock->ss_count++;
	*existing = true;
	break;
      }
    }
    while (next_socket != first);
    if (next_socket == first) {
      ERROR("Could not find an existing call socket to re-use!");
    }
  } else {
    sock = new_sipp_socket(use_ipv6, transport);
    sock->ss_call_socket = true;
    call_sockets++;
    *existing = false;
  }
  return sock;
}

struct sipp_socket *sipp_accept_socket(struct sipp_socket *accept_socket) {
  struct sipp_socket *ret;
  struct sockaddr_storage remote_sockaddr;
  int fd;
  sipp_socklen_t addrlen = sizeof(remote_sockaddr);

  if((fd = accept(accept_socket->ss_fd, (struct sockaddr *)&remote_sockaddr, &addrlen))== -1) {
    ERROR("Unable to accept on a %s socket: %s", TRANSPORT_TO_STRING(transport), strerror(errno));
  }

  ret  = sipp_allocate_socket(accept_socket->ss_ipv6, accept_socket->ss_transport, fd, 1);
  if (!ret) {
	close(fd);
	ERROR_NO("Could not allocate new socket!");
  }

  memcpy(&ret->ss_remote_sockaddr, &remote_sockaddr, sizeof(ret->ss_remote_sockaddr));
  /* We should connect back to the address which connected to us if we
   * experience a TCP failure. */
  memcpy(&ret->ss_dest, &remote_sockaddr, sizeof(ret->ss_remote_sockaddr));

  if (ret->ss_transport == T_TLS) {
#ifdef _USE_OPENSSL
    int err;
    if ((err = SSL_accept(ret->ss_ssl)) < 0) {
      ERROR("Error in SSL_accept: %s\n", sip_tls_error_string(accept_socket->ss_ssl, err));
    }
#else
    ERROR("You need to compile SIPp with TLS support");
#endif
  }

  return ret;
}

int sipp_bind_socket(struct sipp_socket *socket, struct sockaddr_storage *saddr, int *port) {
  int ret;
  int len;

  if (socket->ss_ipv6) {
    len = sizeof(struct sockaddr_in6);
  } else {
    len = sizeof(struct sockaddr_in);
  }

  if((ret = bind(socket->ss_fd, (sockaddr *)saddr, len))) {
    return ret;
  }

  if (!port) {
    return 0;
  }

  if ((ret = getsockname(socket->ss_fd, (sockaddr *)saddr, (sipp_socklen_t *) &len))) {
    return ret;
  }

  if (socket->ss_ipv6) {
    *port = ntohs((short)((_RCAST(struct sockaddr_in6 *, saddr))->sin6_port));
  } else {
    *port = ntohs((short)((_RCAST(struct sockaddr_in *, saddr))->sin_port));
  }

  return 0;
}

int sipp_do_connect_socket(struct sipp_socket *socket) {
  int ret;

  assert(socket->ss_transport == T_TCP || socket->ss_transport == T_TLS);

  errno = 0;
  ret = connect(socket->ss_fd, (struct sockaddr *)&socket->ss_dest, SOCK_ADDR_SIZE(&socket->ss_dest));
  if (ret < 0) {
    return ret;
  }

  if (socket->ss_transport == T_TLS) {
#ifdef _USE_OPENSSL
    int err;
    if ((err = SSL_connect(socket->ss_ssl)) < 0) {
      ERROR("Error in SSL connection: %s\n", sip_tls_error_string(socket->ss_ssl, err));
    }
#else
    ERROR("You need to compile SIPp with TLS support");
#endif
  }

  return 0;
}

int sipp_connect_socket(struct sipp_socket *socket, struct sockaddr_storage *dest) {
  memcpy(&socket->ss_dest, dest, SOCK_ADDR_SIZE(dest));
  return sipp_do_connect_socket(socket);
}

int sipp_reconnect_socket(struct sipp_socket *socket) {
  assert(socket->ss_fd == -1);

  socket->ss_fd = socket_fd(socket->ss_ipv6, socket->ss_transport);
  if (socket->ss_fd == -1) {
    ERROR_NO("Could not obtain new socket: ");
  }

  if (socket->ss_invalid) {
#ifdef _USE_OPENSSL
    socket->ss_ssl = NULL;

    if ( transport == T_TLS ) {
      if ((socket->ss_bio = BIO_new_socket(socket->ss_fd,BIO_NOCLOSE)) == NULL) {
	ERROR("Unable to create BIO object:Problem with BIO_new_socket()\n");
      }

      if (!(socket->ss_ssl = SSL_new(sip_trp_ssl_ctx_client))) {
	ERROR("Unable to create SSL object : Problem with SSL_new() \n");
      }

      SSL_set_bio(socket->ss_ssl,socket->ss_bio,socket->ss_bio);
    }
#endif

    /* Store this socket in the tables. */
    socket->ss_pollidx = pollnfds++;
    sockets[socket->ss_pollidx] = socket;
    pollfiles[socket->ss_pollidx].fd      = socket->ss_fd;
    pollfiles[socket->ss_pollidx].events  = POLLIN | POLLERR;
    pollfiles[socket->ss_pollidx].revents = 0;

    socket->ss_invalid = false;
  }

  return sipp_do_connect_socket(socket);
}


/* Main */
int main(int argc, char *argv[])
{
  int                  argi = 0;
  struct sockaddr_storage   media_sockaddr;
  pthread_t            pthread_id, pthread2_id,  pthread3_id;
  int                  L_maxSocketPresent = 0;
  unsigned int         generic_count = 0;
  bool                 slave_masterSet = false;
  
  generic[0] = NULL;

  /* At least one argument is needed */
  if(argc < 2) {
    help();
    exit(EXIT_OTHER);
  }
  {
    /* Ignore the SIGPIPE signal */
    struct sigaction action_pipe;
    memset(&action_pipe, 0, sizeof(action_pipe));
    action_pipe.sa_handler=SIG_IGN;
    sigaction(SIGPIPE, &action_pipe, NULL);

    /* The Window Size change Signal is also useless, and causes failures. */
#ifdef SIGWINCH
    sigaction(SIGWINCH, &action_pipe, NULL);
#endif

    /* sig usr1 management */
    struct sigaction action_usr1;
    memset(&action_usr1, 0, sizeof(action_usr1));
    action_usr1.sa_handler = sipp_sigusr1;
    sigaction(SIGUSR1, &action_usr1, NULL);

    /* sig usr2 management */
    struct sigaction action_usr2;
    memset(&action_usr2, 0, sizeof(action_usr2));
    action_usr2.sa_handler = sipp_sigusr2;
    sigaction(SIGUSR2, &action_usr2, NULL);
  }

  screen_set_exename((char *)"sipp");
  
  pid = getpid();
  memset(local_ip, 0, 40);
  memset(media_ip,0, 40);
  memset(control_ip,0, 40);
  memset(media_ip_escaped,0, 42);
  
  /* Load compression pluggin if available */
  comp_load();

  /* Initialize the tolower table. */
  init_tolower_table();

  /* Initialize our global variable structure. */
  globalVariables = new AllocVariableTable(NULL);
  userVariables = new AllocVariableTable(globalVariables);

  /* Command line parsing */
#define REQUIRE_ARG() if((++argi) >= argc) { ERROR("Missing argument for param '%s'.\n" \
				     "Use 'sipp -h' for details",  argv[argi - 1]); }
#define CHECK_PASS() if (option->pass != pass) { break; }

  for (int pass = 0; pass <= 2; pass++) {
    for(argi = 1; argi < argc; argi++) {
      struct sipp_option *option = find_option(argv[argi]);
      if (!option) {
	if((argv[argi])[0] != '-') {
	  strcpy(remote_host, argv[argi]);
	  continue;
	}
	help();
	ERROR("Invalid argument: '%s'.\n"
	    "Use 'sipp -h' for details", argv[argi]);
      }

      switch(option->type)
      {
	case SIPP_OPTION_HELP:
	  if(((argi+1) < argc) && (!strcmp(argv[argi+1], "stat"))) {
	    help_stats();
	  } else {
	    help();
	  }
	  exit(EXIT_OTHER);
	case SIPP_OPTION_VERSION:
	  printf("\n SIPp v3.1"
#ifdef _USE_OPENSSL
	      "-TLS"
#endif
#ifdef PCAPPLAY
	      "-PCAP"
#endif
	      ", version %s, built %s, %s.\n\n",
	      SIPP_VERSION, __DATE__, __TIME__); 

	  printf
	    (" This program is free software; you can redistribute it and/or\n"
	     " modify it under the terms of the GNU General Public License as\n"
	     " published by the Free Software Foundation; either version 2 of\n"
	     " the License, or (at your option) any later version.\n"
	     "\n"
	     " This program is distributed in the hope that it will be useful,\n"
	     " but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
	     " MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
	     " GNU General Public License for more details.\n"
	     "\n"
	     " You should have received a copy of the GNU General Public\n"
	     " License along with this program; if not, write to the\n"
	     " Free Software Foundation, Inc.,\n"
	     " 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA\n"
	     "\n"
	     " Author: see source files.\n\n");
	  exit(EXIT_OTHER);
	case SIPP_OPTION_INT:
	  REQUIRE_ARG();
	  CHECK_PASS();
	  *((int *)option->data) = get_long(argv[argi], argv[argi-1]);
	  break;
        case SIPP_OPTION_LONG:
          REQUIRE_ARG();
          CHECK_PASS();
          *((long *)option->data) = get_long(argv[argi], argv[argi-1]);
          break; 
        case SIPP_OPTION_LONG_LONG:
          REQUIRE_ARG();
          CHECK_PASS();
          *((unsigned long long *)option->data) = get_long_long(argv[argi], argv[argi-1]);
          break;
	case SIPP_OPTION_TIME_SEC:
	  REQUIRE_ARG();
	  CHECK_PASS();
	  *((long *)option->data) = get_time(argv[argi], argv[argi-1], 1000);
	  break;
	case SIPP_OPTION_TIME_MS:
	  REQUIRE_ARG();
	  CHECK_PASS();
	  *((int *)option->data) = get_time(argv[argi], argv[argi-1], 1);
	  break;
        case SIPP_OPTION_TIME_MS_LONG:
          REQUIRE_ARG();
          CHECK_PASS();
          *((long *)option->data) = get_time(argv[argi], argv[argi-1], 1);
          break;
	case SIPP_OPTION_BOOL:
	  REQUIRE_ARG();
	  CHECK_PASS();
	  *((bool *)option->data) = get_bool(argv[argi], argv[argi-1]);
	  break;
	case SIPP_OPTION_FLOAT:
	  REQUIRE_ARG();
	  CHECK_PASS();
	  *((double *)option->data) = get_double(argv[argi], argv[argi-1]);
	  break;
	case SIPP_OPTION_STRING:
	  REQUIRE_ARG();
	  CHECK_PASS();
	  *((char **)option->data) = argv[argi];
	  break;
	case SIPP_OPTION_ARGI:
	  REQUIRE_ARG();
	  CHECK_PASS();
	  *((int *)option->data) = argi;
	  break;
	case SIPP_OPTION_INPUT_FILE:
	  REQUIRE_ARG();
	  CHECK_PASS();
	  inFiles[argv[argi]] = new FileContents(argv[argi]);
	  /* By default, the first file is used for IP address input. */
	  if (!ip_file) {
	    ip_file = argv[argi];
	  }
	  if (!default_file) {
	    default_file = argv[argi];
	  }
	  break;
	case SIPP_OPTION_INDEX_FILE:
	  REQUIRE_ARG();
	  REQUIRE_ARG();
	  CHECK_PASS();
	  {
	    char *fileName = argv[argi - 1];
	    char *endptr;
	    char tmp[SIPP_MAX_MSG_SIZE];
	    int field;

	    if (inFiles.find(fileName) == inFiles.end()) {
	      ERROR("Could not find file for -infindex: %s", argv[argi - 1]);
	    }

	    field = strtoul(argv[argi], &endptr, 0);
	    if (*endptr) {
	      ERROR("Invalid field specification for -infindex: %s", argv[argi]);
	    }

	    infIndex[fileName] = new str_int_map;

	    for (int line = 0; line < inFiles[fileName]->numLines(); line++) {
	      inFiles[fileName]->getField(line, field, tmp, SIPP_MAX_MSG_SIZE);
	      str_int_map *indmap = infIndex[fileName];
	      indmap->insert(pair<str_int_map::key_type,int>(str_int_map::key_type(tmp), line));
	    }
	  }
	  break;
	case SIPP_OPTION_SETFLAG:
	  CHECK_PASS();
	  *((bool *)option->data) = true;
	  break;
	case SIPP_OPTION_UNSETFLAG:
	  CHECK_PASS();
	  *((bool *)option->data) = false;
	  break;
	case SIPP_OPTION_TRANSPORT:
	  REQUIRE_ARG();
	  CHECK_PASS();

	  if (strlen(argv[argi]) != 2) {
	    ERROR("Invalid argument for -t param : '%s'.\n"
		"Use 'sipp -h' for details",  argv[argi]);
	  }

	  switch(argv[argi][0]) {
	    case 'u':
	      transport = T_UDP;
	      break;
	    case 't':
	      transport = T_TCP;
	      break;
	    case 'l':
#ifdef _USE_OPENSSL
	      transport = T_TLS;
	      if ( init_OpenSSL() != 1) {
		printf("OpenSSL Initialization problem\n");
		exit ( -1);
	      }
#else
	      ERROR("To use a TLS transport you must compile SIPp with OpenSSL");
#endif
	      break;
	    case 'c':
	      if(strlen(comp_error)) {
		ERROR("No " COMP_PLUGGIN " pluggin available:\n%s", comp_error);
	      }
	      transport = T_UDP;
	      compression = 1;
	  }
	  switch(argv[argi][1]) {
	    case '1':
	      multisocket = 0;
	      peripsocket = 0;
	      break;
	    case 'n':
	      multisocket = 1;
	      peripsocket = 0;
	      break;
	    case 'i':
	      multisocket = 1;
	      peripsocket = 1;
	      socket_close = false;
	      break;
	  }

	  if (peripsocket && transport != T_UDP) {
	    ERROR("You can only use a perip socket with UDP!\n");
	  }
	  break;
	case SIPP_OPTION_NEED_SSL:
	  CHECK_PASS();
	  ERROR("OpenSSL is required for the %s option.", argv[argi]);
	  break;
	case SIPP_OPTION_MAX_SOCKET:
	  REQUIRE_ARG();
	  CHECK_PASS();
	  max_multi_socket = get_long(argv[argi], argv[argi - 1]);
	  maxSocketPresent = true ;
	  break;
	case SIPP_OPTION_CSEQ:
	  REQUIRE_ARG();
	  CHECK_PASS();
	  base_cseq = get_long(argv[argi], argv[argi - 1]);
	  base_cseq--;
	  break;
	case SIPP_OPTION_IP:
	  {
	    int dummy_port;
	    char *ptr = (char *)option->data;
	    REQUIRE_ARG();
	    CHECK_PASS();

	    strcpy(ptr, argv[argi]);
	    get_host_and_port(ptr, ptr, &dummy_port);
	  }
	  break;
	case SIPP_OPTION_LIMIT:
	  REQUIRE_ARG();
	  CHECK_PASS();
	  open_calls_allowed = get_long(argv[argi], argv[argi - 1]);
	  open_calls_user_setting = 1;
	  break;
	case SIPP_OPTION_USERS:
	  REQUIRE_ARG();
	  CHECK_PASS();
	  users = open_calls_allowed = get_long(argv[argi], argv[argi - 1]);
	  open_calls_user_setting = 1;
	  break;
	case SIPP_OPTION_KEY:
	  REQUIRE_ARG();
	  REQUIRE_ARG();
	  CHECK_PASS();

	  if (generic_count+1 >= sizeof(generic)/sizeof(generic[0])) {
	    ERROR("Too many generic parameters %d",generic_count+1);
	  }
	  generic[generic_count++] = &argv[argi - 1];
	  generic[generic_count] = NULL;
	  break;
	case SIPP_OPTION_3PCC:
	  if(slave_masterSet){
	    ERROR("-3PCC option is not compatible with -master and -slave options\n");
	  }
	  if(extendedTwinSippMode){
	    ERROR("-3pcc and -slave_cfg options are not compatible\n");
	  } 
	  REQUIRE_ARG();
	  CHECK_PASS();
	  twinSippMode = true;
	  strcpy(twinSippHost, argv[argi]);
	  get_host_and_port(twinSippHost, twinSippHost, &twinSippPort);
	  break;
	case SIPP_OPTION_SCENARIO:
	  REQUIRE_ARG();
	  CHECK_PASS();
	  if (!strcmp(argv[argi - 1], "-sf")) {
	    main_scenario = new scenario(argv[argi], 0);
	    scenario_file = new char [strlen(argv[argi])+1] ;
	    sprintf(scenario_file,"%s", argv[argi]);
	    main_scenario->stats->setFileName(argv[argi], (char*)".csv");
	  } else if (!strcmp(argv[argi - 1], "-sn")) {
	    int i = find_scenario(argv[argi]);

	    main_scenario = new scenario(0, i);
	    scenario_file = new char [strlen(argv[argi])+1] ;
	    sprintf(scenario_file,"%s", argv[argi]);
	    main_scenario->stats->setFileName(argv[argi], (char*)".csv");
	  } else if (!strcmp(argv[argi - 1], "-sd")) {
	    int i = find_scenario(argv[argi]);
	    fprintf(stdout, "%s", default_scenario[i]);
	    exit(EXIT_OTHER);
	  } else {
	    ERROR("Internal error, I don't recognize %s as a scenario option\n", argv[argi] - 1);
	  }
	  break;
	case SIPP_OPTION_OOC_SCENARIO:
	  REQUIRE_ARG();
	  CHECK_PASS();
	  if (!strcmp(argv[argi - 1], "-oocsf")) {
	    ooc_scenario = new scenario(argv[argi], 0);
	  } else if (!strcmp(argv[argi - 1], "-oocsn")) {
	    int i = find_scenario(argv[argi]);
	    ooc_scenario = new scenario(0, i);
	  } else {
	    ERROR("Internal error, I don't recognize %s as a scenario option\n", argv[argi] - 1);
	  }
	  break;
	case SIPP_OPTION_SLAVE_CFG: 
	  REQUIRE_ARG();
	  CHECK_PASS();
	  if(twinSippMode){
	    ERROR("-slave_cfg and -3pcc options are not compatible\n");
	  }
	  extendedTwinSippMode = true;
	  slave_cfg_file = new char [strlen(argv[argi])+1] ;
	  sprintf(slave_cfg_file,"%s", argv[argi]);
	  parse_slave_cfg();
	  break;
	case SIPP_OPTION_3PCC_EXTENDED:
     REQUIRE_ARG();
     CHECK_PASS();
	  if(slave_masterSet){
	    ERROR("-slave and -master options are not compatible\n");
	  }
	  if(twinSippMode){
	    ERROR("-master and -slave options are not compatible with -3PCC option\n");
	  }
	  *((char **)option->data) = argv[argi];
	  slave_masterSet = true;
	  break;
	case SIPP_OPTION_RSA: {
	  REQUIRE_ARG();
	  CHECK_PASS();
	  char *remote_s_address ;
	  int   remote_s_p = DEFAULT_PORT;
	  int   temp_remote_s_p;

	  temp_remote_s_p = 0;
	  remote_s_address = argv[argi] ;
	  get_host_and_port(remote_s_address, remote_s_address, &temp_remote_s_p);
	  if (temp_remote_s_p != 0) {
	    remote_s_p = temp_remote_s_p;
	  }
	  struct addrinfo   hints;
	  struct addrinfo * local_addr;

	  printf("Resolving remote sending address %s...\n", remote_s_address);

	  memset((char*)&hints, 0, sizeof(hints));
	  hints.ai_flags  = AI_PASSIVE;
	  hints.ai_family = PF_UNSPEC;

	  /* FIXME: add DNS SRV support using liburli? */
	  if (getaddrinfo(remote_s_address,
		NULL,
		&hints,
		&local_addr) != 0) {
	    ERROR("Unknown remote host '%s'.\n"
		"Use 'sipp -h' for details", remote_s_address);
	  }

	  memcpy(&remote_sending_sockaddr,
	      local_addr->ai_addr,
	      SOCK_ADDR_SIZE(
		_RCAST(struct sockaddr_storage *, local_addr->ai_addr)));

	  if (remote_sending_sockaddr.ss_family == AF_INET) {
	    (_RCAST(struct sockaddr_in *, &remote_sending_sockaddr))->sin_port =
	      htons((short)remote_s_p);
	  } else {
	    (_RCAST(struct sockaddr_in6 *, &remote_sending_sockaddr))->sin6_port =
	      htons((short)remote_s_p);
	  }
	  use_remote_sending_addr = 1 ;

	  freeaddrinfo(local_addr);
	  break;
	}
	case SIPP_OPTION_TDMMAP: {
          REQUIRE_ARG();
	  CHECK_PASS();
	  int i1, i2, i3, i4, i5, i6, i7;

	  if (sscanf(argv[argi], "{%d-%d}{%d}{%d-%d}{%d-%d}", &i1, &i2, &i3, &i4, &i5, &i6, &i7) == 7) {
	    use_tdmmap = true;
	    tdm_map_a = i2 - i1;
	    tdm_map_x = i1;
	    tdm_map_h = i3;
	    tdm_map_b = i5 - i4;
	    tdm_map_y = i4;
	    tdm_map_c = i7 - i6;
	    tdm_map_z = i6;
	  } else {
	    ERROR("Parameter -tdmmap must be of form {%%d-%%d}{%%d}{%%d-%%d}{%%d-%%d}");
	  }
	  break;
	}
	case SIPP_OPTION_DEFAULTS: {
	    unsigned long *ptr = (unsigned long *)option->data;
	    char *token;

	    REQUIRE_ARG();
	    CHECK_PASS();

	    *ptr = 0;

	    token = argv[argi];
	    while ((token = strtok(token, ","))) {
		if (!strcmp(token, "none")) {
		  *ptr = 0;
		} else {
		  unsigned long mask = 0;
		  int mode = 1;
		  char *p = token;
		  if (token[0] == '+') {
		    mode = 1;
		    p++;
		  } else if (token[0] == '-') {
		    mode = -1;
		    p++;
		  }
		  if (!strcmp(p, "all")) {
		    mask = DEFAULT_BEHAVIOR_ALL;
		  } else if (!strcmp(p, "bye")) {
		    mask = DEFAULT_BEHAVIOR_BYE;
		  } else if (!strcmp(p, "abortunexp")) {
		    mask = DEFAULT_BEHAVIOR_ABORTUNEXP;
		  } else if (!strcmp(p, "pingreply")) {
		    mask = DEFAULT_BEHAVIOR_PINGREPLY;
		  } else {
		    ERROR("Unknown default behavior: '%s'\n", token);
		  }
		  switch(mode) {
		    case 0:
		      *ptr = mask;
		      break;
		    case 1:
		      *ptr |= mask;
		      break;
		    case -1:
		      *ptr &= ~mask;
		      break;
		    default:
		     assert(0);
		  }
		}
		token = NULL;
	    }
	    fprintf(stderr, "Defaults: %lu\n", *ptr);
	  }
	  break;
	default:
	  ERROR("Internal error: I don't recognize the option type for %s\n", argv[argi]);
      }
    }
  }

  if((extendedTwinSippMode && !slave_masterSet) || (!extendedTwinSippMode && slave_masterSet)){
    ERROR("-slave_cfg option must be used with -slave or -master option\n");
  }

  if (peripsocket) {
    if (!ip_file) {
      ERROR("You must use the -inf option when using -t ui.\n"
               "Use 'sipp -h' for details");
    }
  }

  if (ringbuffer_size && max_log_size) {
    ERROR("Ring Buffer options and maximum log size are mutually exclusive.");
  }

  if (global_lost) {
    lose_packets = 1;
  }

  /* trace file setting */
  if (scenario_file == NULL) {
    scenario_file = new char [ 5 ] ;
    sprintf(scenario_file, "%s", "sipp");
  } else {
    scenario_file = remove_pattern (scenario_file, (char*)".xml");
  }

   screen_init(print_last_stats);

#ifdef _USE_OPENSSL
    if ((transport == T_TLS) && (FI_init_ssl_context() != SSL_INIT_NORMAL))
    {
      ERROR("FI_init_ssl_context() failed");
    }
#endif

  if (useMessagef == 1) {
    rotate_messagef();
  }
  
  if (useShortMessagef == 1) {
    rotate_shortmessagef();
  }
  
  if (useScreenf == 1) {
    char L_file_name [MAX_PATH];
    sprintf (L_file_name, "%s_%d_screen.log", scenario_file, getpid());
    screenf = fopen(L_file_name, "w");
    if(!screenf) {
      ERROR("Unable to create '%s'", L_file_name);
    }
  }  

   // TODO: finish the -trace_timeout option implementation    

 /* if (useTimeoutf == 1) {
    char L_file_name [MAX_PATH];
    sprintf (L_file_name, "%s_%d_timeout.log", scenario_file, getpid());
    timeoutf = fopen(L_file_name, "w");
    if(!timeoutf) {
      ERROR("Unable to create '%s'", L_file_name);
    }
  } */

  if (useCountf == 1) {
    char L_file_name [MAX_PATH];
    sprintf (L_file_name, "%s_%d_counts.csv", scenario_file, getpid());
    countf = fopen(L_file_name, "w");
    if(!countf) {
      ERROR("Unable to create '%s'", L_file_name);
    }
    print_count_file(countf, 1);
  }

  if (useLogf == 1) {
    rotate_logfile();
  }

  if (dumpInRtt == 1) {
     main_scenario->stats->initRtt((char*)scenario_file, (char*)".csv",
                                report_freq_dumpRtt);
  }

  if ((maxSocketPresent) && (max_multi_socket > FD_SETSIZE) ) {
     L_maxSocketPresent = 1;
  }

  /* Initialization:  boost open file limit to the max (AgM)*/
  if (!skip_rlimit) {
    struct rlimit rlimit;

    if (getrlimit (RLIMIT_NOFILE, &rlimit) < 0) {
      ERROR_NO("getrlimit error");
    }

    if (rlimit.rlim_max >
#ifndef __CYGWIN
       ((L_maxSocketPresent) ?  max_multi_socket : FD_SETSIZE)
#else
       FD_SETSIZE
#endif
       ) {
      fprintf (stderr, "Warning: open file limit > FD_SETSIZE; "
               "limiting max. # of open files to FD_SETSIZE = %d\n",
               FD_SETSIZE);

      rlimit.rlim_max =
#ifndef __CYGWIN
          (L_maxSocketPresent) ?  max_multi_socket+min_socket : FD_SETSIZE ;
#else

	  FD_SETSIZE;
#endif
    }
    
    rlimit.rlim_cur = rlimit.rlim_max;
    if (setrlimit (RLIMIT_NOFILE, &rlimit) < 0) {
      ERROR("Unable to increase the open file limit to FD_SETSIZE = %d",
               FD_SETSIZE);
    }
  }
  
  /* Load default scenario in case nothing was loaded */
  if(!main_scenario) {
    main_scenario = new scenario(0, 0);
    main_scenario->stats->setFileName((char*)"uac", (char*)".csv");
    sprintf(scenario_file,"uac");
  }
  if(!ooc_scenario) {
    ooc_scenario = new scenario(0, find_scenario("ooc_default"));
    ooc_scenario->stats->setFileName((char*)"ooc_default", (char*)".csv");
  }
  display_scenario = main_scenario;

  init_default_messages();
  for (int i = 1; i <= users; i++) {
    freeUsers.push_back(i);
    userVarMap[i] = new VariableTable(userVariables);
  }

  if(argiFileName) {
    main_scenario->stats->setFileName(argv[argiFileName]);
  }

  /* In which mode the tool is launched ? */
  main_scenario->computeSippMode();

  /* checking if we need to launch the tool in background mode */ 
  if(backgroundMode == true)
    {
      pid_t l_pid;
      switch(l_pid = fork())
        {
        case -1:
          // error when forking !
          ERROR_NO("Forking error");
          exit(EXIT_FATAL_ERROR);
        case 0:
          // child process - poursuing the execution
	  // close all of our file descriptors
	  {
	    int nullfd = open("/dev/null", O_RDWR);

	    dup2(nullfd, fileno(stdin));
	    dup2(nullfd, fileno(stdout));
	    dup2(nullfd, fileno(stderr));

	    close(nullfd);
	  }
          break;
        default:
          // parent process - killing the parent - the child get the parent pid
          printf("Background mode - PID=[%d]\n", l_pid);
          exit(EXIT_OTHER);
        }
    }
	 
  /* Setting the rate and its dependant params (open_calls_allowed) */
  set_rate(rate);
	 
  if (toolMode == MODE_SERVER) {
    reset_number = 0;
  }
   
  open_connections();
   
   
  /* Defaults for media sockets */
  if (media_ip[0] == '\0') {
      strcpy(media_ip, local_ip);
    }
  if (media_ip_escaped[0] == '\0') {
    strcpy(media_ip_escaped, local_ip);
  }
  if (local_ip_is_ipv6) {
    media_ip_is_ipv6 = true;
  } else {
    media_ip_is_ipv6 = false;
  }

  /* Always create and Bind RTP socket */
  /* to avoid ICMP                     */
  if (1) {
    /* retrieve RTP local addr */
    struct addrinfo   hints;
    struct addrinfo * local_addr;

    memset((char*)&hints, 0, sizeof(hints));
    hints.ai_flags  = AI_PASSIVE;
    hints.ai_family = PF_UNSPEC;

    /* Resolving local IP */
    if (getaddrinfo(media_ip,
                    NULL,
                    &hints,
                    &local_addr) != 0) {
      ERROR("Unknown RTP address '%s'.\n"
               "Use 'sipp -h' for details", media_ip);
    }

    memcpy(&media_sockaddr,
           local_addr->ai_addr,
           SOCK_ADDR_SIZE(
             _RCAST(struct sockaddr_storage *,local_addr->ai_addr)));
    freeaddrinfo(local_addr);

    if((media_socket = socket(media_ip_is_ipv6 ? AF_INET6 : AF_INET,
                              SOCK_DGRAM, 0)) == -1) {
      char msg[512];
      sprintf(msg, "Unable to get the audio RTP socket (IP=%s, port=%d)", media_ip, media_port);
      ERROR_NO(msg);
    }
    /* create a second socket for video */
    if((media_socket_video = socket(media_ip_is_ipv6 ? AF_INET6 : AF_INET,
                                    SOCK_DGRAM, 0)) == -1) {
      char msg[512];
      sprintf(msg, "Unable to get the video RTP socket (IP=%s, port=%d)", media_ip, media_port+2);
      ERROR_NO(msg);
    }

    int try_counter;
    int max_tries = user_media_port ? 1 : 100;
    media_port = user_media_port ? user_media_port : DEFAULT_MEDIA_PORT;
    for (try_counter = 0; try_counter < max_tries; try_counter++) {

      if (media_sockaddr.ss_family == AF_INET) {
	(_RCAST(struct sockaddr_in *,&media_sockaddr))->sin_port =
	  htons((short)media_port);
      } else {
	(_RCAST(struct sockaddr_in6 *,&media_sockaddr))->sin6_port =
	  htons((short)media_port);
	media_ip_is_ipv6 = true;
      }
      strcpy(media_ip_escaped, media_ip);

      if(bind(media_socket,
	    (sockaddr *)(void *)&media_sockaddr,
	    SOCK_ADDR_SIZE(&media_sockaddr)) == 0) {
	break;
      }

      media_port++;
    }

    if (try_counter >= max_tries) {
      char msg[512];
      sprintf(msg, "Unable to bind audio RTP socket (IP=%s, port=%d)", media_ip, media_port);
      ERROR_NO(msg);
    }

    /*---------------------------------------------------------
       Bind the second socket to media_port+2 
       (+1 is reserved for RTCP) 
    ----------------------------------------------------------*/

    if (media_sockaddr.ss_family == AF_INET) {
     (_RCAST(struct sockaddr_in *,&media_sockaddr))->sin_port =
       htons((short)media_port+2);
     strcpy(media_ip_escaped, media_ip);
    } else {
      (_RCAST(struct sockaddr_in6 *,&media_sockaddr))->sin6_port =
        htons((short)media_port+2);
      media_ip_is_ipv6 = true;
      strcpy(media_ip_escaped, media_ip);
    }

    if(bind(media_socket_video, 
            (sockaddr *)(void *)&media_sockaddr,
            SOCK_ADDR_SIZE(&media_sockaddr))) {
      char msg[512];
      sprintf(msg, "Unable to bind video RTP socket (IP=%s, port=%d)", media_ip, media_port+2);
      ERROR_NO(msg);
    }
    /* Second socket bound */
  }

  /* Creating the remote control socket thread */
  setup_ctrl_socket();
  if (!nostdin) {
    setup_stdin_socket();
  }

  if ((media_socket > 0) && (rtp_echo_enabled)) {
    if (pthread_create
        (&pthread2_id,
         NULL,
         (void *(*)(void *)) rtp_echo_thread,
         (void*)&media_socket) 
        == -1) {
      ERROR_NO("Unable to create RTP echo thread");
    }
  }


  /* Creating second RTP echo thread for video */
  if ((media_socket_video > 0) && (rtp_echo_enabled)) {
    if (pthread_create
        (&pthread3_id,
         NULL,
         (void *(*)(void *)) rtp_echo_thread,
         (void*)&media_socket_video) 
        == -1) {
      ERROR_NO("Unable to create second RTP echo thread");
      }
    } 

  traffic_thread();

  if (scenario_file != NULL) {
    delete [] scenario_file ;
    scenario_file = NULL ;
  }

}

void sipp_usleep(unsigned long usec) {
	if (usec >= 1000000) {
		sleep(usec / 1000000);
	}
	usec %= 1000000;
	usleep(usec);
}

bool reconnect_allowed() {
  if (reset_number == -1) {
    return true;
  }
  return (reset_number > 0);
}

void reset_connection(struct sipp_socket *socket) {
  if (!reconnect_allowed()) {
      ERROR_NO("Max number of reconnections reached");
    }

  if (reset_number != -1) {
	reset_number--;
  }

  if (reset_close) {
    WARNING("Closing calls, because of TCP reset or close!");
    close_calls(socket);
  }

  /* Sleep for some period of time before the reconnection. */
  usleep(1000 * reset_sleep);

  if (sipp_reconnect_socket(socket) < 0) {
    WARNING_NO("Could not reconnect TCP socket");
    close_calls(socket);
  } else {
    WARNING("Socket required a reconnection.");
  }
}

/* Close just those calls for a given socket (e.g., if the remote end closes
 * the connection. */
void close_calls(struct sipp_socket *socket) {
  owner_list *owners = get_owners_for_socket(socket);
  owner_list::iterator owner_it;
  socketowner *owner_ptr = NULL;

  for (owner_it = owners->begin(); owner_it != owners->end(); owner_it++) {
    owner_ptr = *owner_it;
    if(owner_ptr) {
      owner_ptr->tcpClose();
    }
  }

  delete owners;
}

int open_connections() {
  int status=0;
  local_port = 0;
  
  if(!strlen(remote_host)) {
    if((toolMode != MODE_SERVER)) {
      ERROR("Missing remote host parameter. This scenario requires it");
    }
  } else {
    int temp_remote_port;
    get_host_and_port(remote_host, remote_host, &temp_remote_port);
    if (temp_remote_port != 0) {
      remote_port = temp_remote_port;
    }
 
    /* Resolving the remote IP */
    {
      struct addrinfo   hints;
      struct addrinfo * local_addr;

      fprintf(stderr,"Resolving remote host '%s'... ", remote_host);

      memset((char*)&hints, 0, sizeof(hints));
      hints.ai_flags  = AI_PASSIVE;
      hints.ai_family = PF_UNSPEC;

      /* FIXME: add DNS SRV support using liburli? */
      if (getaddrinfo(remote_host,
                      NULL,
                      &hints,
                      &local_addr) != 0) {
        ERROR("Unknown remote host '%s'.\n"
                 "Use 'sipp -h' for details", remote_host);
      }

      memset(&remote_sockaddr, 0, sizeof( remote_sockaddr ));
      memcpy(&remote_sockaddr,
             local_addr->ai_addr,
             SOCK_ADDR_SIZE(
               _RCAST(struct sockaddr_storage *,local_addr->ai_addr)));

      freeaddrinfo(local_addr);

      strcpy(remote_ip, get_inet_address(&remote_sockaddr));
      if (remote_sockaddr.ss_family == AF_INET) {
        (_RCAST(struct sockaddr_in *, &remote_sockaddr))->sin_port =
          htons((short)remote_port);
        strcpy(remote_ip_escaped, remote_ip); 
      } else {
        (_RCAST(struct sockaddr_in6 *, &remote_sockaddr))->sin6_port =
          htons((short)remote_port);
        sprintf(remote_ip_escaped, "[%s]", remote_ip); 
      }
      fprintf(stderr,"Done.\n");
    }
   }

  if(gethostname(hostname,64) != 0) {
    ERROR_NO("Can't get local hostname in 'gethostname(hostname,64)'");
  }
  
  {
    char            * local_host = NULL;
    struct addrinfo * local_addr;
    struct addrinfo   hints;

    if (!strlen(local_ip)) {
      local_host = (char *)hostname;
    } else {
      local_host = (char *)local_ip;
    }

    memset((char*)&hints, 0, sizeof(hints));
    hints.ai_flags  = AI_PASSIVE;
    hints.ai_family = PF_UNSPEC;

    /* Resolving local IP */
    if (getaddrinfo(local_host, NULL, &hints, &local_addr) != 0) {
      ERROR("Can't get local IP address in getaddrinfo, local_host='%s', local_ip='%s'",
	  local_host,
	  local_ip);
    }
    // store local addr info for rsa option
    getaddrinfo(local_host, NULL, &hints, &local_addr_storage);

    memset(&local_sockaddr,0,sizeof(struct sockaddr_storage));
    local_sockaddr.ss_family = local_addr->ai_addr->sa_family;

    if (!strlen(local_ip)) {
      strcpy(local_ip,
	  get_inet_address(
	    _RCAST(struct sockaddr_storage *, local_addr->ai_addr)));
    } else {
      if (!(local_sockaddr.ss_family == AF_INET6)) {
	memcpy(&local_sockaddr,
	    local_addr->ai_addr,
	    SOCK_ADDR_SIZE(
	      _RCAST(struct sockaddr_storage *,local_addr->ai_addr)));
      }
    }
    freeaddrinfo(local_addr);

    if (local_sockaddr.ss_family == AF_INET6) {
      local_ip_is_ipv6 = true;
      sprintf(local_ip_escaped, "[%s]", local_ip);
    } else {
      strcpy(local_ip_escaped, local_ip);
    }
  }

  /* Creating and binding the local socket */
  if ((main_socket = new_sipp_socket(local_ip_is_ipv6, transport)) == NULL) {
    ERROR_NO("Unable to get the local socket");
  }

  sipp_customize_socket(main_socket);

  /* Trying to bind local port */
  char peripaddr[256];
  if(!user_port) {
    unsigned short l_port;
    for(l_port = DEFAULT_PORT;
        l_port < (DEFAULT_PORT + 60);
        l_port++) {

      // Bind socket to local_ip
      if (bind_local || peripsocket) {
	struct addrinfo * local_addr;
	struct addrinfo   hints;
	memset((char*)&hints, 0, sizeof(hints));
	hints.ai_flags  = AI_PASSIVE;
	hints.ai_family = PF_UNSPEC;

	if (peripsocket) {
	  // On some machines it fails to bind to the self computed local
	  // IP address.
	  // For the socket per IP mode, bind the main socket to the
	  // first IP address specified in the inject file.
	  inFiles[ip_file]->getField(0, peripfield, peripaddr, sizeof(peripaddr));
	  if (getaddrinfo(peripaddr,
		NULL,
		&hints,
		&local_addr) != 0) {
	    ERROR("Unknown host '%s'.\n"
		"Use 'sipp -h' for details", peripaddr);
	  }
	} else {
	  if (getaddrinfo(local_ip,
		NULL,
		&hints,
		&local_addr) != 0) {
	    ERROR("Unknown host '%s'.\n"
		"Use 'sipp -h' for details", peripaddr);
	  }
	}
	memcpy(&local_sockaddr,
	    local_addr->ai_addr,
	    SOCK_ADDR_SIZE(
	      _RCAST(struct sockaddr_storage *, local_addr->ai_addr)));
	freeaddrinfo(local_addr);
      }
      if (local_ip_is_ipv6) {
	(_RCAST(struct sockaddr_in6 *, &local_sockaddr))->sin6_port
	  = htons((short)l_port);
      } else {
	(_RCAST(struct sockaddr_in *, &local_sockaddr))->sin_port
	  = htons((short)l_port);
      }
      if(sipp_bind_socket(main_socket, &local_sockaddr, &local_port) == 0) {
	break;
      }
    }
  }

  if(!local_port) {
    /* Not already binded, use user_port of 0 to leave
     * the system choose a port. */

    if (bind_local || peripsocket) {
      struct addrinfo * local_addr;
      struct addrinfo   hints;
      memset((char*)&hints, 0, sizeof(hints));
      hints.ai_flags  = AI_PASSIVE;
      hints.ai_family = PF_UNSPEC;
       
      if (peripsocket) {
        // On some machines it fails to bind to the self computed local
        // IP address.
        // For the socket per IP mode, bind the main socket to the
        // first IP address specified in the inject file.
	inFiles[ip_file]->getField(0, peripfield, peripaddr, sizeof(peripaddr));
        if (getaddrinfo(peripaddr,
                         NULL,
                         &hints,
                         &local_addr) != 0) {
           ERROR("Unknown host '%s'.\n"
                    "Use 'sipp -h' for details", peripaddr);
        }
      } else {
        if (getaddrinfo(local_ip,
                        NULL,
                        &hints,
                        &local_addr) != 0) {
           ERROR("Unknown host '%s'.\n"
                   "Use 'sipp -h' for details", peripaddr);
        }
      }
      memcpy(&local_sockaddr,
             local_addr->ai_addr,
             SOCK_ADDR_SIZE(
               _RCAST(struct sockaddr_storage *, local_addr->ai_addr)));
      freeaddrinfo(local_addr);
    }

    if (local_ip_is_ipv6) {
      (_RCAST(struct sockaddr_in6 *, &local_sockaddr))->sin6_port
          = htons((short)user_port);        
    } else {
      (_RCAST(struct sockaddr_in *, &local_sockaddr))->sin_port
          = htons((short)user_port); 
    }
    if(sipp_bind_socket(main_socket, &local_sockaddr, &local_port)) {
      ERROR_NO("Unable to bind main socket");
    }
  }

  if (peripsocket) {
    // Add the main socket to the socket per subscriber map
    map_perip_fd[peripaddr] = main_socket;
  }

  // Create additional server sockets when running in socket per
  // IP address mode.
  if (peripsocket && toolMode == MODE_SERVER) {
    struct sockaddr_storage server_sockaddr;
    struct addrinfo * local_addr;
    struct addrinfo   hints;
    memset((char*)&hints, 0, sizeof(hints));
    hints.ai_flags  = AI_PASSIVE;
    hints.ai_family = PF_UNSPEC;

    char peripaddr[256];
    struct sipp_socket *sock;
    unsigned int lines = inFiles[ip_file]->numLines();
    for (unsigned int i = 0; i < lines; i++) {
      inFiles[ip_file]->getField(i, peripfield, peripaddr, sizeof(peripaddr));
      map<string, struct sipp_socket *>::iterator j;
      j = map_perip_fd.find(peripaddr);

      if (j == map_perip_fd.end()) {
        if((sock = new_sipp_socket(is_ipv6, transport)) == NULL) {
          ERROR_NO("Unable to get server socket");
        }

        if (getaddrinfo(peripaddr,
                        NULL,
                        &hints,
                        &local_addr) != 0) {
            ERROR("Unknown remote host '%s'.\n"
                     "Use 'sipp -h' for details", peripaddr);
          }

        memcpy(&server_sockaddr,
              local_addr->ai_addr,
              SOCK_ADDR_SIZE(
                 _RCAST(struct sockaddr_storage *, local_addr->ai_addr)));
        freeaddrinfo(local_addr);

        if (is_ipv6) {
          (_RCAST(struct sockaddr_in6 *, &server_sockaddr))->sin6_port
              = htons((short)local_port);
        } else {
          (_RCAST(struct sockaddr_in *, &server_sockaddr))->sin_port
              = htons((short)local_port);
        }

        sipp_customize_socket(sock);
        if(sipp_bind_socket(sock, &server_sockaddr, NULL)) {
          ERROR_NO("Unable to bind server socket");
        }

        map_perip_fd[peripaddr] = sock;
      }
    }
  }

  if((!multisocket) && (transport == T_TCP || transport == T_TLS) &&
   (toolMode != MODE_SERVER)) {
    if((tcp_multiplex = new_sipp_socket(local_ip_is_ipv6, transport)) == NULL) {
      ERROR_NO("Unable to get a TCP socket");
    }

    /* OJA FIXME: is it correct? */
    if (use_remote_sending_addr) {
        remote_sockaddr = remote_sending_sockaddr ;
    }

    if(sipp_connect_socket(tcp_multiplex, &remote_sockaddr)) {
      if(reset_number >0){
	      WARNING("Failed to reconnect\n");
	      sipp_close_socket(main_socket);
	      reset_number--;
	      return 1;
	   }else{
      if(errno == EINVAL){
        /* This occurs sometime on HPUX but is not a true INVAL */
        ERROR_NO("Unable to connect a TCP socket, remote peer error.\n"
              "Use 'sipp -h' for details");
      } else {
        ERROR_NO("Unable to connect a TCP socket.\n"
                 "Use 'sipp -h' for details");
      }
    }
    }

    sipp_customize_socket(tcp_multiplex);
  }


  if(transport == T_TCP || transport == T_TLS) {
    if(listen(main_socket->ss_fd, 100)) {
      ERROR_NO("Unable to listen main socket");
    }
  }

  /* Trying to connect to Twin Sipp in 3PCC mode */
  if(twinSippMode) {
    if(toolMode == MODE_3PCC_CONTROLLER_A || toolMode == MODE_3PCC_A_PASSIVE) {
       connect_to_peer(twinSippHost, twinSippPort, &twinSipp_sockaddr, twinSippIp, &twinSippSocket);
     }else if(toolMode == MODE_3PCC_CONTROLLER_B){
       connect_local_twin_socket(twinSippHost);
      }else{
       ERROR("TwinSipp Mode enabled but toolMode is different "
              "from 3PCC_CONTROLLER_B and 3PCC_CONTROLLER_A\n");
      }
   }else if (extendedTwinSippMode){       
     if (toolMode == MODE_MASTER || toolMode == MODE_MASTER_PASSIVE) {
       strcpy(twinSippHost,get_peer_addr(master_name));
       get_host_and_port(twinSippHost, twinSippHost, &twinSippPort);
       connect_local_twin_socket(twinSippHost);
       connect_to_all_peers();
     }else if(toolMode == MODE_SLAVE) {
       strcpy(twinSippHost,get_peer_addr(slave_number));
       get_host_and_port(twinSippHost, twinSippHost, &twinSippPort);
       connect_local_twin_socket(twinSippHost);
     }else{
        ERROR("extendedTwinSipp Mode enabled but toolMode is different "
              "from MASTER and SLAVE\n");
     }
    }

  return status;
            }


void connect_to_peer(char *peer_host, int peer_port, struct sockaddr_storage *peer_sockaddr, char *peer_ip, struct sipp_socket **peer_socket) {

          /* Resolving the  peer IP */
      printf("Resolving peer address : %s...\n",peer_host);
      struct addrinfo   hints;
      struct addrinfo * local_addr;
      memset((char*)&hints, 0, sizeof(hints));
      hints.ai_flags  = AI_PASSIVE;
      hints.ai_family = PF_UNSPEC;
      is_ipv6 = false;
      /* Resolving twin IP */
      if (getaddrinfo(peer_host,
                      NULL,
                      &hints,
                      &local_addr) != 0) {

ERROR("Unknown peer host '%s'.\n"
                       "Use 'sipp -h' for details", peer_host);
            }

      memcpy(peer_sockaddr,
             local_addr->ai_addr,
             SOCK_ADDR_SIZE(
               _RCAST(struct sockaddr_storage *,local_addr->ai_addr)));

      freeaddrinfo(local_addr);

      if (peer_sockaddr->ss_family == AF_INET) {
       (_RCAST(struct sockaddr_in *,peer_sockaddr))->sin_port =
         htons((short)peer_port);
      } else {
        (_RCAST(struct sockaddr_in6 *,peer_sockaddr))->sin6_port =
          htons((short)peer_port);
        is_ipv6 = true;
      }
      strcpy(peer_ip, get_inet_address(peer_sockaddr));
      if((*peer_socket = new_sipp_socket(is_ipv6, T_TCP)) == NULL) {
	ERROR_NO("Unable to get a twin sipp TCP socket");
      }

      /* Mark this as a control socket. */
      (*peer_socket)->ss_control = 1;

      if(sipp_connect_socket(*peer_socket, peer_sockaddr)) {
	if(errno == EINVAL) {
	  /* This occurs sometime on HPUX but is not a true INVAL */
	  ERROR_NO("Unable to connect a twin sipp TCP socket\n "
	      ", remote peer error.\n"
	      "Use 'sipp -h' for details");
	} else {
	  ERROR_NO("Unable to connect a twin sipp socket "
	      "\n"
	      "Use 'sipp -h' for details");
	}
      }

      sipp_customize_socket(*peer_socket);
}

struct sipp_socket **get_peer_socket(char * peer)
{
    struct sipp_socket **peer_socket;
    T_peer_infos infos;
    peer_map::iterator peer_it;
    peer_it = peers.find(peer_map::key_type(peer));
    if(peer_it != peers.end()) {
      infos = peer_it->second;
      peer_socket = &(infos.peer_socket);
      return peer_socket;
     }
     else {
       ERROR("get_peer_socket: Peer %s not found\n", peer);
    }
   return NULL;
}

char * get_peer_addr(char * peer)
{
    char * addr;
    peer_addr_map::iterator peer_addr_it;
    peer_addr_it = peer_addrs.find(peer_addr_map::key_type(peer)); 
    if(peer_addr_it != peer_addrs.end()){
       addr =  peer_addr_it->second;
       return addr;
       }
     else{
       ERROR("get_peer_addr: Peer %s not found\n", peer);
       }
   return NULL;
}

bool is_a_peer_socket(struct sipp_socket *peer_socket)
{
    peer_socket_map::iterator peer_socket_it;
    peer_socket_it = peer_sockets.find(peer_socket_map::key_type(peer_socket));
    if(peer_socket_it == peer_sockets.end()){
       return false;
      }else{
       return true;
      }
}

void connect_local_twin_socket(char * twinSippHost)
{
          /* Resolving the listener IP */
            printf("Resolving listener address : %s...\n", twinSippHost);
            struct addrinfo   hints;
            struct addrinfo * local_addr;
            memset((char*)&hints, 0, sizeof(hints));
            hints.ai_flags  = AI_PASSIVE;
            hints.ai_family = PF_UNSPEC;
            is_ipv6 = false;

            /* Resolving twin IP */
            if (getaddrinfo(twinSippHost,
                           NULL,
                           &hints,
                           &local_addr) != 0) {
               ERROR("Unknown twin host '%s'.\n"
                        "Use 'sipp -h' for details", twinSippHost);
                }
             memcpy(&twinSipp_sockaddr,
                    local_addr->ai_addr,
                    SOCK_ADDR_SIZE(
                      _RCAST(struct sockaddr_storage *,local_addr->ai_addr)));

             if (twinSipp_sockaddr.ss_family == AF_INET) {
              (_RCAST(struct sockaddr_in *,&twinSipp_sockaddr))->sin_port =
                htons((short)twinSippPort);
             } else {
               (_RCAST(struct sockaddr_in6 *,&twinSipp_sockaddr))->sin6_port =
                 htons((short)twinSippPort);
               is_ipv6 = true;
             }
             strcpy(twinSippIp, get_inet_address(&twinSipp_sockaddr));

	     if((localTwinSippSocket = new_sipp_socket(is_ipv6, T_TCP)) == NULL) {
	       ERROR_NO("Unable to get a listener TCP socket ");
	     }

           memset(&localTwin_sockaddr, 0, sizeof(struct sockaddr_storage));
           if (!is_ipv6) {
               localTwin_sockaddr.ss_family = AF_INET;
            (_RCAST(struct sockaddr_in *,&localTwin_sockaddr))->sin_port =
             htons((short)twinSippPort);
           } else {
             localTwin_sockaddr.ss_family = AF_INET6;
             (_RCAST(struct sockaddr_in6 *,&localTwin_sockaddr))->sin6_port =
               htons((short)twinSippPort);
           }

           // add socket option to allow the use of it without the TCP timeout
           // This allows to re-start the controller B (or slave) without timeout after its exit
           int reuse = 1;
           setsockopt(localTwinSippSocket->ss_fd,SOL_SOCKET,SO_REUSEADDR,(int *)&reuse,sizeof(reuse));
           sipp_customize_socket(localTwinSippSocket);

	   if(sipp_bind_socket(localTwinSippSocket, &localTwin_sockaddr, 0)) {
	     ERROR_NO("Unable to bind twin sipp socket ");
	   }

	   if(listen(localTwinSippSocket->ss_fd, 100)) {
	     ERROR_NO("Unable to listen twin sipp socket in ");
	   }
}

void close_peer_sockets()
{
 peer_map::iterator peer_it;
 T_peer_infos infos;

 for(peer_it = peers.begin(); peer_it != peers.end(); peer_it++){
     infos = peer_it->second;
     sipp_close_socket(infos.peer_socket);
     infos.peer_socket = NULL ;
     peers[std::string(peer_it->first)] = infos;
 }

 peers_connected = 0;
}

void close_local_sockets(){
   for (int i = 0; i< local_nb; i++){
     sipp_close_socket(local_sockets[i]);
     local_sockets[i] = NULL;
   }
}

void connect_to_all_peers(){
     peer_map::iterator peer_it;
     T_peer_infos infos;
     for (peer_it = peers.begin(); peer_it != peers.end(); peer_it++){
         infos = peer_it->second;
         get_host_and_port(infos.peer_host, infos.peer_host, &infos.peer_port);
         connect_to_peer(infos.peer_host, infos.peer_port,&(infos.peer_sockaddr), infos.peer_ip, &(infos.peer_socket));
         peer_sockets[infos.peer_socket] = peer_it->first;
         peers[std::string(peer_it->first)] = infos;
     }
     peers_connected = 1;
}

bool is_a_local_socket(struct sipp_socket *s){
  for (int i = 0; i< local_nb + 1; i++){
    if(local_sockets[i] == s) return true;
  }
  return (false);
}

void free_peer_addr_map() {
  peer_addr_map::iterator peer_addr_it;
  for (peer_addr_it = peer_addrs.begin(); peer_addr_it != peer_addrs.end(); peer_addr_it++){
       free(peer_addr_it->second);
  }
}

#ifdef __cplusplus
extern "C" {
#endif
int TRACE_MSG(char *fmt, ...) {
  int ret = 0;
  static unsigned long long count = 0;
  if(messagef) {
    va_list ap;
    va_start(ap, fmt);
    ret = vfprintf(messagef, fmt, ap);
    va_end(ap);
    fflush(messagef);

    count += ret;

    if (max_log_size && count > max_log_size) {
      fclose(messagef);
      messagef = NULL;
    }

    if (ringbuffer_size && count > ringbuffer_size) {
      rotate_messagef();
      count = 0;
    }
  }
  return ret;
}

int TRACE_SHORTMSG(char *fmt, ...) {
  int ret = 0;
  static unsigned long long count = 0;
  if(shortmessagef) {
    va_list ap;
    va_start(ap, fmt);
    ret = vfprintf(shortmessagef, fmt, ap);
    va_end(ap);
    fflush(shortmessagef);

    count += ret;

    if (max_log_size && count > max_log_size) {
      fclose(shortmessagef);
      shortmessagef = NULL;
    }

    if (ringbuffer_size && count > ringbuffer_size) {
      rotate_shortmessagef();
      count = 0;
    }
  }
  return ret;
}

int LOG_MSG(char *fmt, ...) {
  int ret = 0;
  static unsigned long long count = 0;
  if(logfile) {
    va_list ap;
    va_start(ap, fmt);
    ret = vfprintf(logfile, fmt, ap);
    va_end(ap);
    fflush(logfile);

    count += ret;

    if (max_log_size && count > max_log_size) {
      fclose(logfile);
      logfile = NULL;
    }

    if (ringbuffer_size && count > ringbuffer_size) {
      rotate_messagef();
      count = 0;
    }
  }
  return ret;
}

// TODO: finish the -trace_timeout option implementation
/* int TRACE_TIMEOUT(char *fmt, ...) */

#ifdef __cplusplus
}
#endif

struct logfile_id {
  time_t start;
  int n;
};

/* We can not use the error functions from this file, as we may be rotating the error log itself! */
void rotatef(char *name, FILE **fptr, time_t *starttime, int *nfiles, struct logfile_id **ftimes, bool check, bool *overwrite) {
  char L_file_name [MAX_PATH];
  char L_rotate_file_name [MAX_PATH];

  sprintf (L_file_name, "%s_%d_%s.log", scenario_file, getpid(), name);

  if (ringbuffer_files > 0) {
    if (!*ftimes) {
	*ftimes = (struct logfile_id *)calloc(ringbuffer_files, sizeof(struct logfile_id));
    }
    /* We need to rotate away an existing file. */
    if (*nfiles == ringbuffer_files) {
      if ((*ftimes)[0].n) {
	sprintf(L_rotate_file_name, "%s_%d_%s_%d.%d.log", scenario_file, getpid(), name, (*ftimes)[0].start, (*ftimes)[0].n);
      } else {
	sprintf(L_rotate_file_name, "%s_%d_%s_%d.log", scenario_file, getpid(), name, (*ftimes)[0].start);
      }
      unlink(L_rotate_file_name);
      (*nfiles)--;
      memmove(*ftimes, &((*ftimes)[1]), sizeof(struct logfile_id) * (*nfiles));
    }
    if (*starttime) {
      (*ftimes)[*nfiles].start = *starttime;
      (*ftimes)[*nfiles].n = 0;
      /* If we have the same time, then we need to append an identifier. */
      if (*nfiles && ((*ftimes)[*nfiles].start == (*ftimes)[*nfiles - 1].start)) {
	  (*ftimes)[*nfiles].n = (*ftimes)[*nfiles - 1].n + 1;
      }
      if ((*ftimes)[*nfiles].n) {
	sprintf(L_rotate_file_name, "%s_%d_%s_%d.%d.log", scenario_file, getpid(), name, (*ftimes)[*nfiles].start, (*ftimes)[*nfiles].n);
      } else {
	sprintf(L_rotate_file_name, "%s_%d_%s_%d.log", scenario_file, getpid(), name, (*ftimes)[*nfiles].start);
      }
      (*nfiles)++;
      fflush(*fptr);
      fclose(*fptr);
      *fptr = NULL;
      rename(L_file_name, L_rotate_file_name);
    }
  }

  time(starttime);
  if (*overwrite) {
    *fptr = fopen(L_file_name, "w");
  } else {
    *fptr = fopen(L_file_name, "a");
    *overwrite = true;
  }
  if(check && !*fptr) {
    ERROR("Unable to create '%s'", L_file_name);
  }
}

int messagef_nfiles = 0;
struct logfile_id *messagef_times = NULL;

void rotate_messagef() {
  static time_t starttime = 0;
  rotatef("messages", &messagef, &starttime, &messagef_nfiles, &messagef_times, true, &messagef_overwrite);
}

int shortmessagef_nfiles = 0;
struct logfile_id *shortmessagef_times = NULL;

void rotate_shortmessagef() {
  static time_t starttime = 0;
  rotatef("shortmessages", &shortmessagef, &starttime, &shortmessagef_nfiles, &shortmessagef_times, true, &shortmessagef_overwrite);
}

int logfile_nfiles = 0;
struct logfile_id *logfile_times = NULL;

void rotate_logfile() {
  static time_t starttime = 0;
  rotatef("logs", &logfile, &starttime, &logfile_nfiles, &logfile_times, true, &logfile_overwrite);
}

int errorf_nfiles  = 0;
struct logfile_id *errorf_times = NULL;

void rotate_errorf() {
  static time_t starttime = 0;
  rotatef("errors", &screen_errorf, &starttime, &errorf_nfiles, &errorf_times, false, &errorf_overwrite);
  /* If rotatef is changed, this must be changed as well. */
  sprintf (screen_logfile, "%s_%d_errors.log", scenario_file, getpid());
}

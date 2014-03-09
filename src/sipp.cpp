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
 *           Francois Draperi (for dynamic_id)
 *           From Hewlett Packard Company.
 *           F. Tarek Rogers
 *           Peter Higginson
 *           Vincent Luba
 *           Shriram Natarajan
 *           Guillaume Teissier from FTR&D
 *           Clement Chen
 *           Wolfgang Beck
 *           Charles P Wright from IBM Research
 *           Martin Van Leeuwen
 *           Andy Aicken
 *	     Michael Hirschbichler
 */

#define GLOBALS_FULL_DEFINITION
#define NOTLAST 0

#include <dlfcn.h>
#include "sipp.hpp"
#include "sip_parser.hpp"
#include "socket.hpp"
#include "logger.hpp"
#include "assert.h"

extern struct sipp_socket *ctrl_socket;
extern struct sipp_socket *stdin_socket;

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
#define SIPP_OPTION_VAR		  34
#define SIPP_OPTION_RTCHECK	  35
#define SIPP_OPTION_LFNAME	  36
#define SIPP_OPTION_LFOVERWRITE	  37
#define SIPP_OPTION_PLUGIN	  38
#define SIPP_OPTION_NEED_SCTP	  39
#define SIPP_HELP_TEXT_HEADER	  255

/* Put each option, its help text, and type in this table. */
struct sipp_option options_table[] = {
    {"h", NULL, SIPP_OPTION_HELP, NULL, 0},
    {"help", NULL, SIPP_OPTION_HELP, NULL, 0},

    {"", "Scenario file options:", SIPP_HELP_TEXT_HEADER, NULL, 0},
    {"sd", "Dumps a default scenario (embedded in the SIPp executable)", SIPP_OPTION_SCENARIO, NULL, 0},
    {"sf", "Loads an alternate XML scenario file.  To learn more about XML scenario syntax, use the -sd option to dump embedded scenarios. They contain all the necessary help.", SIPP_OPTION_SCENARIO, NULL, 2},
    {"oocsf", "Load out-of-call scenario.", SIPP_OPTION_OOC_SCENARIO, NULL, 2},
    {"oocsn", "Load out-of-call scenario.", SIPP_OPTION_OOC_SCENARIO, NULL, 2},
    {
        "sn", "Use a default scenario (embedded in the SIPp executable). If this option is omitted, the Standard SipStone UAC scenario is loaded.\n"
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
        "- '3pcc-B'   : B side.\n", SIPP_OPTION_SCENARIO, NULL, 2
    },

    {"", "IP, port and protocol options:", SIPP_HELP_TEXT_HEADER, NULL, 0},
        {
        "t", "Set the transport mode:\n"
        "- u1: UDP with one socket (default),\n"
        "- un: UDP with one socket per call,\n"
        "- ui: UDP with one socket per IP address. The IP addresses must be defined in the injection file.\n"
        "- t1: TCP with one socket,\n"
        "- tn: TCP with one socket per call,\n"
#ifdef _USE_OPENSSL
        "- l1: TLS with one socket,\n"
        "- ln: TLS with one socket per call,\n"
#endif
#ifdef USE_SCTP
        "- s1: SCTP with one socket,\n"
        "- sn: SCTP with one socket per call,\n"
#endif
        "- c1: u1 + compression (only if compression plugin loaded),\n"
        "- cn: un + compression (only if compression plugin loaded).  This plugin is not provided with SIPp.\n"
        , SIPP_OPTION_TRANSPORT, NULL, 1
    },
    {"i", "Set the local IP address for 'Contact:','Via:', and 'From:' headers. Default is primary host IP address.\n", SIPP_OPTION_IP, local_ip, 1},
    {"p", "Set the local port number.  Default is a random free port chosen by the system.", SIPP_OPTION_INT, &user_port, 1},
    {"bind_local", "Bind socket to local IP address, i.e. the local IP address is used as the source IP address.  If SIPp runs in server mode it will only listen on the local IP address instead of all IP addresses.", SIPP_OPTION_SETFLAG, &bind_local, 1},
    {"ci", "Set the local control IP address", SIPP_OPTION_IP, control_ip, 1},
    {"cp", "Set the local control port number. Default is 8888.", SIPP_OPTION_INT, &control_port, 1},
    {"max_socket", "Set the max number of sockets to open simultaneously. This option is significant if you use one socket per call. Once this limit is reached, traffic is distributed over the sockets already opened. Default value is 50000", SIPP_OPTION_MAX_SOCKET, NULL, 1},
    {"max_reconnect", "Set the the maximum number of reconnection.", SIPP_OPTION_INT, &reset_number, 1},
    {"reconnect_close", "Should calls be closed on reconnect?", SIPP_OPTION_BOOL, &reset_close, 1},
    {"reconnect_sleep", "How long (in milliseconds) to sleep between the close and reconnect?", SIPP_OPTION_TIME_MS, &reset_sleep, 1},
    {"rsa", "Set the remote sending address to host:port for sending the messages.", SIPP_OPTION_RSA, NULL, 1},

   #ifdef _USE_OPENSSL
    {"tls_cert", "Set the name for TLS Certificate file. Default is 'cacert.pem", SIPP_OPTION_STRING, &tls_cert_name, 1},
    {"tls_key", "Set the name for TLS Private Key file. Default is 'cakey.pem'", SIPP_OPTION_STRING, &tls_key_name, 1},
    {"tls_crl", "Set the name for Certificate Revocation List file. If not specified, X509 CRL is not activated.", SIPP_OPTION_STRING, &tls_crl_name, 1},
#else
    {"tls_cert", NULL, SIPP_OPTION_NEED_SSL, NULL, 1},
    {"tls_key", NULL, SIPP_OPTION_NEED_SSL, NULL, 1},
    {"tls_crl", NULL, SIPP_OPTION_NEED_SSL, NULL, 1},
#endif

#ifdef USE_SCTP
    {"multihome", "Set multihome address for SCTP", SIPP_OPTION_IP, multihome_ip, 1},
    {"heartbeat", "Set heartbeat interval in ms for SCTP", SIPP_OPTION_INT, &heartbeat, 1},
    {"assocmaxret", "Set association max retransmit counter for SCTP", SIPP_OPTION_INT, &assocmaxret, 1},
    {"pathmaxret", "Set path max retransmit counter for SCTP", SIPP_OPTION_INT, &pathmaxret, 1},
    {"pmtu", "Set path MTU for SCTP", SIPP_OPTION_INT, &pmtu, 1},
    {"gracefulclose", "If true, SCTP association will be closed with SHUTDOWN (default).\n If false, SCTP association will be closed by ABORT.\n", SIPP_OPTION_BOOL, &gracefulclose, 1},
#else
    {"multihome", NULL, SIPP_OPTION_NEED_SCTP, NULL, 1},
    {"heartbeat", NULL, SIPP_OPTION_NEED_SCTP, NULL, 1},
    {"assocmaxret", NULL, SIPP_OPTION_NEED_SCTP, NULL, 1},
    {"pathmaxret", NULL, SIPP_OPTION_NEED_SCTP, NULL, 1},
    {"pmtu", NULL, SIPP_OPTION_NEED_SCTP, NULL, 1},
    {"gracefulclose", NULL, SIPP_OPTION_NEED_SCTP, NULL, 1},
#endif


   {"", "SIPp overall behavior options:", SIPP_HELP_TEXT_HEADER, NULL, 0},
   {"v", "Display version and copyright information.", SIPP_OPTION_VERSION, NULL, 0},
   {"bg", "Launch SIPp in background mode.", SIPP_OPTION_SETFLAG, &backgroundMode, 1},
   {"nostdin", "Disable stdin.\n", SIPP_OPTION_SETFLAG, &nostdin, 1},
   {"plugin", "Load a plugin.", SIPP_OPTION_PLUGIN, NULL, 1},
   {"sleep", "How long to sleep for at startup. Default unit is seconds.", SIPP_OPTION_TIME_SEC, &sleeptime, 1},
   {"skip_rlimit", "Do not perform rlimit tuning of file descriptor limits.  Default: false.", SIPP_OPTION_SETFLAG, &skip_rlimit, 1},
   {"buff_size", "Set the send and receive buffer size.", SIPP_OPTION_INT, &buff_size, 1},
   {"sendbuffer_warn", "Produce warnings instead of errors on SendBuffer failures.", SIPP_OPTION_BOOL, &sendbuffer_warn, 1},
   {"lost", "Set the number of packets to lose by default (scenario specifications override this value).", SIPP_OPTION_FLOAT, &global_lost, 1},
   {"key", "keyword value\nSet the generic parameter named \"keyword\" to \"value\".", SIPP_OPTION_KEY, NULL, 1},
   {"set", "variable value\nSet the global variable parameter named \"variable\" to \"value\".", SIPP_OPTION_VAR, NULL, 3},
   {"tdmmap", "Generate and handle a table of TDM circuits.\n"
    "A circuit must be available for the call to be placed.\n"
    "Format: -tdmmap {0-3}{99}{5-8}{1-31}", SIPP_OPTION_TDMMAP, NULL, 1},
   {"dynamicStart", "variable value\nSet the start offset of dynamic_id variable",  SIPP_OPTION_INT, &startDynamicId, 1},
   {"dynamicMax",   "variable value\nSet the maximum of dynamic_id variable     ",   SIPP_OPTION_INT, &maxDynamicId,   1},
   {"dynamicStep",  "variable value\nSet the increment of dynamic_id variable",      SIPP_OPTION_INT, &stepDynamicId,  1},


    {"", "Call behavior options:", SIPP_HELP_TEXT_HEADER, NULL, 0},
    {"aa", "Enable automatic 200 OK answer for INFO, UPDATE and NOTIFY messages.", SIPP_OPTION_SETFLAG, &auto_answer, 1},
    {"base_cseq", "Start value of [cseq] for each call.", SIPP_OPTION_CSEQ, NULL, 1},
    {"cid_str", "Call ID string (default %u-%p@%s).  %u=call_number, %s=ip_address, %p=process_number, %%=% (in any order).", SIPP_OPTION_STRING, &call_id_string, 1},
    {"d", "Controls the length of calls. More precisely, this controls the duration of 'pause' instructions in the scenario, if they do not have a 'milliseconds' section. Default value is 0 and default unit is milliseconds.", SIPP_OPTION_TIME_MS, &duration, 1},
    {"deadcall_wait", "How long the Call-ID and final status of calls should be kept to improve message and error logs (default unit is ms).", SIPP_OPTION_TIME_MS, &deadcall_wait, 1},
    {"auth_uri", "Force the value of the URI for authentication.\n"
     "By default, the URI is composed of remote_ip:remote_port.", SIPP_OPTION_STRING, &auth_uri, 1},
    {"au", "Set authorization username for authentication challenges. Default is taken from -s argument", SIPP_OPTION_STRING, &auth_username, 1},
    {"ap", "Set the password for authentication challenges. Default is 'password'", SIPP_OPTION_STRING, &auth_password, 1},
    {"s", "Set the username part of the request URI. Default is 'service'.", SIPP_OPTION_STRING, &service, 1},
    {"default_behaviors", "Set the default behaviors that SIPp will use.  Possbile values are:\n"
     "- all\tUse all default behaviors\n"
     "- none\tUse no default behaviors\n"
     "- bye\tSend byes for aborted calls\n"
     "- abortunexp\tAbort calls on unexpected messages\n"
     "- pingreply\tReply to ping requests\n"
     "If a behavior is prefaced with a -, then it is turned off.  Example: all,-bye\n",
     SIPP_OPTION_DEFAULTS, &default_behaviors, 1},
    {"nd", "No Default. Disable all default behavior of SIPp which are the following:\n"
     "- On UDP retransmission timeout, abort the call by sending a BYE or a CANCEL\n"
     "- On receive timeout with no ontimeout attribute, abort the call by sending a BYE or a CANCEL\n"
     "- On unexpected BYE send a 200 OK and close the call\n"
     "- On unexpected CANCEL send a 200 OK and close the call\n"
     "- On unexpected PING send a 200 OK and continue the call\n"
     "- On any other unexpected message, abort the call by sending a BYE or a CANCEL\n",
     SIPP_OPTION_UNSETFLAG, &default_behaviors, 1},
    {"pause_msg_ign", "Ignore the messages received during a pause defined in the scenario ", SIPP_OPTION_SETFLAG, &pause_msg_ign, 1},


    {"", "Injection file options:", SIPP_HELP_TEXT_HEADER, NULL, 0},
    {"inf", "Inject values from an external CSV file during calls into the scenarios.\n"
     "First line of this file say whether the data is to be read in sequence (SEQUENTIAL), random (RANDOM), or user (USER) order.\n"
     "Each line corresponds to one call and has one or more ';' delimited data fields. Those fields can be referred as [field0], [field1], ... in the xml scenario file.  Several CSV files can be used simultaneously (syntax: -inf f1.csv -inf f2.csv ...)", SIPP_OPTION_INPUT_FILE, NULL, 1},
    {"infindex", "file field\nCreate an index of file using field.  For example -inf users.csv -infindex users.csv 0 creates an index on the first key.", SIPP_OPTION_INDEX_FILE, NULL, 1 },
    {"ip_field", "Set which field from the injection file contains the IP address from which the client will send its messages.\n"
     "If this option is omitted and the '-t ui' option is present, then field 0 is assumed.\n"
     "Use this option together with '-t ui'", SIPP_OPTION_INT, &peripfield, 1},


    {"", "RTP behaviour options:", SIPP_HELP_TEXT_HEADER, NULL, 0},
    {"mi", "Set the local media IP address (default: local primary host IP address)", SIPP_OPTION_IP, media_ip, 1},
    {"rtp_echo", "Enable RTP echo. RTP/UDP packets received on port defined by -mp are echoed to their sender.\n"
     "RTP/UDP packets coming on this port + 2 are also echoed to their sender (used for sound and video echo).",
     SIPP_OPTION_SETFLAG, &rtp_echo_enabled, 1},
    {"mb", "Set the RTP echo buffer size (default: 2048).", SIPP_OPTION_INT, &media_bufsize, 1},
    {"mp", "Set the local RTP echo port number. Default is 6000.", SIPP_OPTION_INT, &user_media_port, 1},
#ifdef RTP_STREAM
	{"min_rtp_port", "Minimum port number for RTP socket range.", SIPP_OPTION_INT, &min_rtp_port, 1},
	{"max_rtp_port", "Maximum port number for RTP socket range.", SIPP_OPTION_INT, &max_rtp_port, 1},
	{"rtp_payload", "RTP default payload type.", SIPP_OPTION_INT, &rtp_default_payload, 1},
	{"rtp_threadtasks", "RTP number of playback tasks per thread.", SIPP_OPTION_INT, &rtp_tasks_per_thread, 1},
	{"rtp_buffsize", "Set the rtp socket send/receive buffer size.", SIPP_OPTION_INT, &rtp_buffsize, 1},
#endif

    {"", "Call rate options:", SIPP_HELP_TEXT_HEADER, NULL, 0},
    {"r", "Set the call rate (in calls per seconds).  This value can be"
     "changed during test by pressing '+','_','*' or '/'. Default is 10.\n"
     "pressing '+' key to increase call rate by 1 * rate_scale,\n"
     "pressing '-' key to decrease call rate by 1 * rate_scale,\n"
     "pressing '*' key to increase call rate by 10 * rate_scale,\n"
     "pressing '/' key to decrease call rate by 10 * rate_scale.\n",
     SIPP_OPTION_FLOAT, &rate, 1},
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

    {"l", "Set the maximum number of simultaneous calls. Once this limit is reached, traffic is decreased until the number of open calls goes down. Default:\n"
     "  (3 * call_duration (s) * rate).", SIPP_OPTION_LIMIT, NULL, 1},
    {"m", "Stop the test and exit when 'calls' calls are processed", SIPP_OPTION_LONG, &stop_after, 1},
    {"users", "Instead of starting calls at a fixed rate, begin 'users' calls at startup, and keep the number of calls constant.", SIPP_OPTION_USERS, NULL, 1},


    {"", "Retransmission and timeout options:", SIPP_HELP_TEXT_HEADER, NULL, 0},
    {"recv_timeout", "Global receive timeout. Default unit is milliseconds. If the expected message is not received, the call times out and is aborted.", SIPP_OPTION_TIME_MS_LONG, &defl_recv_timeout, 1},
    {"send_timeout", "Global send timeout. Default unit is milliseconds. If a message is not sent (due to congestion), the call times out and is aborted.", SIPP_OPTION_TIME_MS_LONG, &defl_send_timeout, 1},
    {"timeout", "Global timeout. Default unit is seconds.  If this option is set, SIPp quits after nb units (-timeout 20s quits after 20 seconds).", SIPP_OPTION_TIME_SEC, &global_timeout, 1},
    {"timeout_error", "SIPp fails if the global timeout is reached is set (-timeout option required).", SIPP_OPTION_SETFLAG, &timeout_error, 1},
    {"max_retrans", "Maximum number of UDP retransmissions before call ends on timeout.  Default is 5 for INVITE transactions and 7 for others.", SIPP_OPTION_INT, &max_udp_retrans, 1},
    {"max_invite_retrans", "Maximum number of UDP retransmissions for invite transactions before call ends on timeout.", SIPP_OPTION_INT, &max_invite_retrans, 1},
    {"max_non_invite_retrans", "Maximum number of UDP retransmissions for non-invite transactions before call ends on timeout.", SIPP_OPTION_INT, &max_non_invite_retrans, 1},
    {"nr", "Disable retransmission in UDP mode.", SIPP_OPTION_UNSETFLAG, &retrans_enabled, 1},
    {"rtcheck", "Select the retransmission detection method: full (default) or loose.", SIPP_OPTION_RTCHECK, &rtcheck, 1},
    {"T2", "Global T2-timer in milli seconds", SIPP_OPTION_TIME_MS, &global_t2, 1},


    {"", "Third-party call control options:", SIPP_HELP_TEXT_HEADER, NULL, 0},
    {"3pcc", "Launch the tool in 3pcc mode (\"Third Party call control\"). The passed IP address depends on the 3PCC role.\n"
     "- When the first twin command is 'sendCmd' then this is the address of the remote twin socket.  SIPp will try to connect to this address:port to send the twin command (This instance must be started after all other 3PCC scenarios).\n"
     "    Example: 3PCC-C-A scenario.\n"
     "- When the first twin command is 'recvCmd' then this is the address of the local twin socket. SIPp will open this address:port to listen for twin command.\n"
     "    Example: 3PCC-C-B scenario.", SIPP_OPTION_3PCC, NULL, 1},
    {"master","3pcc extended mode: indicates the master number", SIPP_OPTION_3PCC_EXTENDED, &master_name, 1},
    {"slave", "3pcc extended mode: indicates the slave number", SIPP_OPTION_3PCC_EXTENDED, &slave_number, 1},
    {"slave_cfg", "3pcc extended mode: indicates the file where the master and slave addresses are stored", SIPP_OPTION_SLAVE_CFG, NULL, 1},

    {"", "Performance and watchdog options:", SIPP_HELP_TEXT_HEADER, NULL, 0},
    {"timer_resol", "Set the timer resolution. Default unit is milliseconds.  This option has an impact on timers precision."
     "Small values allow more precise scheduling but impacts CPU usage."
     "If the compression is on, the value is set to 50ms. The default value is 10ms.", SIPP_OPTION_TIME_MS, &timer_resolution, 1},
    {"max_recv_loops", "Set the maximum number of messages received read per cycle. Increase this value for high traffic level.  The default value is 1000.", SIPP_OPTION_INT, &max_recv_loops, 1},
    {"max_sched_loops", "Set the maximum number of calls run per event loop. Increase this value for high traffic level.  The default value is 1000.", SIPP_OPTION_INT, &max_sched_loops, 1},

    {"watchdog_interval", "Set gap between watchdog timer firings.  Default is 400.", SIPP_OPTION_TIME_MS, &watchdog_interval, 1},
    {"watchdog_reset", "If the watchdog timer has not fired in more than this time period, then reset the max triggers counters.  Default is 10 minutes.", SIPP_OPTION_TIME_MS, &watchdog_reset, 1},
    {"watchdog_minor_threshold", "If it has been longer than this period between watchdog executions count a minor trip.  Default is 500.", SIPP_OPTION_TIME_MS, &watchdog_minor_threshold, 1},
    {"watchdog_major_threshold", "If it has been longer than this period between watchdog executions count a major trip.  Default is 3000.", SIPP_OPTION_TIME_MS, &watchdog_major_threshold, 1},
    {"watchdog_major_maxtriggers", "How many times the major watchdog timer can be tripped before the test is terminated.  Default is 10.", SIPP_OPTION_INT, &watchdog_major_maxtriggers, 1},
    {"watchdog_minor_maxtriggers", "How many times the minor watchdog timer can be tripped before the test is terminated.  Default is 120.", SIPP_OPTION_INT, &watchdog_minor_maxtriggers, 1},


    {"", "Tracing, logging and statistics options:", SIPP_HELP_TEXT_HEADER, NULL, 0},
    {"f", "Set the statistics report frequency on screen. Default is 1 and default unit is seconds.", SIPP_OPTION_TIME_SEC, &report_freq, 1},

    {"trace_stat", "Dumps all statistics in <scenario_name>_<pid>.csv file. Use the '-h stat' option for a detailed description of the statistics file content.", SIPP_OPTION_SETFLAG, &dumpInFile, 1},
    {"stat_delimiter", "Set the delimiter for the statistics file", SIPP_OPTION_STRING, &stat_delimiter, 1},
    {"stf", "Set the file name to use to dump statistics", SIPP_OPTION_ARGI, &argiFileName, 1},
    {"fd", "Set the statistics dump log report frequency. Default is 60 and default unit is seconds.", SIPP_OPTION_TIME_SEC, &report_freq_dumpLog, 1},
    {"periodic_rtd", "Reset response time partition counters each logging interval.", SIPP_OPTION_SETFLAG, &periodic_rtd, 1},

    {"trace_msg", "Displays sent and received SIP messages in <scenario file name>_<pid>_messages.log", SIPP_OPTION_SETFLAG, &useMessagef, 1},
    {"message_file", "Set the name of the message log file.", SIPP_OPTION_LFNAME, &message_lfi, 1},
    {"message_overwrite", "Overwrite the message log file (default true).", SIPP_OPTION_LFOVERWRITE, &message_lfi, 1},

    {"trace_shortmsg", "Displays sent and received SIP messages as CSV in <scenario file name>_<pid>_shortmessages.log", SIPP_OPTION_SETFLAG, &useShortMessagef, 1},
    {"shortmessage_file", "Set the name of the short message log file.", SIPP_OPTION_LFNAME, &shortmessage_lfi, 1},
    {"shortmessage_overwrite", "Overwrite the short message log file (default true).", SIPP_OPTION_LFOVERWRITE, &shortmessage_lfi, 1},

    {"trace_counts", "Dumps individual message counts in a CSV file.", SIPP_OPTION_SETFLAG, &useCountf, 1},

    {"trace_err", "Trace all unexpected messages in <scenario file name>_<pid>_errors.log.", SIPP_OPTION_SETFLAG, &print_all_responses, 1},
    {"error_file", "Set the name of the error log file.", SIPP_OPTION_LFNAME, &error_lfi, 1},
    {"error_overwrite", "Overwrite the error log file (default true).", SIPP_OPTION_LFOVERWRITE, &error_lfi, 1},

    {"trace_error_codes", "Dumps the SIP response codes of unexpected messages to <scenario file name>_<pid>_error_codes.log.", SIPP_OPTION_SETFLAG, &useErrorCodesf, 1},
//	{"trace_timeout", "Displays call ids for calls with timeouts in <scenario file name>_<pid>_timeout.log", SIPP_OPTION_SETFLAG, &useTimeoutf, 1},

    {"trace_calldebug", "Dumps debugging information about aborted calls to <scenario_name>_<pid>_calldebug.log file.", SIPP_OPTION_SETFLAG, &useCallDebugf, 1},
    {"calldebug_file", "Set the name of the call debug file.", SIPP_OPTION_LFNAME, &calldebug_lfi, 1},
    {"calldebug_overwrite", "Overwrite the call debug file (default true).", SIPP_OPTION_LFOVERWRITE, &calldebug_lfi, 1},

    {"trace_screen", "Dump statistic screens in the <scenario_name>_<pid>_screens.log file when quitting SIPp. Useful to get a final status report in background mode (-bg option).", SIPP_OPTION_SETFLAG, &useScreenf, 1},

    {"trace_rtt", "Allow tracing of all response times in <scenario file name>_<pid>_rtt.csv.", SIPP_OPTION_SETFLAG, &dumpInRtt, 1},
    {"rtt_freq", "freq is mandatory. Dump response times every freq calls in the log file defined by -trace_rtt. Default value is 200.",
     SIPP_OPTION_LONG, &report_freq_dumpRtt, 1},


    {"trace_logs", "Allow tracing of <log> actions in <scenario file name>_<pid>_logs.log.", SIPP_OPTION_SETFLAG, &useLogf, 1},
    {"log_file", "Set the name of the log actions log file.", SIPP_OPTION_LFNAME, &log_lfi, 1},
    {"log_overwrite", "Overwrite the log actions log file (default true).", SIPP_OPTION_LFOVERWRITE, &log_lfi, 1},

    {"ringbuffer_files", "How many error, message, shortmessage and calldebug files should be kept after rotation?", SIPP_OPTION_INT, &ringbuffer_files, 1},
    {"ringbuffer_size", "How large should error, message, shortmessage and calldebug files be before they get rotated?", SIPP_OPTION_LONG_LONG, &ringbuffer_size, 1},
    {"max_log_size", "What is the limit for error, message, shortmessage and calldebug file sizes.", SIPP_OPTION_LONG_LONG, &max_log_size, 1},

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

/******************** Recv Poll Processing *********************/

extern int pollnfds;
#ifdef HAVE_EPOLL
extern int epollfd;
extern struct epoll_event   epollfiles[SIPP_MAXFDS];
extern struct epoll_event*  epollevents;
#else
extern struct pollfd        pollfiles[SIPP_MAXFDS];
#endif
extern struct sipp_socket  *sockets[SIPP_MAXFDS];

extern int pending_messages;

/************** Statistics display & User control *************/

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

void pollset_process(int wait)
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
#ifndef HAVE_EPOLL
    // If not using epoll, we have a queue of pending messages to spin through.

    if (read_index >= pollnfds) {
        read_index = 0;
    }

    /* We need to process any messages that we have left over. */
    while (pending_messages && (loops > 0)) {
        getmilliseconds();
        if (sockets[read_index]->ss_msglen) {
            struct sockaddr_storage src;
            char msg[SIPP_MAX_MSG_SIZE];
            ssize_t len = read_message(sockets[read_index], msg, sizeof(msg), &src);
            if (len > 0) {
                process_message(sockets[read_index], msg, len, &src);
            } else {
                assert(0);
            }
            loops--;
        }
        read_index = (read_index + 1) % pollnfds;
    }

    /* Don't read more data if we still have some left over. */
    if (pending_messages) {
        return;
    }
#endif
    /* Get socket events. */
#ifdef HAVE_EPOLL
    /* Ignore the wait parameter and always wait - when establishing TCP
     * connections, the alternative is that we tight-loop. */
    rs = epoll_wait(epollfd, epollevents, max_recv_loops, 1);
    // If we're receiving as many epollevents as possible, flag CPU congestion
    cpu_max = (rs > (max_recv_loops - 2));
#else
    rs = poll(pollfiles, pollnfds, wait ? 1 : 0);
#endif
    if((rs < 0) && (errno == EINTR)) {
        return;
    }

    /* We need to flush all sockets and pull data into all of our buffers. */
#ifdef HAVE_EPOLL
    for (int event_idx = 0; event_idx < rs; event_idx++) {
        int poll_idx = (int)epollevents[event_idx].data.u32;
#else
    for (int poll_idx = 0; rs > 0 && poll_idx < pollnfds; poll_idx++) {
#endif
        struct sipp_socket *sock = sockets[poll_idx];
        int events = 0;
        int ret = 0;

        assert(sock);

#ifdef HAVE_EPOLL
        if (epollevents[event_idx].events & EPOLLOUT) {
#else
        if (pollfiles[poll_idx].revents & POLLOUT) {
#endif

#ifdef USE_SCTP
            if (transport == T_SCTP && sock->sctpstate != SCTP_UP) ;
            else
#endif
            {
                /* We can flush this socket. */
                TRACE_MSG("Exit problem event on socket %d \n", sock->ss_fd);
#ifdef HAVE_EPOLL
                epollfiles[poll_idx].events &= ~EPOLLOUT;
                int rc = epoll_ctl(epollfd, EPOLL_CTL_MOD, sock->ss_fd, &epollfiles[poll_idx]);
                if (rc == -1) {
                    ERROR_NO("Failed to clear EPOLLOUT");
                }
#else
                pollfiles[poll_idx].events &= ~POLLOUT;
#endif
                sock->ss_congested = false;

                flush_socket(sock);
                events++;
            }
        }

#ifdef HAVE_EPOLL
        if (epollevents[event_idx].events & EPOLLIN) {
#else
        if (pollfiles[poll_idx].revents & POLLIN) {
#endif
            /* We can empty this socket. */
            if ((transport == T_TCP || transport == T_TLS || transport == T_SCTP) && sock == main_socket) {
                struct sipp_socket *new_sock = sipp_accept_socket(sock);
                if (!new_sock) {
                    ERROR_NO("Accepting new TCP connection.\n");
                }
            } else if (sock == ctrl_socket) {
                handle_ctrl_socket();
            } else if (sock == stdin_socket) {
                handle_stdin_socket();
            } else if (sock == localTwinSippSocket) {
                if (thirdPartyMode == MODE_3PCC_CONTROLLER_B) {
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
                    if(!peers_connected) {
                        connect_to_all_peers();
                    }
                }
            } else {
                if ((ret = empty_socket(sock)) <= 0) {
#ifdef USE_SCTP
                    if (sock->ss_transport==T_SCTP && ret==-2) ;
                    else
#endif
                    {
            ret = read_error(sock, ret);
            if (ret == 0) {
              /* If read_error() then the poll_idx now belongs
               * to the newest/last socket added to the sockets[].
               * Need to re-do the same poll_idx for the "new" socket.
               * We do this differently when using epoll. */
#ifdef HAVE_EPOLL
              for (int event_idx2 = event_idx + 1; event_idx2 < rs; event_idx2++) {
                if (epollevents[event_idx2].data.u32 == pollnfds) {
                  epollevents[event_idx2].data.u32 = poll_idx;
                }
              }
#else
              poll_idx--;
              events++;
              rs--;
#endif
              continue;
            }
          }
        }
                }
            events++;
        }
    /* Here the logic diverges; if we're using epoll, we want to stay in the
     * for-each-socket loop and handle messages on that socket. If we're not using
     * epoll, we want to wait until after that loop, and spin through our
     * pending_messages queue again. */

#ifdef HAVE_EPOLL
    int old_pollnfds = pollnfds;
    getmilliseconds();
    /* Keep processing messages until this socket is freed (changing the number of file descriptors) or we run out of messages. */
    while ((pollnfds == old_pollnfds) &&
           (sock->ss_msglen)) {
      char msg[SIPP_MAX_MSG_SIZE];
      struct sockaddr_storage src;
      ssize_t len;

      len = read_message(sock, msg, sizeof(msg), &src);
      if (len > 0) {
        process_message(sock, msg, len, &src);
      } else {
        assert(0);
      }
    }

    if (pollnfds != old_pollnfds) {
      /* Processing messages has changed the number of pollnfds, so update any remaining events */
      for (int event_idx2 = event_idx + 1; event_idx2 < rs; event_idx2++) {
        if (epollevents[event_idx2].data.u32 == pollnfds) {
          epollevents[event_idx2].data.u32 = poll_idx;
        }
      }
    }
  }
#else

        if (events) {
            rs--;
        }
    pollfiles[poll_idx].revents = 0;
    }

    if (read_index >= pollnfds) {
        read_index = 0;
    }

    /* We need to process any new messages that we read. */
    while (pending_messages && (loops > 0)) {
        getmilliseconds();

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
            loops--;
        }
        read_index = (read_index + 1) % pollnfds;
    }

    cpu_max = (loops <= 0);
#endif
}

void timeout_alarm(int param)
{
    /* We need the param parameter as this is a callback with defined arguments,
     * but we don't use it. Cast to void to avoid warnings. */
    (void)param;

    if (timeout_error) {
        ERROR("%s timed out after '%.3lf' seconds", scenario_file, ((double)clock_tick / 1000LL));
    }
    quitting = 1;
    timeout_exit = true;
}

/* Send loop & trafic generation*/

void traffic_thread()
{
    /* create the file */
    char         L_file_name [MAX_PATH];
    sprintf (L_file_name, "%s_%d_screen.log", scenario_file, getpid());

    getmilliseconds();

    /* Arm the global timer if needed */
    if (global_timeout > 0) {
        signal(SIGALRM, timeout_alarm);
        alarm(global_timeout / 1000);
    }

    // Dump (to create file on disk) and showing screen at the beginning even if
    // the report period is not reached
    stattask::report();
    screentask::report(false);

    while(1) {
        scheduling_loops++;
        getmilliseconds();

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

        if ((main_scenario->stats->GetStat(CStat::CPT_C_IncomingCallCreated) + main_scenario->stats->GetStat(CStat::CPT_C_OutgoingCallCreated)) >= stop_after) {
            quitting = 1;
        }
        if (quitting) {
            if (quitting > 11) {
                /* Force exit: abort all calls */
                abort_all_tasks();
            }
            /* Quitting and no more openned calls, close all */
            if(!main_scenario->stats->GetStat(CStat::CPT_C_CurrentCall)) {
                /* We can have calls that do not count towards our open-call count (e.g., dead calls). */
                abort_all_tasks();
#ifdef RTP_STREAM
                rtpstream_shutdown();
#endif
                for (int i = 0; i < pollnfds; i++) {
                    sipp_close_socket(sockets[i]);
                }

                screentask::report(true);
                stattask::report();
                if (screenf) {
                    print_screens();
                }

                screen_exit(EXIT_TEST_RES_UNKNOWN);
            }
        }

        getmilliseconds();

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
                if (sockets_pending_reset.begin() != sockets_pending_reset.end()) {
                    last = NULL;
                    break;
                }
            }
            last = *iter;
            if (--loops <= 0) {
                break;
            }
        }
        if(last) {
            last -> run();
        }
        while (sockets_pending_reset.begin() != sockets_pending_reset.end()) {
            reset_connection(*(sockets_pending_reset.begin()));
            sockets_pending_reset.erase(sockets_pending_reset.begin());
        }

        /* Update the clock. */
        getmilliseconds();
        /* Receive incoming messages */
        pollset_process(running_tasks->empty());
    }
}

/*************** RTP ECHO THREAD ***********************/
/* param is a pointer to RTP socket */

void rtp_echo_thread (void * param)
{
    char msg[media_bufsize];
    size_t nr, ns;
    sipp_socklen_t len;
    struct sockaddr_storage remote_rtp_addr;


    int                   rc;
    sigset_t              mask;
    sigfillset(&mask); /* Mask all allowed signals */
    rc = pthread_sigmask(SIG_BLOCK, &mask, NULL);
    if (rc) {
        WARNING("pthread_sigmask returned %d", rc);
        return;
    }

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
        } else {
            /* packets on the second RTP stream */
            rtp2_pckts++;
            rtp2_bytes += ns;
        }
    }
}

/* Wrap the help text. */
char *wrap(const char *in, int offset, int size)
{
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
                int move_back = 0;

                out[k] = '\n';
                pos = j - k;
                // move_back is used to step back in the in and out buffers when a
                // word is longer than useoffset.
                if (i > (k + useoffset)) {
                    move_back = i - (k + useoffset);
                    i -= move_back;
                }
                k++;
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
                j += useoffset - move_back;
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
     "Example:\n"
     "\n"
     "   Run SIPp with embedded server (uas) scenario:\n"
     "     ./sipp -sn uas\n"
     "   On the same host, run SIPp with embedded client (uac) scenario:\n"
     "     ./sipp -sn uac 127.0.0.1\n"
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
        formatted = wrap(options_table[i].help, 22, 77);
        if (options_table[i].type == SIPP_HELP_TEXT_HEADER) {
            printf("\n*** %s\n\n", formatted);
        } else {
        printf("   -%-16s: %s\n", options_table[i].option, formatted);
        }
        free(formatted);
    }

    printf
    (
        "\n\nSignal handling:\n"
        "\n"
        "   SIPp can be controlled using POSIX signals. The following signals\n"
        "   are handled:\n"
        "   USR1: Similar to pressing the 'q' key. It triggers a soft exit\n"
        "         of SIPp. No more new calls are placed and all ongoing calls\n"
        "         are finished before SIPp exits.\n"
        "         Example: kill -SIGUSR1 732\n"
        "   USR2: Triggers a dump of all statistics screens in\n"
        "         <scenario_name>_<pid>_screens.log file. Especially useful \n"
        "         in background mode to know what the current status is.\n"
        "         Example: kill -SIGUSR2 732\n"
        "\n"
        "Exit codes:\n"
        "\n"
        "   Upon exit (on fatal error or when the number of asked calls (-m\n"
        "   option) is reached, SIPp exits with one of the following exit\n"
        "   code:\n"
        "    0: All calls were successful\n"
        "    1: At least one call failed\n"
        "   97: Exit on internal command. Calls may have been processed\n"
        "   99: Normal exit without calls processed\n"
        "   -1: Fatal error\n"
        "   -2: Fatal error binding a socket\n");
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
        "  statistic row and (C) means 'Cumulative' - since SIPp was\n"
        "  started.\n"
        "\n"
        "  Available statistics are:\n"
        "\n"
        "  - StartTime: \n"
        "    Date and time when the test has started.\n"
        "\n"
        "  - LastResetTime:\n"
        "    Date and time when periodic counters were last reset.\n"
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
        "    Number of failed calls because SIPp cannot send the\n"
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
        "    Number of failed calls because of SIPp internal error.\n"
        "    (a scenario sync command is not recognized, a scenario\n"
        "    action failed or a scenario variable assignment failed).\n"
        "\n"
        "  - FailedCmdNotSent:\n"
        "    Number of failed calls because of inter-SIPp\n"
        "    communication error (a scenario sync command failed to\n"
        "    be sent).\n"
        "\n"
        "  - FailedRegexpDoesntMatch:\n"
        "    Number of failed calls because of regexp that doesn't\n"
        "    match (there might be several regexp that don't match\n"
        "    during the call but the counter is increased only by\n"
        "    one).\n"
        "\n"
        "  - FailedRegexpShouldntMatch:\n"
        "    Number of failed calls because of regexp that shouldn't\n"
        "    match but does (there might be several regexp that shouldn't match\n"
        "    during the call but the counter is increased only by\n"
        "    one).\n"
        "\n"
        "  - FailedRegexpHdrNotFound:\n"
        "    Number of failed calls because of regexp with 'hdr'\n"
        "    option but no matching header found.\n"
        "\n"
        "  - OutOfCallMsgs:\n"
        "    Number of SIP messages received that cannot be associated\n"
        "    to an existing call.\n"
        "\n"
        "  - AutoAnswered:\n"
        "    Number of unexpected specific messages received for new Call-ID.\n"
        "    The message has been automatically answered by a 200 OK\n"
        "    Currently, implemented for 'NOTIFY', 'INFO' and 'PING' messages.\n"
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
    if (main_scenario) {
        stattask::report();
    }
}

char* remove_pattern(char* P_buffer, char* P_extensionPattern)
{

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

/* Main */
int main(int argc, char *argv[])
{
    int                  argi = 0;
    struct sockaddr_storage   media_sockaddr;
    pthread_t            pthread2_id,  pthread3_id;
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
#ifdef USE_SCTP
    memset(multihome_ip, 0, 40);
#endif
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

    for (int pass = 0; pass <= 3; pass++) {
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

            switch(option->type) {
            case SIPP_OPTION_HELP:
                if(((argi+1) < argc) && (!strcmp(argv[argi+1], "stat"))) {
                    help_stats();
                } else {
                    help();
                }
                exit(EXIT_OTHER);
            case SIPP_OPTION_VERSION:
                printf("\n SIPp v3.4.1"
#ifdef _USE_OPENSSL
                       "-TLS"
#endif
#ifdef USE_SCTP
                       "-SCTP"
#endif
#ifdef PCAPPLAY
                       "-PCAP"
#endif
#ifdef RTP_STREAM
                       "-RTPSTREAM"
#endif
                       " built %s, %s.\n\n",
                       __DATE__, __TIME__);

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
            case SIPP_OPTION_INPUT_FILE: {
                REQUIRE_ARG();
                CHECK_PASS();
                FileContents *data = new FileContents(argv[argi]);
                char *name = argv[argi];
                if (strrchr(name, '/')) {
                    name = strrchr(name, '/') + 1;
                } else if (strrchr(name, '\\')) {
                    name = strrchr(name, '\\') + 1;
                }
                assert(name);
                inFiles[name] = data;
                /* By default, the first file is used for IP address input. */
                if (!ip_file) {
                    ip_file = name;
                }
                if (!default_file) {
                    default_file = name;
                }
            }
            break;
            case SIPP_OPTION_INDEX_FILE:
                REQUIRE_ARG();
                REQUIRE_ARG();
                CHECK_PASS();
                {
                    char *fileName = argv[argi - 1];
                    char *endptr;
                    int field;

                    if (inFiles.find(fileName) == inFiles.end()) {
                        ERROR("Could not find file for -infindex: %s", argv[argi - 1]);
                    }

                    field = strtoul(argv[argi], &endptr, 0);
                    if (*endptr) {
                        ERROR("Invalid field specification for -infindex: %s", argv[argi]);
                    }

                    inFiles[fileName]->index(field);
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
                case 's':
#ifdef USE_SCTP
                    transport = T_SCTP;
#else
                    ERROR("To use SCTP transport you must compile SIPp with lksctp");
#endif
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
            case SIPP_OPTION_NEED_SCTP:
                CHECK_PASS();
                ERROR("SCTP support is required for the %s option.", argv[argi]);
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
            case SIPP_OPTION_IP: {
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
                if (users >= 0) {
                    ERROR("Can not set open call limit (-l) when -users is specified.");
                }
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
            case SIPP_OPTION_VAR:
                REQUIRE_ARG();
                REQUIRE_ARG();
                CHECK_PASS();

                {
                    int varId = globalVariables->find(argv[argi  - 1], false);
                    if (varId == -1) {
                        globalVariables->dump();
                        ERROR("Can not set the global variable %s, because it does not exist.", argv[argi - 1]);
                    }
                    globalVariables->getVar(varId)->setString(strdup(argv[argi]));
                }
                break;
            case SIPP_OPTION_3PCC:
                if(slave_masterSet) {
                    ERROR("-3PCC option is not compatible with -master and -slave options\n");
                }
                if(extendedTwinSippMode) {
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
                    scenario_file = new char [strlen(argv[argi])+1] ;
                    sprintf(scenario_file,"%s", argv[argi]);
                    scenario_file = remove_pattern (scenario_file, (char*)".xml");
                    if (useLogf == 1) {
                        rotate_logfile();
                    }
                    main_scenario = new scenario(argv[argi], 0);
                    main_scenario->stats->setFileName(scenario_file, (char*)".csv");
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
                if(twinSippMode) {
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
                if(slave_masterSet) {
                    ERROR("-slave and -master options are not compatible\n");
                }
                if(twinSippMode) {
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
            case SIPP_OPTION_RTCHECK:
                REQUIRE_ARG();
                CHECK_PASS();
                if (!strcmp(argv[argi], "full")) {
                    *((int *)option->data) = RTCHECK_FULL;
                } else if (!strcmp(argv[argi], "loose")) {
                    *((int *)option->data) = RTCHECK_LOOSE;
                } else {
                    ERROR("Unknown retransmission detection method: %s\n", argv[argi]);
                }
                break;
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
                break;
            }
            case SIPP_OPTION_LFNAME:
                REQUIRE_ARG();
                CHECK_PASS();
                ((struct logfile_info*)option->data)->fixedname = true;
                strcpy(((struct logfile_info*)option->data)->file_name, argv[argi]);
                break;
            case SIPP_OPTION_LFOVERWRITE:
                REQUIRE_ARG();
                CHECK_PASS();
                ((struct logfile_info*)option->data)->fixedname = true;
                ((struct logfile_info*)option->data)->overwrite = get_bool(argv[argi], argv[argi-1]);
                break;
            case SIPP_OPTION_PLUGIN: {
                void *handle;
                char *error;
                int (*init)();
                int ret;

                REQUIRE_ARG();
                CHECK_PASS();

                handle = dlopen(argv[argi], RTLD_NOW);
                if (!handle) {
                    ERROR("Could not open plugin %s: %s", argv[argi], dlerror());
                }

                init = (int (*)())dlsym(handle, "init");
                if((error = (char *) dlerror())) {
                    ERROR("Could not locate init function in %s: %s", argv[argi], dlerror());
                }

                ret = init();
                if (ret != 0) {
                    ERROR("Plugin %s initialization failed.", argv[argi]);
                }
            }
            break;
            default:
                ERROR("Internal error: I don't recognize the option type for %s\n", argv[argi]);
            }
        }
    }

    if((extendedTwinSippMode && !slave_masterSet) || (!extendedTwinSippMode && slave_masterSet)) {
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
    }

    screen_init(print_last_stats);

#ifdef _USE_OPENSSL
    if ((transport == T_TLS) && (FI_init_ssl_context() != SSL_INIT_NORMAL)) {
        ERROR("FI_init_ssl_context() failed");
    }
#endif

    if (useMessagef == 1) {
        rotate_messagef();
    }

    if (useShortMessagef == 1) {
        rotate_shortmessagef();
    }

    if (useCallDebugf) {
        rotate_calldebugf();
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

    if (useErrorCodesf == 1) {
        char L_file_name [MAX_PATH];
        sprintf (L_file_name, "%s_%d_error_codes.csv", scenario_file, getpid());
        codesf = fopen(L_file_name, "w");
        if(!codesf) {
            ERROR("Unable to create '%s'", L_file_name);
        }
    }


    if (dumpInRtt == 1) {
        main_scenario->stats->initRtt((char*)scenario_file, (char*)".csv",
                                      report_freq_dumpRtt);
    }

    // Check the soft limit on the number of open files,
    // error out if this does not allow us to open the
    // required number of signalling channels, and warn
    // if this may not allow enough media channels.
    if (!skip_rlimit) {
        struct rlimit rlimit;
        int max_sockets_needed = multisocket ? max_multi_socket : 1; 

        if (getrlimit (RLIMIT_NOFILE, &rlimit) < 0) {
            ERROR_NO("getrlimit error");
        }

        if (max_sockets_needed > rlimit.rlim_cur) {
            ERROR("Maximum number of open sockets (%d) should be less than the maximum number of open files (%d). Tune this with the `ulimit` command or the -max_socket option", max_sockets_needed, rlimit.rlim_cur);
        }

        if ((open_calls_allowed + max_sockets_needed) > rlimit.rlim_cur) {
            WARNING("Maximum number of open sockets (%d) plus number of open calls (%d) should be less than the maximum number of open files (%d) to allow for media support. Tune this with the `ulimit` command, the -l option or the -max_socket option", max_sockets_needed, open_calls_allowed, rlimit.rlim_cur);
        }
    }

    /* Load default scenario in case nothing was loaded */
    if(!main_scenario) {
        main_scenario = new scenario(0, 0);
        main_scenario->stats->setFileName((char*)"uac", (char*)".csv");
        sprintf(scenario_file,"uac");
    }
    /*
    if(!ooc_scenario) {
      ooc_scenario = new scenario(0, find_scenario("ooc_default"));
      ooc_scenario->stats->setFileName((char*)"ooc_default", (char*)".csv");
    }
    */
    display_scenario = main_scenario;
    aa_scenario = new scenario(0, find_scenario("ooc_dummy"));
    aa_scenario->stats->setFileName((char*)"ooc_dummy", (char*)".csv");

    init_default_messages();
    for (int i = 1; i <= users; i++) {
        freeUsers.push_back(i);
        userVarMap[i] = new VariableTable(userVariables);
    }

    if(argiFileName) {
        main_scenario->stats->setFileName(argv[argiFileName]);
    }

    // setup option form cmd line
    call::maxDynamicId   = maxDynamicId;
    call::startDynamicId = startDynamicId;
    call::dynamicId      = startDynamicId;
    call::stepDynamicId  = stepDynamicId;


    /* Now Initialize the scenarios. */
    main_scenario->runInit();
    if(ooc_scenario) {
        ooc_scenario->runInit();
    }

    /* In which mode the tool is launched ? */
    main_scenario->computeSippMode();
    if (ooc_scenario && sendMode == MODE_SERVER) {
        ERROR("SIPp cannot use out-of-call scenarios when running in server mode");
    }

    /* checking if we need to launch the tool in background mode */
    if(backgroundMode == true) {
        pid_t l_pid;
        switch(l_pid = fork()) {
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

    sipp_usleep(sleeptime * 1000);

    /* Create the statistics reporting task. */
    stattask::initialize();
    /* Create the screen update task. */
    screentask::initialize();
    /* Create a watchdog task. */
    if (watchdog_interval) {
        new watchdog(watchdog_interval, watchdog_reset, watchdog_major_threshold, watchdog_major_maxtriggers, watchdog_minor_threshold, watchdog_minor_maxtriggers);
    }

    /* Setting the rate and its dependant params (open_calls_allowed) */
    /* If we are a client, then create the task to open new calls. */
    if (creationMode == MODE_CLIENT) {
        CallGenerationTask::initialize();
        CallGenerationTask::set_rate(rate);
    }

#ifdef HAVE_EPOLL
    epollevents = (struct epoll_event*)malloc(sizeof(struct epoll_event) * max_recv_loops);
    epollfd = epoll_create(SIPP_MAXFDS);
    if (epollfd == -1) {
        ERROR_NO("Failed to open epoll FD");
    }
#endif

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

        memset(&media_sockaddr,0,sizeof(struct sockaddr_storage));
        media_sockaddr.ss_family = local_addr->ai_addr->sa_family;

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

#ifdef HAVE_EPOLL
    close(epollfd);
    free(epollevents);
#endif

    if (scenario_file != NULL) {
        delete [] scenario_file ;
        scenario_file = NULL ;
    }

}

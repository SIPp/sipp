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
 *           Michael Hirschbichler
 */

#include <dlfcn.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <atomic>
#include <vector>

#ifdef __APPLE__
/* Provide OSX version of extern char **environ; */
#include <crt_externs.h>
#define environ (*_NSGetEnviron())
#endif
extern char** environ;

#define GLOBALS_FULL_DEFINITION
#include "sipp.hpp"

#include "sip_parser.hpp"
#include "socket.hpp"
#include "logger.hpp"
#include "assert.h"
#include "config.h"
#include "version.h"

extern SIPpSocket *ctrl_socket;
extern SIPpSocket *stdin_socket;

/* These could be local to main, but for the option processing table. */
static int argiFileName;
static std::atomic<bool> run_echo_thread(true);

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

#define SIPP_OPTION_HELP           1
#define SIPP_OPTION_INT            2
#define SIPP_OPTION_SETFLAG        3
#define SIPP_OPTION_UNSETFLAG      4
#define SIPP_OPTION_STRING         5
#define SIPP_OPTION_ARGI           6
#define SIPP_OPTION_TIME_SEC       7
#define SIPP_OPTION_FLOAT          8
#define SIPP_OPTION_BOOL          10
#define SIPP_OPTION_VERSION       11
#define SIPP_OPTION_TRANSPORT     12
#define SIPP_OPTION_NEED_SSL      13
#define SIPP_OPTION_IP            14
#define SIPP_OPTION_MAX_SOCKET    15
#define SIPP_OPTION_CSEQ          16
#define SIPP_OPTION_SCENARIO      17
#define SIPP_OPTION_RSA           18
#define SIPP_OPTION_LIMIT         19
#define SIPP_OPTION_USERS         20
#define SIPP_OPTION_KEY           21
#define SIPP_OPTION_3PCC          22
#define SIPP_OPTION_TDMMAP        23
#define SIPP_OPTION_TIME_MS       24
#define SIPP_OPTION_SLAVE_CFG     25
#define SIPP_OPTION_3PCC_EXTENDED 26
#define SIPP_OPTION_INPUT_FILE    27
#define SIPP_OPTION_TIME_MS_LONG  28
#define SIPP_OPTION_LONG          29
#define SIPP_OPTION_LONG_LONG     30
#define SIPP_OPTION_DEFAULTS      31
#define SIPP_OPTION_OOC_SCENARIO  32
#define SIPP_OPTION_INDEX_FILE    33
#define SIPP_OPTION_VAR           34
#define SIPP_OPTION_RTCHECK       35
#define SIPP_OPTION_LFNAME        36
#define SIPP_OPTION_LFOVERWRITE   37
#define SIPP_OPTION_PLUGIN        38
#define SIPP_OPTION_NEED_SCTP     39
#define SIPP_HELP_TEXT_HEADER    255

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
#ifdef USE_TLS
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

#ifdef USE_TLS
    {"tls_cert", "Set the name for TLS Certificate file. Default is 'cacert.pem'", SIPP_OPTION_STRING, &tls_cert_name, 1},
    {"tls_key", "Set the name for TLS Private Key file. Default is 'cakey.pem'", SIPP_OPTION_STRING, &tls_key_name, 1},
    {"tls_ca", "Set the name for TLS CA file. If not specified, X509 verification is not activated.", SIPP_OPTION_STRING, &tls_ca_name, 1},
    {"tls_crl", "Set the name for Certificate Revocation List file. If not specified, X509 CRL is not activated.", SIPP_OPTION_STRING, &tls_crl_name, 1},
    {"tls_version", "Set the TLS protocol version to use (1.0, 1.1, 1.2) -- default is autonegotiate", SIPP_OPTION_FLOAT, &tls_version, 1},
#else
    {"tls_cert", NULL, SIPP_OPTION_NEED_SSL, NULL, 1},
    {"tls_key", NULL, SIPP_OPTION_NEED_SSL, NULL, 1},
    {"tls_ca", NULL, SIPP_OPTION_NEED_SSL, NULL, 1},
    {"tls_crl", NULL, SIPP_OPTION_NEED_SSL, NULL, 1},
    {"tls_version", NULL, SIPP_OPTION_NEED_SSL, NULL, 1},
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
    {"aa", "Enable automatic 200 OK answer for INFO, NOTIFY, OPTIONS and UPDATE.", SIPP_OPTION_SETFLAG, &auto_answer, 1},
    {"base_cseq", "Start value of [cseq] for each call.", SIPP_OPTION_CSEQ, NULL, 1},
    {"cid_str", "Call ID string (default %u-%p@%s).  %u=call_number, %s=ip_address, %p=process_number, %%=% (in any order).", SIPP_OPTION_STRING, &call_id_string, 1},
    {"d", "Controls the length of calls. More precisely, this controls the duration of 'pause' instructions in the scenario, if they do not have a 'milliseconds' section. Default value is 0 and default unit is milliseconds.", SIPP_OPTION_TIME_MS, &duration, 1},
    {"deadcall_wait", "How long the Call-ID and final status of calls should be kept to improve message and error logs (default unit is ms).", SIPP_OPTION_TIME_MS, &deadcall_wait, 1},
    {"auth_uri", "Force the value of the URI for authentication.\n"
     "By default, the URI is composed of remote_ip:remote_port.", SIPP_OPTION_STRING, &auth_uri, 1},
    {"au", "Set authorization username for authentication challenges. Default is taken from -s argument", SIPP_OPTION_STRING, &auth_username, 1},
    {"ap", "Set the password for authentication challenges. Default is 'password'", SIPP_OPTION_STRING, &auth_password, 1},
    {"s", "Set the username part of the request URI. Default is 'service'.", SIPP_OPTION_STRING, &service, 1},
    {"default_behaviors", "Set the default behaviors that SIPp will use.  Possible values are:\n"
     "- all\tUse all default behaviors\n"
     "- none\tUse no default behaviors\n"
     "- bye\tSend byes for aborted calls\n"
     "- abortunexp\tAbort calls on unexpected messages\n"
     "- pingreply\tReply to ping requests\n"
     "- cseq\tCheck CSeq of ACKs\n"
     "If a behavior is prefaced with a -, then it is turned off.  Example: all,-bye\n",
     SIPP_OPTION_DEFAULTS, &default_behaviors, 1},
    {"nd", "No Default. Disable all default behavior of SIPp which are the following:\n"
     "- On UDP retransmission timeout, abort the call by sending a BYE or a CANCEL\n"
     "- On receive timeout with no ontimeout attribute, abort the call by sending a BYE or a CANCEL\n"
     "- On unexpected BYE send a 200 OK and close the call\n"
     "- On unexpected CANCEL send a 200 OK and close the call\n"
     "- On unexpected PING send a 200 OK and continue the call\n"
     "- On unexpected ACK CSeq do nothing\n"
     "- On any other unexpected message, abort the call by sending a BYE or a CANCEL\n",
     SIPP_OPTION_UNSETFLAG, &default_behaviors, 1},
    {"pause_msg_ign", "Ignore the messages received during a pause defined in the scenario ", SIPP_OPTION_SETFLAG, &pause_msg_ign, 1},
    {"callid_slash_ign", "Don't treat a triple-slash in Call-IDs as indicating an extra SIPp prefix.", SIPP_OPTION_SETFLAG, &callidSlash, 1},


    {"", "Injection file options:", SIPP_HELP_TEXT_HEADER, NULL, 0},
    {"inf", "Inject values from an external CSV file during calls into the scenarios.\n"
     "First line of this file say whether the data is to be read in sequence (SEQUENTIAL), random (RANDOM), or user (USER) order.\n"
     "Each line corresponds to one call and has one or more ';' delimited data fields. Those fields can be referred as [field0], [field1], ... in the xml scenario file.  Several CSV files can be used simultaneously (syntax: -inf f1.csv -inf f2.csv ...)", SIPP_OPTION_INPUT_FILE, NULL, 1},
    {"infindex", "file field\nCreate an index of file using field.  For example -inf ../path/to/users.csv -infindex users.csv 0 creates an index on the first key.", SIPP_OPTION_INDEX_FILE, NULL, 1 },
    {"ip_field", "Set which field from the injection file contains the IP address from which the client will send its messages.\n"
     "If this option is omitted and the '-t ui' option is present, then field 0 is assumed.\n"
     "Use this option together with '-t ui'", SIPP_OPTION_INT, &peripfield, 1},


    {"", "RTP behaviour options:", SIPP_HELP_TEXT_HEADER, NULL, 0},
    {"mi", "Set the local media IP address (default: local primary host IP address)", SIPP_OPTION_IP, media_ip, 1},
    {"rtp_echo", "Enable RTP echo. RTP/UDP packets received on media port are echoed to their sender.\n"
     "RTP/UDP packets coming on this port + 2 are also echoed to their sender (used for sound and video echo).",
     SIPP_OPTION_SETFLAG, &rtp_echo_enabled, 1},
    {"mb", "Set the RTP echo buffer size (default: 2048).", SIPP_OPTION_INT, &media_bufsize, 1},
    {"min_rtp_port", "Minimum port number for RTP socket range.", SIPP_OPTION_INT, &min_rtp_port, 1},
    {"max_rtp_port", "Maximum port number for RTP socket range.", SIPP_OPTION_INT, &max_rtp_port, 1},
    {"mp", NULL, SIPP_OPTION_INT, &min_rtp_port, 1},
    {"rtp_payload", "RTP default payload type.", SIPP_OPTION_INT, &rtp_default_payload, 1},
    {"rtp_threadtasks", "RTP number of playback tasks per thread.", SIPP_OPTION_INT, &rtp_tasks_per_thread, 1},
    {"rtp_buffsize", "Set the rtp socket send/receive buffer size.", SIPP_OPTION_INT, &rtp_buffsize, 1},
    {"rtpcheck_debug", "Write RTP check debug information to file", SIPP_OPTION_SETFLAG, &rtpcheck_debug, 1},
#ifdef USE_TLS
    {"srtpcheck_debug", "Write SRTP check debug information to file", SIPP_OPTION_SETFLAG, &srtpcheck_debug, 1},
#endif // USE_TLS
    {"audiotolerance", "Audio error tolerance for RTP checks (0.0-1.0) -- default: 1.0", SIPP_OPTION_FLOAT, &audiotolerance, 1},
    {"videotolerance", "Video error tolerance for RTP checks (0.0-1.0) -- default: 1.0", SIPP_OPTION_FLOAT, &videotolerance, 1},

    {"", "Call rate options:", SIPP_HELP_TEXT_HEADER, NULL, 0},
    {"r", "Set the call rate (in calls per seconds).  This value can be"
     "changed during test by pressing '+', '_', '*' or '/'. Default is 10.\n"
     "pressing '+' key to increase call rate by 1 * rate_scale,\n"
     "pressing '-' key to decrease call rate by 1 * rate_scale,\n"
     "pressing '*' key to increase call rate by 10 * rate_scale,\n"
     "pressing '/' key to decrease call rate by 10 * rate_scale.\n",
     SIPP_OPTION_FLOAT, &rate, 1},
    {"rp", "Specify the rate period for the call rate.  Default is 1 second and default unit is milliseconds.  This allows you to have n calls every m milliseconds (by using -r n -rp m).\n"
     "Example: -r 7 -rp 2000 ==> 7 calls every 2 seconds.\n         -r 10 -rp 5s => 10 calls every 5 seconds.", SIPP_OPTION_TIME_MS, &rate_period_ms, 1},
    {"rate_scale", "Control the units for the '+', '-', '*', and '/' keys.", SIPP_OPTION_FLOAT, &rate_scale, 1},

    {"rate_increase", "Specify the rate increase every -rate_interval units (default is seconds).  This allows you to increase the load for each independent logging period.\n"
     "Example: -rate_increase 10 -rate_interval 10s\n"
     "  ==> increase calls by 10 every 10 seconds.", SIPP_OPTION_INT, &rate_increase, 1},
    {"rate_max", "If -rate_increase is set, then quit after the rate reaches this value.\n"
     "Example: -rate_increase 10 -rate_max 100\n"
     "  ==> increase calls by 10 until 100 cps is hit.", SIPP_OPTION_INT, &rate_max, 1},
    {"rate_interval", "Set the interval by which the call rate is increased. Defaults to the value of -fd.", SIPP_OPTION_TIME_SEC, &rate_increase_freq, 1},
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
//     {"trace_timeout", "Displays call ids for calls with timeouts in <scenario file name>_<pid>_timeout.log", SIPP_OPTION_SETFLAG, &useTimeoutf, 1},

    {"trace_calldebug", "Dumps debugging information about aborted calls to <scenario_name>_<pid>_calldebug.log file.", SIPP_OPTION_SETFLAG, &useCallDebugf, 1},
    {"calldebug_file", "Set the name of the call debug file.", SIPP_OPTION_LFNAME, &calldebug_lfi, 1},
    {"calldebug_overwrite", "Overwrite the call debug file (default true).", SIPP_OPTION_LFOVERWRITE, &calldebug_lfi, 1},

    {"trace_screen", "Dump statistic screens in the <scenario_name>_<pid>_screens.log file when quitting SIPp. Useful to get a final status report in background mode (-bg option).", SIPP_OPTION_SETFLAG, &useScreenf, 1},
    {"screen_file", "Set the name of the screen file.", SIPP_OPTION_LFNAME, &screen_lfi, 1},
    {"screen_overwrite", "Overwrite the screen file (default true).", SIPP_OPTION_LFOVERWRITE, &screen_lfi, 1},

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

static struct sipp_option *find_option(const char* option) {
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
}

/******************** Recv Poll Processing *********************/

extern unsigned pollnfds;
#ifdef HAVE_EPOLL
extern int epollfd;
extern struct epoll_event*  epollevents;
#endif

extern SIPpSocket  *sockets[SIPP_MAXFDS];

/************** Statistics display & User control *************/

static void sipp_sigusr1(int /* not used */)
{
    /* Smooth exit: do not place any new calls and exit */
    quitting+=10;
}

static void sipp_sigusr2(int /* not used */)
{
    if (!signalDump) {
        signalDump = true;
    }
}

void timeout_alarm(int /*param*/)
{
    if (timeout_error) {
        ERROR("%s timed out after '%.3lf' seconds", scenario_file, ((double)clock_tick / 1000LL));
    }
    quitting = 1;
    timeout_exit = true;
}

/* Send loop & traffic generation*/

static void traffic_thread(int &rtp_errors, int &echo_errors)
{
    /* create the file */
    char L_file_name[MAX_PATH];
    sprintf(L_file_name, "%s_%ld_screen.log", scenario_file, (long) getpid());

    update_clock_tick();

    /* Arm the global timer if needed */
    if (global_timeout > 0) {
        signal(SIGALRM, timeout_alarm);
        alarm(global_timeout / 1000);
    }

    // Dump (to create file on disk) and showing screen at the beginning even if
    // the report period is not reached
    stattask::report();
    screentask::report(false);

    while (1) {
        scheduling_loops++;
        update_clock_tick();

        if (signalDump) {
            /* Screen dumping in a file */
            if (useScreenf == 1) {
                print_screens();
            } else {
                /* If the -trace_screen option has not been set, */
                /* create the file at this occasion              */
                rotate_screenf();
                print_screens();
            }

            if (dumpInRtt) {
                main_scenario->stats->dumpDataRtt();
            }

            signalDump = false;
        }

        while (sockets_pending_reset.begin() != sockets_pending_reset.end()) {
            (*(sockets_pending_reset.begin()))->reset_connection();
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
            /* Quitting and no more opened calls, close all */
            if (!main_scenario->stats->GetStat(CStat::CPT_C_CurrentCall)) {
                /* We can have calls that do not count towards our open-call count (e.g., dead calls). */
                abort_all_tasks();
                rtp_errors = rtpstream_shutdown(main_scenario->fetchRtpTaskThreadIDs());
                echo_errors = main_scenario->stats->getRtpEchoErrors();

                /* Reverse order shutdown, because deleting reorders the
                 * sockets list. */
                for (int i = pollnfds - 1; i >= 0; --i) {
                    sockets[i]->close();
                    if (sockets[i] == ctrl_socket) {
                        ctrl_socket = NULL;
                    } else if (sockets[i] == stdin_socket) {
                        stdin_socket = NULL;
                    }
                }

                screentask::report(true);
                stattask::report();
                if (useScreenf == 1) {
                    print_screens();
                }
                return;
            }
        }

        update_clock_tick();

        /* Schedule all pending calls and process their timers */
        task_list *running_tasks;
        if ((clock_tick - last_timer_cycle) > timer_resolution) {

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
        for (iter = running_tasks->begin(); iter != running_tasks->end(); iter++) {
            if (last) {
                last->run();
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
        if (last) {
            last->run();
        }
        while (sockets_pending_reset.begin() != sockets_pending_reset.end()) {
            (*(sockets_pending_reset.begin()))->reset_connection();
            sockets_pending_reset.erase(sockets_pending_reset.begin());
        }

        update_clock_tick();
        /* Receive incoming messages */
        SIPpSocket::pollset_process(running_tasks->empty());
    }
    assert(0);
}

/*************** RTP ECHO THREAD ***********************/
/* param is a pointer to RTP socket */

static void rtp_echo_thread(void* param)
{
    std::vector<char> msg;
    msg.resize(media_bufsize);
    ssize_t nr, ns;
    sipp_socklen_t len;
    struct sockaddr_storage remote_rtp_addr;
    int sock = *(int *)param;


    int                   rc;
    sigset_t              mask;
    sigfillset(&mask); /* Mask all allowed signals */
    rc = pthread_sigmask(SIG_BLOCK, &mask, NULL);
    if (rc) {
        WARNING("pthread_sigmask returned %d", rc);
        return;
    }

    // timeout after 100ms, to enable graceful termination of the thread
    struct timeval tv = {0, 100000};
    if ((setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) ||
        (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)) {
        WARNING("Cannot set socket timeout. error: %d", errno);
    }

    while (run_echo_thread.load(std::memory_order_relaxed)) {
        len = sizeof(remote_rtp_addr);
        nr = recvfrom(sock, msg.data(), media_bufsize, 0,
                      (sockaddr*)&remote_rtp_addr, &len);

        if (nr < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            WARNING("%s %i",
                    "Error on RTP echo reception - stopping echo - errno=",
                    errno);
            return;
        }
        if (!rtp_echo_state) {
            continue;
        }
        ns = sendto(sock, msg.data(), nr, 0,
                    (sockaddr*)&remote_rtp_addr, len);

        if (ns != nr) {
            WARNING("%s %i",
                    "Error on RTP echo transmission - stopping echo - errno=",
                    errno);
            return;
        }

        if (*(int*)param == media_socket_audio) {
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
static char* wrap(const char* in, int offset, int size)
{
    int pos = 0;
    int i, j;
    int l = strlen(in);
    int alloced = l + 1;
    char* out = (char*)malloc(alloced);
    int indent = 0;

    if (!out) {
        ERROR_NO("malloc");
    }

    for (i = j = 0; i < l; i++) {
        out[j++] = in[i];
        if (in[i] == '\n') {
            out = (char*)realloc(out, alloced += offset);
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
                out = (char*)realloc(out, alloced += useoffset);
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
                out = (char*)realloc(out, alloced += useoffset);
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

/* If stdout is a TTY, wrap stdout in a call to PAGER (generally less(1)).
 * Returns a pid_t you'll have to pass to end_pager(). */
static pid_t begin_pager() {
    char pager[15] = "/usr/bin/pager";
    char *argv[2] = {NULL, NULL};

    int stdout_fd = fileno(stdout);
    int read_write[2];
    pid_t ret;

    if (!isatty(stdout_fd)) {
        return 0;
    }

    /* Get pager first, so we can bail if it's not there */
    argv[0] = getenv("PAGER");
    if (!argv[0]) {
        argv[0] = pager; /* missing PAGER */
    } else if (!*argv[0]) {
        return 0; /* blank PAGER */
    }

    /* Should use euidaccess(3), but requires _GNU_SOURCE */
    if (access(argv[0], X_OK) < 0) {
        perror(argv[0]);
        return 0;
    }

    /* Set up pipes and fork */
    if (pipe(&read_write[0]) < 0) {
        perror("pipe");
        return 0;
    }
    if ((ret = fork()) < 0) {
        perror("fork");
        return 0;
    }

    /* Switch stdout FD in parent */
    if (ret != 0) {
        fflush(stdout);
        close(stdout_fd);
        close(read_write[0]);
        if (dup2(read_write[1], stdout_fd) < 0) {
            perror("dup2");
        } else {
            close(read_write[1]);
        }
        return ret;
    }

    /* Switch stdin FD and start pager in child */
    if (setenv("LESS", "FRX", 1) < 0) {
        perror("setenv");
    }

    close(STDIN_FILENO);
    close(read_write[1]);
    if (dup2(read_write[0], STDIN_FILENO) < 0) {
        perror("dup2");
    } else {
        close(read_write[0]);
    }
    execve(argv[0], argv, environ);

    /* This was not supposed to happen. Missing binary? */
    perror("execve");
    return 0;
}

/* Make sure we flush and close, or the child won't get all the data (and know
 * when we're done). Wait for the child to exit first. */
void end_pager(pid_t pager) {
    fflush(stdout);
    fclose(stdout);
    while (pager != 0) {
        int wstatus;
        if (waitpid(pager, &wstatus, 0) == pager) {
            pager = 0;
        }
    }
}

/* Help screen */
static void help()
{
    int i, max;

    pid_t pager = begin_pager();

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
    max = sizeof(options_table) / sizeof(options_table[0]);
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
        "  253: RTP validation failure\n"
        "   -1: Fatal error\n"
        "   -2: Fatal error binding a socket\n");

    end_pager(pager);
}


static void help_stats()
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

static void print_last_stats()
{
    interrupt = 1;
    if (sp) {
        sp->print_closing_stats();
    }
    if (main_scenario) {
        stattask::report();
    }
}

static void stop_all_traces()
{
    message_lfi.fptr = NULL;
    log_lfi.fptr = NULL;
    dumpInRtt = 0;
    dumpInFile = 0;
}

static void freeInFiles()
{
    for (file_map::iterator file_it = inFiles.begin(); file_it != inFiles.end(); file_it++) {
        delete file_it->second;
    }
}

static void freeUserVarMap()
{
    for (int_vt_map::iterator vt_it = userVarMap.begin(); vt_it != userVarMap.end(); vt_it++) {
        vt_it->second->putTable();
        userVarMap[vt_it->first] = NULL;
    }
}

static void manage_oversized_file(int signum)
{
    FILE *f;
    char L_file_name[MAX_PATH];
    struct timeval currentTime;
    static int managing = 0;

    // we can receive this signal more than once
    if (managing) {
        return;
    }
    managing = 1;

    snprintf(L_file_name, MAX_PATH, "%s_%ld_traces_oversized.log", scenario_file, (long) getpid());
    f = fopen(L_file_name, "w");
    if (!f) {
        ERROR_NO("Unable to open oversized log file");
    }

    GET_TIME(&currentTime);
    fprintf(f,
            "-------------------------------------------- %s\n"
            "Max file size reached - no more logs\n",
            CStat::formatTime(&currentTime));

    fflush(f);
    stop_all_traces();
    print_all_responses = 0;
    error_lfi.fptr = NULL;
}

static void releaseGlobalAllocations()
{
    delete main_scenario;
    delete ooc_scenario;
    delete aa_scenario;
    free_default_messages();
    freeInFiles();
    freeUserVarMap();
    delete userVariables;
    delete globalVariables;
}

void sipp_exit(int rc, int rtp_errors, int echo_errors)
{
    unsigned long counter_value_failed = 0;
    unsigned long counter_value_success = 0;

    /* Some signals may be delivered twice during exit() execution,
       and we must prevent all this from being done twice */

    {
        static int already_exited = 0;
        if (already_exited) {
            return;
        }
        already_exited = 1;
    }

    screen_exit();
    print_last_stats();
    print_errors();
    if (sp) {
        delete sp;
        sp = NULL;
    }

    /* Close open files. */
    struct logfile_info** logfile_ptr;
    struct logfile_info* logfiles[] = {
        &screen_lfi, &calldebug_lfi, &message_lfi, &shortmessage_lfi, &log_lfi, &error_lfi, NULL};
    for (logfile_ptr = logfiles; *logfile_ptr; ++logfile_ptr) {
        if ((*logfile_ptr)->fptr) {
            fclose((*logfile_ptr)->fptr);
            (*logfile_ptr)->fptr = NULL;
        }
    }

    // Get failed calls counter value before releasing objects
    if (display_scenario) {
        counter_value_failed = display_scenario->stats->GetStat(CStat::CPT_C_FailedCall);
        counter_value_success = display_scenario->stats->GetStat(CStat::CPT_C_SuccessfulCall);
    } else {
        rc = EXIT_TEST_FAILED;
    }

    releaseGlobalAllocations();

    if (rc != EXIT_TEST_RES_UNKNOWN) {
        // Exit is not a normal exit. Just use the passed exit code.
        exit(rc);
    } else {
        // Normal exit: we need to determine if the calls were all
        // successful or not. In order to compute the return code, get
        // the counter of failed calls. If there is 0 failed calls,
        // then everything is OK!
        if ((rtp_errors > 0) || (echo_errors > 0))
        {
            exit(EXIT_RTPCHECK_FAILED);
        }
        else
        {
           if (counter_value_failed == 0) {
                if ((timeout_exit) && (counter_value_success < 1)) {
                    exit (EXIT_TEST_RES_INTERNAL);
                } else {
                    exit(EXIT_TEST_OK);
                }
            } else {
                exit(EXIT_TEST_FAILED);
            }
        }
    }
}

static void sipp_sighandler(int signum)
{
    sipp_exit(EXIT_TEST_RES_UNKNOWN, 0, 0);
}

static void sighandle_set()
{
    struct sigaction action_quit = {};
    struct sigaction action_file_size_exceeded = {};

    action_quit.sa_handler = sipp_sighandler;
    action_file_size_exceeded.sa_handler = manage_oversized_file;

    sigaction(SIGTERM, &action_quit, NULL);
    sigaction(SIGINT, &action_quit, NULL);
    sigaction(SIGXFSZ, &action_file_size_exceeded, NULL);  // avoid core dump if the max file size is exceeded
}

static void set_scenario(const char* name)
{
    free(scenario_file);
    free(scenario_path);

    const char* sep = strrchr(name, '/');
    if (sep) {
        ++sep; // include slash
        scenario_path = strndup(name, sep - name);
    } else {
        scenario_path = strdup("");
        sep = name;
    }

    const char* ext = strrchr(sep, '.');
    if (ext && strcmp(ext, ".xml") == 0) {
        scenario_file = strndup(sep, ext - sep);
    } else {
        scenario_file = strdup(sep);
    }
}

static int create_socket(struct sockaddr_storage* media_sa, int try_port, bool last_attempt,
                         const char *type)
{
    int s = socket(media_sa->ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (s == -1) {
        ERROR_NO("Unable to create the %s RTP socket", type);
    }

    if (media_sa->ss_family == AF_INET) {
        (_RCAST(struct sockaddr_in*, media_sa))->sin_port = htons(try_port);
    } else {
        (_RCAST(struct sockaddr_in6*, media_sa))->sin6_port = htons(try_port);
    }

    if (::bind(s, (sockaddr*)media_sa, socklen_from_addr(media_sa)) != 0) {
        if (last_attempt) {
            ERROR_NO("Unable to bind %s RTP socket (IP=%s, port=%d)", type, media_ip, try_port);
        }
        ::close(s);
        return -1;
    }
    return s;
}

/**
 * Create and bind media_socket_audio, media_socket_video for RTP and
 * RCTP on try_port and try_port+2.
 *
 * Sets: media_socket_audio and media_socket_video.
 */
static int bind_rtp_sockets(struct sockaddr_storage* media_sa, int try_port, bool last_attempt)
{
    /* Create RTP sockets for audio and video. */
    media_socket_audio = create_socket(media_sa, try_port, last_attempt, "audio");
    if (media_socket_audio == -1) {
        return -1;
    }

    /* Create and bind the second/video socket to try_port+2 */
    /* (+1 is reserved for RTCP) */
    media_socket_video = create_socket(media_sa, try_port + 2, last_attempt, "video");
    if (media_socket_video == -1) {
        ::close(media_socket_audio);
        media_socket_audio = -1;
        return -1;
    }

    return 0;
}

/**
 * Set a bunch of globals and bind audio and video rtp sockets.
 *
 * Sets: media_ip, media_port, media_ip_is_ipv6, media_socket_audio,
 * media_socket_video.
 */
static void setup_media_sockets()
{
    struct addrinfo hints = {0,};
    struct addrinfo* local_addr;
    struct sockaddr_storage media_sockaddr = {0,};
    int try_counter = 0;
    int max_tries = (min_rtp_port < (max_rtp_port - 2)) ? 100 : 1;

    media_port = min_rtp_port;

    // [JLTAG]
    //
    // RTPCHECK functionality needs port binding to happen only when rtp echo is in use
    // However since the refactoring in commit "99e847e2a129b5e4c4ccfdd502f79a029929ceb9"
    // was done media_ip needs to be set unconditionally so I have moved the media_ip
    // strcpy() to happen outside of the if-block...
    //
    /* Defaults for media sockets */
    if (media_ip[0] == '\0') {
        strcpy(media_ip, local_ip);
    }

    // assert that an IPv6 'media_ip' is not surrounded by brackets?
    //
    hints.ai_flags  = AI_PASSIVE;
    hints.ai_family = PF_UNSPEC; /* use local_ip_is_ipv6 as hint? */

    /* Resolving local IP */
    if (getaddrinfo(media_ip,
                    NULL,
                    &hints,
                    &local_addr) != 0) {
        ERROR("Unknown RTP address '%s'.\n"
              "Use 'sipp -h' for details", media_ip);
    }
    memcpy(&media_sockaddr, local_addr->ai_addr, socklen_from_addr(_RCAST(struct sockaddr_storage*, local_addr->ai_addr)));
    freeaddrinfo(local_addr);

    media_ip_is_ipv6 = (media_sockaddr.ss_family == AF_INET6);

    media_socket_audio = -1;
    media_socket_video = -1;

    if (rtp_echo_enabled) {
        for (try_counter = 1; try_counter <= max_tries; try_counter++) {
            const bool last_attempt = (
                try_counter == max_tries || media_port >= (max_rtp_port - 2));

            if (bind_rtp_sockets(&media_sockaddr, media_port, last_attempt) == 0) {
                break;
            }

            // Old RFC 3551 says:
            // > RTP data SHOULD be carried on an even UDP port number and
            // > the corresponding RTCP packets SHOULD be carried on the
            // > next higher (odd) port number.
            // So, try only even numbers.
            media_port += 2;
        }
    }
}

/* Main */
int main(int argc, char *argv[])
{
    int                  argi = 0;
    pthread_t pthread2_id = 0, pthread3_id = 0;
    bool                 slave_masterSet = false;
    int rtp_errors;
    int echo_errors;

    rtp_errors = 0;
    echo_errors = 0;

    /* At least one argument is needed */
    if (argc < 2) {
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

    pid = getpid();
    memset(local_ip, 0, sizeof(local_ip));
#ifdef USE_SCTP
    memset(multihome_ip, 0, sizeof(multihome_ip));
#endif
    memset(media_ip, 0, sizeof(media_ip));
    memset(control_ip, 0, sizeof(control_ip));

    /* Initialize our global variable structure. */
    globalVariables = new AllocVariableTable(NULL);
    userVariables = new AllocVariableTable(globalVariables);

    /* Command line parsing */
#define REQUIRE_ARG() if ((++argi) >= argc) { \
    ERROR("Missing argument for param '%s'.\nUse 'sipp -h' for details",  argv[argi - 1]); }
#define CHECK_PASS() if (option->pass != pass) { break; }

    for (int pass = 0; pass <= 3; pass++) {
        for(argi = 1; argi < argc; argi++) {
            struct sipp_option *option = find_option(argv[argi]);
            if (!option) {
                if (argv[argi][0] != '-') {
                    if ((pass == 0) && (remote_host[0] != 0)) {
                        ERROR("remote_host given multiple times on command-line (%s and %s)", remote_host, argv[argi]);
                    }
                    strncpy(remote_host, argv[argi], sizeof(remote_host) - 1);
                    continue;
                }
                help();
                ERROR("Invalid argument: '%s'.\n"
                      "Use 'sipp -h' for details", argv[argi]);
            }

            switch(option->type) {
            case SIPP_OPTION_HELP:
                if (argi + 1 < argc && !strcmp(argv[argi + 1], "stat")) {
                    help_stats();
                } else {
                    help();
                }
                exit(EXIT_OTHER);
            case SIPP_OPTION_VERSION:
                printf("\n %s.\n\n",
                       /* SIPp v1.2.3-TLS-PCAP */
                       "SIPp " SIPP_VERSION
#ifdef USE_TLS
                       "-TLS"
#endif
#ifdef USE_SCTP
                       "-SCTP"
#endif
#ifdef PCAPPLAY
                       "-PCAP"
#endif
#ifdef USE_SHA256
                       "-SHA256"
#endif
                       );

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
                *((int*)option->data) = get_long(argv[argi], argv[argi-1]);
                break;
            case SIPP_OPTION_LONG:
                REQUIRE_ARG();
                CHECK_PASS();
                *((long*)option->data) = get_long(argv[argi], argv[argi-1]);
                break;
            case SIPP_OPTION_LONG_LONG:
                REQUIRE_ARG();
                CHECK_PASS();
                *((unsigned long long*)option->data) = get_long_long(argv[argi], argv[argi-1]);
                break;
            case SIPP_OPTION_TIME_SEC:
                REQUIRE_ARG();
                CHECK_PASS();
                *((long*)option->data) = get_time(argv[argi], argv[argi-1], 1000);
                break;
            case SIPP_OPTION_TIME_MS:
                REQUIRE_ARG();
                CHECK_PASS();
                *((int*)option->data) = get_time(argv[argi], argv[argi-1], 1);
                break;
            case SIPP_OPTION_TIME_MS_LONG:
                REQUIRE_ARG();
                CHECK_PASS();
                *((long*)option->data) = get_time(argv[argi], argv[argi-1], 1);
                break;
            case SIPP_OPTION_BOOL:
                REQUIRE_ARG();
                CHECK_PASS();
                *((bool*)option->data) = get_bool(argv[argi], argv[argi - 1]);
                break;
            case SIPP_OPTION_FLOAT:
                REQUIRE_ARG();
                CHECK_PASS();
                *((double*)option->data) = get_double(argv[argi], argv[argi - 1]);
                break;
            case SIPP_OPTION_STRING:
                REQUIRE_ARG();
                CHECK_PASS();
                *((char**)option->data) = argv[argi];
                break;
            case SIPP_OPTION_ARGI:
                REQUIRE_ARG();
                CHECK_PASS();
                *((int*)option->data) = argi;
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
                *((bool*)option->data) = true;
                break;
            case SIPP_OPTION_UNSETFLAG:
                CHECK_PASS();
                *((bool*)option->data) = false;
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
#ifdef USE_TLS
                    transport = T_TLS;
                    if (TLS_init() != 1) {
                        printf("TLS initialization problem\n");
                        exit(-1);
                    }
#else
                    ERROR("To use TLS transport you must compile SIPp with OpenSSL or WolfSSL");
#endif
                    break;
                case 'c':
                    if (strlen(comp_error)) {
                        ERROR("No " COMP_PLUGGIN " plugin available: %s", comp_error);
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
                    break;
                }

                if (peripsocket && transport != T_UDP) {
                    ERROR("You can only use a perip socket with UDP!");
                }
                break;
            case SIPP_OPTION_NEED_SCTP:
                CHECK_PASS();
                ERROR("SCTP support is required for the %s option.", argv[argi]);
                break;
            case SIPP_OPTION_NEED_SSL:
                CHECK_PASS();
                ERROR("TLS support is required for the %s option.", argv[argi]);
                break;
            case SIPP_OPTION_MAX_SOCKET:
                REQUIRE_ARG();
                CHECK_PASS();
                max_multi_socket = get_long(argv[argi], argv[argi - 1]);
                break;
            case SIPP_OPTION_CSEQ:
                REQUIRE_ARG();
                CHECK_PASS();
                base_cseq = get_long(argv[argi], argv[argi - 1]);
                base_cseq--;
                break;
            case SIPP_OPTION_IP: {
                int dummy_port;
                char* ptr = (char*)option->data;
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

                generic[argv[argi - 1]] = argv[argi];
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
                if (slave_masterSet) {
                    ERROR("-3PCC option is not compatible with -master and -slave options");
                }
                if (extendedTwinSippMode) {
                    ERROR("-3pcc and -slave_cfg options are not compatible");
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
                if (main_scenario) {
                    ERROR("Internal error, main_scenario already set");
                } else if (!strcmp(argv[argi - 1], "-sf")) {
                    set_scenario(argv[argi]);
                    if (useLogf == 1) {
                        rotate_logfile();
                    }
                    main_scenario = new scenario(argv[argi], 0);
                    main_scenario->stats->setFileName(scenario_file, ".csv");
                } else if (!strcmp(argv[argi - 1], "-sn")) {
                    int i = find_scenario(argv[argi]);
                    set_scenario(argv[argi]);
                    main_scenario = new scenario(0, i);
                    main_scenario->stats->setFileName(scenario_file, ".csv");
                } else if (!strcmp(argv[argi - 1], "-sd")) {
                    int i = find_scenario(argv[argi]);
                    fprintf(stdout, "%s", default_scenario[i]);
                    exit(EXIT_OTHER);
                } else {
                    ERROR("Internal error, I don't recognize %s as a scenario option", argv[argi] - 1);
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
                    ERROR("Internal error, I don't recognize %s as a scenario option", argv[argi] - 1);
                }
                break;
            case SIPP_OPTION_SLAVE_CFG:
                REQUIRE_ARG();
                CHECK_PASS();
                if (twinSippMode) {
                    ERROR("-slave_cfg and -3pcc options are not compatible");
                }
                extendedTwinSippMode = true;
                slave_cfg_file = new char [strlen(argv[argi]) + 1];
                sprintf(slave_cfg_file,"%s", argv[argi]);
                parse_slave_cfg();
                break;
            case SIPP_OPTION_3PCC_EXTENDED:
                REQUIRE_ARG();
                CHECK_PASS();
                if (slave_masterSet) {
                    ERROR("-slave and -master options are not compatible");
                }
                if (twinSippMode) {
                    ERROR("-master and -slave options are not compatible with -3PCC option");
                }
                *((char**)option->data) = argv[argi];
                slave_masterSet = true;
                break;
            case SIPP_OPTION_RSA: {
                REQUIRE_ARG();
                CHECK_PASS();
                char *remote_s_address;
                int   remote_s_p = DEFAULT_PORT;
                int   temp_remote_s_p;

                temp_remote_s_p = 0;
                remote_s_address = argv[argi];
                get_host_and_port(remote_s_address, remote_s_address, &temp_remote_s_p);
                if (temp_remote_s_p != 0) {
                    remote_s_p = temp_remote_s_p;
                }

                printf("Resolving remote sending address %s...\n", remote_s_address);

                /* FIXME: add DNS SRV support using liburli? */
                if (gai_getsockaddr(&remote_sending_sockaddr, remote_s_address, remote_s_p,
                                    AI_PASSIVE, AF_UNSPEC) != 0) {
                    ERROR("Unknown remote host '%s'.\n"
                          "Use 'sipp -h' for details", remote_s_address);
                }

                use_remote_sending_addr = 1;
                break;
            }
            case SIPP_OPTION_RTCHECK:
                REQUIRE_ARG();
                CHECK_PASS();
                if (!strcmp(argv[argi], "full")) {
                    *((int*)option->data) = RTCHECK_FULL;
                } else if (!strcmp(argv[argi], "loose")) {
                    *((int*)option->data) = RTCHECK_LOOSE;
                } else {
                    ERROR("Unknown retransmission detection method: %s", argv[argi]);
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
                unsigned long *ptr = (unsigned long*)option->data;
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
                        } else if (!strcmp(p, "cseq")) {
                            mask = DEFAULT_BEHAVIOR_BADCSEQ;
                        } else {
                            ERROR("Unknown default behavior: '%s'", token);
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
                ((struct logfile_info*)option->data)->overwrite = get_bool(argv[argi], argv[argi - 1]);
                break;
            case SIPP_OPTION_PLUGIN: {
                int ret;

                REQUIRE_ARG();
                CHECK_PASS();

                void* handle = dlopen(argv[argi], RTLD_NOW);
                if (!handle) {
                    ERROR("Could not open plugin %s: %s", argv[argi], dlerror());
                }

                int (*init)();
                void* funcptr = dlsym(handle, "init");
                /* http://stackoverflow.com/questions/1096341/function-pointers-casting-in-c */
                *reinterpret_cast<void**>(&init) = funcptr; // yuck

                const char* error;
                if ((error = dlerror())) {
                    ERROR("Could not locate init function in %s: %s", argv[argi], error);
                }

                ret = init();
                if (ret != 0) {
                    ERROR("Plugin %s initialization failed.", argv[argi]);
                }
            }
            break;
            default:
                ERROR("Internal error: I don't recognize the option type for %s", argv[argi]);
            }
        }
    }

    /* Load compression plugin if needed/available. */
    if (compression) {
        comp_load();
    }

    if ((extendedTwinSippMode && !slave_masterSet) || (!extendedTwinSippMode && slave_masterSet)) {
        ERROR("-slave_cfg option must be used with -slave or -master option");
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

    /* If no scenario was selected, choose the uac one */
    if (scenario_file == NULL) {
        assert(main_scenario == NULL);
        int i = find_scenario("uac");
        set_scenario("uac");
        main_scenario = new scenario(0, i);
        main_scenario->stats->setFileName(scenario_file, ".csv");
    }

#ifdef USE_TLS
    if ((transport == T_TLS) && (TLS_init_context() != TLS_INIT_NORMAL)) {
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
        rotate_screenf();
    }

    // TODO: finish the -trace_timeout option implementation

    /* if (useTimeoutf == 1) {
       char L_file_name [MAX_PATH];
       sprintf(L_file_name, "%s_%d_timeout.log", scenario_file, getpid());
       timeoutf = fopen(L_file_name, "w");
       if (!timeoutf) {
         ERROR("Unable to create '%s'", L_file_name);
       }
     } */

    if (useCountf == 1) {
        char L_file_name [MAX_PATH];
        sprintf(L_file_name, "%s_%ld_counts.csv", scenario_file, (long) getpid());
        countf = fopen(L_file_name, "w");
        if (!countf) {
            ERROR("Unable to create '%s'", L_file_name);
        }
        print_count_file(countf, 1);
    }

    if (useErrorCodesf == 1) {
        char L_file_name [MAX_PATH];
        sprintf(L_file_name, "%s_%ld_error_codes.csv", scenario_file, (long) getpid());
        codesf = fopen(L_file_name, "w");
        if (!codesf) {
            ERROR("Unable to create '%s'", L_file_name);
        }
    }


    if (dumpInRtt == 1) {
        main_scenario->stats->initRtt(scenario_file, ".csv",
                                      report_freq_dumpRtt);
    }

    if (rate_increase_freq == 0) {
        rate_increase_freq = report_freq_dumpLog;
    }

    // Check the soft limit on the number of open files,
    // error out if this does not allow us to open the
    // required number of signalling channels, and warn
    // if this may not allow enough media channels.
    if (!skip_rlimit) {
        struct rlimit rlimit;
        unsigned max_sockets_needed = multisocket ? max_multi_socket : 1;

        if (getrlimit (RLIMIT_NOFILE, &rlimit) < 0) {
            ERROR_NO("getrlimit error");
        }

        if (max_sockets_needed > rlimit.rlim_cur) {
            ERROR("Maximum number of open sockets (%d) should be less than the maximum number "
                  "of open files (%lu). Tune this with the `ulimit` command or the -max_socket "
                  "option", max_sockets_needed, (unsigned long)rlimit.rlim_cur);
        }

        if ((open_calls_allowed + max_sockets_needed) > rlimit.rlim_cur) {
            WARNING("Maximum number of open sockets (%d) plus number of open calls (%d) "
                    "should be less than the maximum number of open files (%lu) to "
                    "allow for media support. Tune this with the `ulimit` command, "
                    "the -l option or the -max_socket option",
                    max_sockets_needed, open_calls_allowed, (unsigned long)rlimit.rlim_cur);
        }
    }

    /*
    if (!ooc_scenario) {
      ooc_scenario = new scenario(0, find_scenario("ooc_default"));
      ooc_scenario->stats->setFileName((char*)"ooc_default", (char*)".csv");
    }
    */
    display_scenario = main_scenario;
    aa_scenario = new scenario(0, find_scenario("ooc_dummy"));
    aa_scenario->stats->setFileName("ooc_dummy", ".csv");

    init_default_messages();
    for (int i = 1; i <= users; i++) {
        freeUsers.push_back(i);
        userVarMap[i] = new VariableTable(userVariables);
    }

    if (argiFileName) {
        main_scenario->stats->setFileName(argv[argiFileName]);
    }

    // setup option form cmd line
    call::maxDynamicId   = maxDynamicId;
    call::startDynamicId = startDynamicId;
    call::dynamicId      = startDynamicId;
    call::stepDynamicId  = stepDynamicId;


    /* Now Initialize the scenarios. */
    main_scenario->runInit();
    if (ooc_scenario) {
        ooc_scenario->runInit();
    }

    /* In which mode the tool is launched ? */
    main_scenario->computeSippMode();
    if (ooc_scenario && sendMode == MODE_SERVER) {
        ERROR("SIPp cannot use out-of-call scenarios when running in server mode");
    }


    sp = new ScreenPrinter();
    if (!sp->M_headless)
    {
        screen_init();
    }

    sighandle_set();

    /* checking if we need to launch the tool in background mode */
    if (backgroundMode == true) {
        pid_t l_pid;
        switch (l_pid = fork()) {
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
            printf("Background mode - PID=[%ld]\n", (long) l_pid);
            exit(EXIT_OTHER);
        }
    }

    sipp_usleep(sleeptime * 1000);

    /* Create the statistics reporting task. */
    stattask::initialize();
    /* Create the screen update task. */
    screentask::initialize();
    /* Create the rate increase task. */
    ratetask::initialize();
    /* Create a watchdog task. */
    if (watchdog_interval) {
        new watchdog(watchdog_interval, watchdog_reset, watchdog_major_threshold, watchdog_major_maxtriggers, watchdog_minor_threshold, watchdog_minor_maxtriggers);
    }

    /* Setting the rate and its dependent params (open_calls_allowed) */
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

    /* Always create and Bind RTP socket */
    /* to avoid ICMP errors from us. */
    setup_media_sockets();

    /* Creating the remote control socket thread */
    setup_ctrl_socket();

    if (!nostdin) {
        setup_stdin_socket();
    }

    if (rtp_echo_enabled && media_socket_audio > 0) {
        if (pthread_create(&pthread2_id, NULL,
                (void *(*)(void *))rtp_echo_thread, &media_socket_audio) == -1) {
            ERROR_NO("Unable to create RTP echo thread");
        }
    }

    /* Creating second RTP echo thread for video. */
    if (rtp_echo_enabled && media_socket_video > 0) {
        if (pthread_create(&pthread3_id, NULL,
                (void *(*)(void *)) rtp_echo_thread, &media_socket_video) == -1) {
            ERROR_NO("Unable to create video RTP echo thread");
        }
    }

    traffic_thread(rtp_errors, echo_errors);

    /* Cancel and join other threads. */
    run_echo_thread.store(false, std::memory_order_relaxed);
    if (pthread2_id) {
        pthread_join(pthread2_id, NULL);
    }
    if (pthread3_id) {
        pthread_join(pthread3_id, NULL);
    }

#ifdef HAVE_EPOLL
    close(epollfd);
    free(epollevents);
#endif

    free(scenario_file);
    free(scenario_path);
    sipp_exit(EXIT_TEST_RES_UNKNOWN, rtp_errors, echo_errors); // MAIN EXIT PATH HERE...);
}

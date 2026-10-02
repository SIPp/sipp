//! The help, as C SIPp's help() and help_stats() print it: C's
//! options_table, in its order and words, through its wrap().

use std::io::Write;

/// What an option takes after it, for C's first pass over the options.
pub enum Kind {
    /// A section's title.
    Header,
    Help,
    Version,
    /// The number of arguments it takes.
    Args(u8),
    /// An SCTP option in a build without SCTP.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    NeedSctp,
}

/// An option: its name, what it takes and its help text, as C's string
/// literals (none: not in the help).
pub struct Opt(pub &'static str, pub Kind, pub &'static [&'static str]);

use Kind::*;

/// C's options_table, as a C build with SCTP (lksctp) has it on Linux,
/// and without it elsewhere; SO_BINDTODEVICE (-bind_to_device) is Linux's.
pub static OPTIONS: &[Opt] = &[
    Opt("h", Help, &[]),
    Opt("help", Help, &[]),
    Opt("", Header, &["Scenario file options:"]),
    Opt("sd", Args(1), &["Dumps a default scenario (embedded in the SIPp executable)"]),
    Opt("sf", Args(1), &["Loads an alternate XML scenario file.  To learn more about XML scenario syntax, use the -sd option to dump embedded scenarios. They contain all the necessary help."]),
    Opt("rxsf", Args(1), &[
        "Loads an alternate receive xml scenario file as the second scenario - enabling a mixture of originating and terminating calls to be executed.\n",
        "If this is included then the second scenario MUST be a server mode scenario, and the first scenario (specified in -sf / -sn) MUST be a client-mode scenario.\n",
        "If both -rxsf and -rxsn are omitted then only a single scenario is executed.",
    ]),
    Opt("rxsn", Args(1), &["Use a default scenario (embedded in the SIPp executable) as the receive scenario, as -rxsf does with a file."]),
    Opt("oocsf", Args(1), &["Load out-of-call scenario."]),
    Opt("oocsn", Args(1), &["Load out-of-call scenario."]),
    Opt("sn", Args(1), &[
        "Use a default scenario (embedded in the SIPp executable). If this option is omitted, the Standard SipStone UAC scenario is loaded.\n",
        "Available values in this version:\n\n",
        "- 'uac'      : Standard SipStone UAC (default).\n",
        "- 'uas'      : Simple UAS responder.\n",
        "- 'regexp'   : Standard SipStone UAC - with regexp and variables.\n",
        "- 'branchc'  : Branching and conditional branching in scenarios - client.\n",
        "- 'branchs'  : Branching and conditional branching in scenarios - server.\n\n",
        "Default 3pcc scenarios (see -3pcc option):\n\n",
        "- '3pcc-C-A' : Controller A side (must be started after all other 3pcc scenarios)\n",
        "- '3pcc-C-B' : Controller B side.\n",
        "- '3pcc-A'   : A side.\n",
        "- '3pcc-B'   : B side.\n",
    ]),
    Opt("", Header, &["IP, port and protocol options:"]),
    Opt("t", Args(1), &[
        "Set the transport mode:\n",
        "- u1: UDP with one socket (default),\n",
        "- un: UDP with one socket per call,\n",
        "- ui: UDP with one socket per IP address. The IP addresses must be defined in the injection file.\n",
        "- t1: TCP with one socket,\n",
        "- tn: TCP with one socket per call,\n",
        "- l1: TLS with one socket,\n",
        "- ln: TLS with one socket per call,\n",
        "- w1: SIP over WebSocket (WS, RFC 7118) on TCP with one socket,\n",
        "- wn: WS with one socket per call,\n",
        "- x1: SIP over secure WebSocket (WSS) on TLS with one socket,\n",
        "- xn: WSS with one socket per call,\n",
        #[cfg(target_os = "linux")] "- s1: SCTP with one socket,\n",
        #[cfg(target_os = "linux")] "- sn: SCTP with one socket per call,\n",
    ]),
    Opt("i", Args(1), &["Set the local IP address for 'Contact:','Via:', and 'From:' headers. Default is primary host IP address. A host name (remote host, -rsa, setdest) that resolves to several addresses prefers one in the family of the -i address.\n"]),
    Opt("p", Args(1), &["Set the local port number.  Default is a random free port chosen by the system."]),
    Opt("bind_local", Args(0), &["Bind socket to local IP address, i.e. the local IP address is used as the source IP address.  If SIPp runs in server mode it will only listen on the local IP address instead of all IP addresses."]),
    #[cfg(target_os = "linux")]
    Opt("bind_to_device", Args(1), &["Bind socket to the specified network device. Requires superuser permissions."]),
    Opt("ci", Args(1), &["Set the local control IP address"]),
    Opt("cp", Args(1), &["Set the local control port number. Default is 8888."]),
    Opt("max_socket", Args(1), &["Set the max number of call sockets to open simultaneously, if you use one socket per call (-t un, tn, ln). The main, control and stdin sockets don't count. Once this limit is reached, traffic is distributed over the sockets already opened. Default value is 50000"]),
    Opt("max_reconnect", Args(1), &["Set the maximum number of times a connection that fails is made again (-1: no limit). Default is 0."]),
    Opt("reconnect_close", Args(1), &["Should calls be closed on reconnect? If false, they go on on the new connection, which gets what the old one did not take and a request it took with no response yet, as in a failover."]),
    Opt("reconnect_sleep", Args(1), &["How long (in milliseconds) to sleep between the close and reconnect?"]),
    Opt("rsa", Args(1), &["Set the remote sending address to host:port for sending the messages."]),
    Opt("round_robin", Args(0), &["Send each new call to the next address of the remote host, in turn, when its name has several (DNS round robin). They are looked up once, at startup, in the family of the first one, and [remote_ip] is the call's. It needs UDP or one socket per call (-t un, tn, ln...)."]),
    Opt("tls_cert", Args(1), &["Set the name for TLS Certificate file, which may be followed by its intermediate CA certificates. Default is 'cacert.pem'. A client goes without a certificate when neither -tls_cert nor -tls_key is given and neither default file exists"]),
    Opt("tls_key", Args(1), &["Set the name for TLS Private Key file. Default is 'cakey.pem' (see -tls_cert)"]),
    Opt("tls_ca", Args(1), &["Set the name for TLS CA file. If not specified, X509 verification is not activated."]),
    Opt("tls_crl", Args(1), &["Set the name for Certificate Revocation List file. If not specified, X509 CRL is not activated."]),
    Opt("tls_version", Args(1), &["Set the TLS protocol version to use (1.0, 1.1, 1.2, 1.3) -- default is autonegotiate"]),
    Opt("tls_handshake_timeout", Args(1), &["Set how long a TLS handshake may take before its connection is dropped. SIPp handles nothing else meanwhile. 0 means no limit. Default is 10s; default unit is ms."]),
    Opt("ws_path", Args(1), &["Set the path that a WebSocket client (-t w1, wn, x1 or xn) asks for in its handshake. Default is '/'."]),
    Opt("ws_handshake_timeout", Args(1), &["Set how long a WebSocket handshake may take: a client that gets no answer in time, and a server that gets no request, drop the connection. 0 means no limit. Default is 10s; default unit is ms."]),
    #[cfg(target_os = "linux")]
    Opt("multihome", Args(1), &["Set multihome address for SCTP"]),
    #[cfg(target_os = "linux")]
    Opt("heartbeat", Args(1), &["Set heartbeat interval in ms for SCTP"]),
    #[cfg(target_os = "linux")]
    Opt("assocmaxret", Args(1), &["Set association max retransmit counter for SCTP"]),
    #[cfg(target_os = "linux")]
    Opt("pathmaxret", Args(1), &["Set path max retransmit counter for SCTP"]),
    #[cfg(target_os = "linux")]
    Opt("pmtu", Args(1), &["Set path MTU for SCTP"]),
    #[cfg(target_os = "linux")]
    Opt("gracefulclose", Args(1), &["If true, SCTP association will be closed with SHUTDOWN (default).\n If false, SCTP association will be closed by ABORT.\n"]),
    #[cfg(not(target_os = "linux"))]
    Opt("multihome", NeedSctp, &[]),
    #[cfg(not(target_os = "linux"))]
    Opt("heartbeat", NeedSctp, &[]),
    #[cfg(not(target_os = "linux"))]
    Opt("assocmaxret", NeedSctp, &[]),
    #[cfg(not(target_os = "linux"))]
    Opt("pathmaxret", NeedSctp, &[]),
    #[cfg(not(target_os = "linux"))]
    Opt("pmtu", NeedSctp, &[]),
    #[cfg(not(target_os = "linux"))]
    Opt("gracefulclose", NeedSctp, &[]),
    Opt("", Header, &["SIPp overall behavior options:"]),
    Opt("v", Version, &["Display version and copyright information."]),
    Opt("bg", Args(0), &["Launch SIPp in background mode."]),
    Opt("nostdin", Args(0), &["Disable stdin.\n"]),
    Opt("plugin", Args(1), &["Load a plugin."]),
    Opt("lua_file", Args(1), &["Load a Lua file, whose functions <exec lua=\"function arg ...\"/> calls."]),
    Opt("sleep", Args(1), &["How long to sleep for at startup. Default unit is seconds."]),
    Opt("skip_rlimit", Args(0), &["Do not perform rlimit tuning of file descriptor limits.  Default: false."]),
    Opt("buff_size", Args(1), &["Set the send and receive buffer size."]),
    Opt("sendbuffer_warn", Args(1), &["Exit with an error on a failure to send a message SIPp makes itself (such as an automatic answer or an abort's BYE), instead of the default warning."]),
    Opt("lost", Args(1), &["Set the number of packets to lose by default (scenario specifications override this value)."]),
    Opt("key", Args(2), &["keyword value\nSet the generic parameter named \"keyword\" to \"value\"."]),
    Opt("set", Args(2), &["variable value\nSet the global variable parameter named \"variable\" to \"value\"."]),
    Opt("tdmmap", Args(1), &[
        "Generate and handle a table of TDM circuits.\n",
        "A circuit must be available for the call to be placed.\n",
        "Format: -tdmmap {0-3}{99}{5-8}{1-31}",
    ]),
    Opt("dynamicStart", Args(1), &["variable value\nSet the start offset of dynamic_id variable"]),
    Opt("dynamicMax", Args(1), &["variable value\nSet the maximum of dynamic_id variable     "]),
    Opt("dynamicStep", Args(1), &["variable value\nSet the increment of dynamic_id variable"]),
    Opt("", Header, &["Call behavior options:"]),
    Opt("aa", Args(0), &["Enable automatic 200 OK answer for INFO, NOTIFY, OPTIONS and UPDATE."]),
    Opt("base_cseq", Args(1), &["Start value of [cseq] for each call."]),
    Opt("cid_str", Args(1), &["Call ID string (default %u-%p@%s).  %u=call_number, %s=ip_address, %p=process_number, %r=random_integer, %%=% (in any order)."]),
    Opt("cid_type", Args(1), &["Call ID generation mode. Values: default (aliases: format, legacy), uuid, uuid-compact (aliases: uuidcompact, uuid32), random (alias: random-hex), timestamp (alias: time). Modes other than default ignore -cid_str."]),
    Opt("d", Args(1), &["Controls the length of calls. More precisely, this controls the duration of 'pause' instructions in the scenario, if they do not have a 'milliseconds' section. Default value is 0 and default unit is milliseconds."]),
    Opt("deadcall_wait", Args(1), &["How long the Call-ID and final status of calls should be kept to improve message and error logs (default unit is ms)."]),
    Opt("auth_uri", Args(1), &[
        "Force the value of the URI for authentication.\n",
        "By default, the URI is composed of remote_ip:remote_port.",
    ]),
    Opt("au", Args(1), &["Set authorization username for authentication challenges. Default is taken from -s argument"]),
    Opt("ap", Args(1), &["Set the password for authentication challenges. Default is 'password'"]),
    Opt("s", Args(1), &["Set the username part of the request URI. Default is 'service'."]),
    Opt("default_behaviors", Args(1), &[
        "Set the default behaviors that SIPp will use.  Possible values are:\n",
        "- all\tUse all default behaviors\n",
        "- none\tUse no default behaviors\n",
        "- bye\tSend byes for aborted calls\n",
        "- abortunexp\tAbort calls on unexpected messages\n",
        "- pingreply\tReply to ping requests\n",
        "- cseq\tCheck CSeq of ACKs\n",
        "If a behavior is prefaced with a -, then it is turned off.  Example: all,-bye\n",
    ]),
    Opt("nd", Args(0), &[
        "No Default. Disable all default behavior of SIPp which are the following:\n",
        "- On UDP retransmission timeout, abort the call by sending a BYE or a CANCEL\n",
        "- On receive timeout with no ontimeout attribute, abort the call by sending a BYE or a CANCEL\n",
        "- On unexpected BYE send a 200 OK and close the call\n",
        "- On unexpected CANCEL send a 200 OK and close the call\n",
        "- On unexpected PING send a 200 OK and continue the call\n",
        "- On unexpected ACK CSeq do nothing\n",
        "- On any other unexpected message, abort the call by sending a BYE or a CANCEL\n",
    ]),
    Opt("pause_msg_ign", Args(0), &["Ignore the messages received during a pause defined in the scenario "]),
    Opt("callid_slash_ign", Args(0), &["Don't treat a triple-slash in Call-IDs as indicating an extra SIPp prefix."]),
    Opt("", Header, &["Injection file options:"]),
    Opt("rxinf", Args(1), &[
        "Inject values from an external CSV file during calls into the scenarios.\n",
        "First line of this file say whether the data is to be read in sequence (SEQUENTIAL), random (RANDOM), or user (USER) order.\n",
        "Each line corresponds to one call and has one or more ';' delimited data fields. Those fields can be referred as [field0], [field1], ... in the xml scenario file.  Several CSV files can be used simultaneously (syntax: -inf f1.csv -inf f2.csv ...)",
    ]),
    Opt("inf", Args(1), &[
        "Inject values from an external CSV file during calls into the scenarios.\n",
        "First line of this file say whether the data is to be read in sequence (SEQUENTIAL), random (RANDOM), or user (USER) order.\n",
        "Each line corresponds to one call and has one or more ';' delimited data fields. Those fields can be referred as [field0], [field1], ... in the xml scenario file.  Several CSV files can be used simultaneously (syntax: -inf f1.csv -inf f2.csv ...)",
    ]),
    Opt("infindex", Args(2), &["file field\nCreate an index of file using field.  For example -inf ../path/to/users.csv -infindex users.csv 0 creates an index on the first key."]),
    Opt("ip_field", Args(1), &[
        "Set which field from the injection file contains the IP address from which the client will send its messages.\n",
        "If this option is omitted and the '-t ui' option is present, then field 0 is assumed.\n",
        "Use this option together with '-t ui'",
    ]),
    Opt("", Header, &["RTP behaviour options:"]),
    Opt("mi", Args(1), &["Set the local media IP address (default: local primary host IP address)"]),
    Opt("rtp_echo", Args(0), &[
        "Enable RTP echo. RTP/UDP packets received on media port are echoed to their sender.\n",
        "RTP/UDP packets coming on this port + 2 are also echoed to their sender (used for sound and video echo).",
    ]),
    Opt("mb", Args(1), &["Set the RTP echo buffer size (default: 2048)."]),
    Opt("min_rtp_port", Args(1), &["Minimum port number for RTP socket range."]),
    Opt("max_rtp_port", Args(1), &["Maximum port number for RTP socket range."]),
    Opt("mp", Args(1), &["Sets -min_rtp_port for backwards compatibility."]),
    Opt("rtp_payload", Args(1), &["RTP default payload type."]),
    Opt("rtp_threadtasks", Args(1), &["RTP number of playback tasks (calls) per thread (default: 50)."]),
    Opt("rtp_buffsize", Args(1), &["Set the rtp socket send/receive buffer size."]),
    Opt("rtpcheck_debug", Args(0), &["Write RTP check debug information to file"]),
    Opt("srtpcheck_debug", Args(0), &["Write SRTP check debug information to file"]),
    Opt("audiotolerance", Args(1), &["Audio error tolerance for RTP checks (0.0-1.0) -- default: 1.0"]),
    Opt("videotolerance", Args(1), &["Video error tolerance for RTP checks (0.0-1.0) -- default: 1.0"]),
    Opt("random_base_ssrc", Args(0), &["Use a random base SSRC for RTP streams instead of default value 0xCA110000"]),
    Opt("", Header, &["Call rate options:"]),
    Opt("r", Args(1), &[
        "Set the call rate (in calls per seconds).  This value can be",
        "changed during test by pressing '+', '_', '*' or '/'. Default is 10.\n",
        "pressing '+' key to increase call rate by 1 * rate_scale,\n",
        "pressing '-' key to decrease call rate by 1 * rate_scale,\n",
        "pressing '*' key to increase call rate by 10 * rate_scale,\n",
        "pressing '/' key to decrease call rate by 10 * rate_scale.\n",
    ]),
    Opt("rp", Args(1), &[
        "Specify the rate period for the call rate.  Default is 1 second and default unit is milliseconds.  This allows you to have n calls every m milliseconds (by using -r n -rp m).\n",
        "Example: -r 7 -rp 2000 ==> 7 calls every 2 seconds.\n         -r 10 -rp 5s => 10 calls every 5 seconds.",
    ]),
    Opt("rate_scale", Args(1), &["Control the units for the '+', '-', '*', and '/' keys."]),
    Opt("rate_increase", Args(1), &[
        "Specify the rate increase every -rate_interval units (default is seconds).  This allows you to increase the load for each independent logging period.\n",
        "Example: -rate_increase 10 -rate_interval 10s\n",
        "  ==> increase calls by 10 every 10 seconds.",
    ]),
    Opt("rate_max", Args(1), &[
        "If -rate_increase is set, then quit after the rate reaches this value.\n",
        "Example: -rate_increase 10 -rate_max 100\n",
        "  ==> increase calls by 10 until 100 cps is hit.",
    ]),
    Opt("rate_interval", Args(1), &["Set the interval by which the call rate is increased. Defaults to the value of -fd."]),
    Opt("no_rate_quit", Args(0), &["If -rate_increase is set, do not quit after the rate reaches -rate_max."]),
    Opt("l", Args(1), &[
        "Set the maximum number of simultaneous calls. Once this limit is reached, traffic is decreased until the number of open calls goes down. Default:\n",
        "  (3 * call_duration (s) * rate).",
    ]),
    Opt("m", Args(1), &["Stop the test and exit when 'calls' calls are processed"]),
    Opt("m_csv", Args(0), &["Stop the test and exit when as many calls as the first -inf file has lines are processed, e.g. to use each line of a SEQUENTIAL file once."]),
    Opt("users", Args(1), &["Instead of starting calls at a fixed rate, begin 'users' calls at startup, and keep the number of calls constant. With -r, start them at that rate rather than all at once."]),
    Opt("", Header, &["Retransmission and timeout options:"]),
    Opt("recv_timeout", Args(1), &["Global receive timeout. Default unit is milliseconds. If the expected message is not received, the call times out and is aborted."]),
    Opt("send_timeout", Args(1), &["Global send timeout. Default unit is milliseconds. If a message is not sent (due to congestion), the call times out and is aborted."]),
    Opt("timeout", Args(1), &["Global timeout. Default unit is seconds.  If this option is set, SIPp quits after nb units (-timeout 20s quits after 20 seconds)."]),
    Opt("timeout_error", Args(0), &["SIPp fails if the global timeout is reached (-timeout option required)."]),
    Opt("max_retrans", Args(1), &["Maximum number of UDP retransmissions before call ends on timeout.  Default is 5 for INVITE transactions and 9 for others."]),
    Opt("max_invite_retrans", Args(1), &["Maximum number of UDP retransmissions for invite transactions before call ends on timeout."]),
    Opt("max_non_invite_retrans", Args(1), &["Maximum number of UDP retransmissions for non-invite transactions before call ends on timeout."]),
    Opt("nr", Args(0), &["Disable retransmission in UDP mode."]),
    Opt("rtcheck", Args(1), &["Select the retransmission detection method: full (default) or loose."]),
    Opt("T2", Args(1), &["Global T2-timer in milli seconds"]),
    Opt("", Header, &["Third-party call control options:"]),
    Opt("3pcc", Args(1), &[
        "Launch the tool in 3pcc mode (\"Third Party call control\"). The passed IP address depends on the 3PCC role.\n",
        "- When the first twin command is 'sendCmd' then this is the address of the remote twin socket.  SIPp will try to connect to this address:port to send the twin command (This instance must be started after all other 3PCC scenarios).\n",
        "    Example: 3PCC-C-A scenario.\n",
        "- When the first twin command is 'recvCmd' then this is the address of the local twin socket. SIPp will open this address:port to listen for twin command.\n",
        "    Example: 3PCC-C-B scenario.",
    ]),
    Opt("master", Args(1), &["3pcc extended mode: indicates the master number"]),
    Opt("slave", Args(1), &["3pcc extended mode: indicates the slave number"]),
    Opt("slave_cfg", Args(1), &["3pcc extended mode: indicates the file where the master and slave addresses are stored"]),
    Opt("primary", Args(1), &["3pcc extended mode: same as -master"]),
    Opt("secondary", Args(1), &["3pcc extended mode: same as -slave"]),
    Opt("secondary_cfg", Args(1), &["3pcc extended mode: same as -slave_cfg"]),
    Opt("", Header, &["Performance and watchdog options:"]),
    Opt("timer_resol", Args(1), &[
        "Set the timer resolution. Default unit is milliseconds.  This option has an impact on timers precision. ",
        "Small values allow more precise scheduling but impacts CPU usage. ",
        "The default value is 1ms.",
    ]),
    Opt("max_recv_loops", Args(1), &["Set the maximum number of messages received read per cycle. Increase this value for high traffic level.  The default value is 1000."]),
    Opt("max_sched_loops", Args(1), &["Set the maximum number of calls run per event loop. Increase this value for high traffic level.  The default value is 1000."]),
    Opt("watchdog_interval", Args(1), &["Set gap between watchdog timer firings.  Default is 400."]),
    Opt("watchdog_reset", Args(1), &["If the watchdog timer has not fired in more than this time period, then reset the max triggers counters.  Default is 10 minutes."]),
    Opt("watchdog_minor_threshold", Args(1), &["If it has been longer than this period between watchdog executions count a minor trip.  Default is 500."]),
    Opt("watchdog_major_threshold", Args(1), &["If it has been longer than this period between watchdog executions count a major trip.  Default is 3000."]),
    Opt("watchdog_major_maxtriggers", Args(1), &["How many times the major watchdog timer can be tripped before the test is terminated.  Default is 10."]),
    Opt("watchdog_minor_maxtriggers", Args(1), &["How many times the minor watchdog timer can be tripped before the test is terminated.  Default is 120."]),
    Opt("", Header, &["Tracing, logging and statistics options:"]),
    Opt("f", Args(1), &["Set the statistics report frequency on screen. Default is 1 and default unit is seconds."]),
    Opt("trace_stat", Args(0), &["Dumps all statistics in <scenario_name>_<pid>.csv file. Use the '-h stat' option for a detailed description of the statistics file content."]),
    Opt("stat_delimiter", Args(1), &["Set the delimiter for the statistics file"]),
    Opt("stf", Args(1), &["Set the file name to use to dump statistics"]),
    Opt("fd", Args(1), &["Set the statistics dump log report frequency. Default is 60 and default unit is seconds."]),
    Opt("rfc3339", Args(0), &["Use timestamps in RFC3339 format."]),
    Opt("periodic_rtd", Args(0), &["Deprecated and ignored: the statistics file has periodic (P) and cumulative (C) repartition columns."]),
    Opt("trace_msg", Args(0), &["Displays sent and received SIP messages in <scenario file name>_<pid>_messages.log"]),
    Opt("message_file", Args(1), &["Set the name of the message log file."]),
    Opt("message_overwrite", Args(1), &["Overwrite the message log file (default true)."]),
    Opt("trace_shortmsg", Args(0), &["Displays sent and received SIP messages as CSV in <scenario file name>_<pid>_shortmessages.log"]),
    Opt("shortmessage_file", Args(1), &["Set the name of the short message log file."]),
    Opt("shortmessage_overwrite", Args(1), &["Overwrite the short message log file (default true)."]),
    Opt("trace_counts", Args(0), &["Dumps individual message counts in a CSV file."]),
    Opt("trace_err", Args(0), &["Trace all unexpected messages in <scenario file name>_<pid>_errors.log."]),
    Opt("error_file", Args(1), &["Set the name of the error log file."]),
    Opt("error_overwrite", Args(1), &["Overwrite the error log file (default true)."]),
    Opt("trace_error_codes", Args(0), &["Dumps the SIP response codes of unexpected messages to <scenario file name>_<pid>_error_codes.log."]),
    Opt("trace_calldebug", Args(0), &["Dumps debugging information about aborted calls to <scenario_name>_<pid>_calldebug.log file."]),
    Opt("calldebug_file", Args(1), &["Set the name of the call debug file."]),
    Opt("calldebug_overwrite", Args(1), &["Overwrite the call debug file (default true)."]),
    Opt("trace_screen", Args(0), &["Dump statistic screens in the <scenario_name>_<pid>_screens.log file when quitting SIPp. Useful to get a final status report in background mode (-bg option)."]),
    Opt("screen_file", Args(1), &["Set the name of the screen file."]),
    Opt("screen_overwrite", Args(1), &["Overwrite the screen file (default true)."]),
    Opt("trace_rtt", Args(0), &["Allow tracing of all response times in <scenario file name>_<pid>_rtt.csv."]),
    Opt("rtt_freq", Args(1), &["freq is mandatory. Dump response times every freq calls in the log file defined by -trace_rtt. Default value is 200."]),
    Opt("trace_logs", Args(0), &["Allow tracing of <log> actions in <scenario file name>_<pid>_logs.log."]),
    Opt("log_file", Args(1), &["Set the name of the log actions log file."]),
    Opt("log_overwrite", Args(1), &["Overwrite the log actions log file (default true)."]),
    Opt("ringbuffer_files", Args(1), &["How many error, message, shortmessage and calldebug files should be kept after rotation?"]),
    Opt("ringbuffer_size", Args(1), &["How large should error, message, shortmessage and calldebug files be before they get rotated?"]),
    Opt("max_log_size", Args(1), &["What is the limit for error, message, shortmessage and calldebug file sizes."]),
];

const HEADER: &str = concat!(
    "\n",
    "Usage:\n",
    "\n",
    "  sipp remote_host[:remote_port] [options]\n",
    "  sipp\n",
    "\n",
    "  A remote_host name given without a port is looked up with DNS NAPTR\n",
    "  and SRV records first (RFC 3263), for the transport of -t.\n",
    "\n",
    "Example:\n",
    "\n",
    "   Launch the interactive startup wizard from an interactive terminal:\n",
    "     ./sipp\n",
    "   Run SIPp with embedded server (uas) scenario:\n",
    "     ./sipp -sn uas\n",
    "   On the same host, run SIPp with embedded client (uac) scenario:\n",
    "     ./sipp -sn uac 127.0.0.1\n",
    "\n",
    "  Available options:\n",
    "\n",
);

const FOOTER: &str = concat!(
    "\n\nSignal handling:\n",
    "\n",
    "   SIPp can be controlled using POSIX signals. The following signals\n",
    "   are handled:\n",
    "   USR1: Similar to pressing the 'q' key. It triggers a soft exit\n",
    "         of SIPp. No more new calls are placed and all ongoing calls\n",
    "         are finished before SIPp exits.\n",
    "         Example: kill -SIGUSR1 732\n",
    "   USR2: Triggers a dump of all statistics screens in\n",
    "         <scenario_name>_<pid>_screens.log file. Especially useful \n",
    "         in background mode to know what the current status is.\n",
    "         Example: kill -SIGUSR2 732\n",
    "\n",
    "Exit codes:\n",
    "\n",
    "   Upon exit (on fatal error or when the number of asked calls (-m\n",
    "   option) is reached, SIPp exits with one of the following exit\n",
    "   code:\n",
    "    0: All calls were successful\n",
    "    1: At least one call failed\n",
    "   97: Exit on internal command. Calls may have been processed\n",
    "   99: Normal exit without calls processed\n",
    "  253: RTP validation failure\n",
    "   -1: Fatal error\n",
    "   -2: Fatal error binding a socket\n",
);

/// help_stats(): "-h stat".
pub const STATS: &str = concat!(
    "\n",
    "  The  -trace_stat option dumps all statistics in the\n",
    "  <scenario_name.csv> file. The dump starts with one header\n",
    "  line with all counters. All following lines are 'snapshots' of \n",
    "  statistics counter given the statistics report frequency\n",
    "  (-fd option). This file can be easily imported in any\n",
    "  spreadsheet application, like Excel.\n",
    "\n",
    "  In counter names, (P) means 'Periodic' - since last\n",
    "  statistic row and (C) means 'Cumulative' - since SIPp was\n",
    "  started.\n",
    "\n",
    "  Available statistics are:\n",
    "\n",
    "  - StartTime: \n",
    "    Date and time when the test has started.\n",
    "\n",
    "  - LastResetTime:\n",
    "    Date and time when periodic counters were last reset.\n",
    "\n",
    "  - CurrentTime:\n",
    "    Date and time of the statistic row.\n",
    "\n",
    "  - ElapsedTime:\n",
    "    Elapsed time.\n",
    "\n",
    "  - CallRate:\n",
    "    Call rate (calls per seconds).\n",
    "\n",
    "  - IncomingCall:\n",
    "    Number of incoming calls.\n",
    "\n",
    "  - OutgoingCall:\n",
    "    Number of outgoing calls.\n",
    "\n",
    "  - TotalCallCreated:\n",
    "    Number of calls created.\n",
    "\n",
    "  - CurrentCall:\n",
    "    Number of calls currently ongoing.\n",
    "\n",
    "  - SuccessfulCall:\n",
    "    Number of successful calls.\n",
    "\n",
    "  - FailedCall:\n",
    "    Number of failed calls (all reasons).\n",
    "\n",
    "  - FailedCannotSendMessage:\n",
    "    Number of failed calls because SIPp cannot send the\n",
    "    message (transport issue).\n",
    "\n",
    "  - FailedMaxUDPRetrans:\n",
    "    Number of failed calls because the maximum number of\n",
    "    UDP retransmission attempts has been reached.\n",
    "\n",
    "  - FailedUnexpectedMessage:\n",
    "    Number of failed calls because the SIP message received\n",
    "    is not expected in the scenario.\n",
    "\n",
    "  - FailedCallRejected:\n",
    "    Number of failed calls because of SIPp internal error.\n",
    "    (a scenario sync command is not recognized, a scenario\n",
    "    action failed or a scenario variable assignment failed).\n",
    "\n",
    "  - FailedCmdNotSent:\n",
    "    Number of failed calls because of inter-SIPp\n",
    "    communication error (a scenario sync command failed to\n",
    "    be sent).\n",
    "\n",
    "  - FailedRegexpDoesntMatch:\n",
    "    Number of failed calls because of regexp that doesn't\n",
    "    match (there might be several regexp that don't match\n",
    "    during the call but the counter is increased only by\n",
    "    one).\n",
    "\n",
    "  - FailedRegexpShouldntMatch:\n",
    "    Number of failed calls because of regexp that shouldn't\n",
    "    match but does (there might be several regexp that shouldn't match\n",
    "    during the call but the counter is increased only by\n",
    "    one).\n",
    "\n",
    "  - FailedRegexpHdrNotFound:\n",
    "    Number of failed calls because of regexp with 'hdr'\n",
    "    option but no matching header found.\n",
    "\n",
    "  - OutOfCallMsgs:\n",
    "    Number of SIP messages received that cannot be associated\n",
    "    to an existing call.\n",
    "\n",
    "  - AutoAnswered:\n",
    "    Number of unexpected specific messages received for new Call-ID.\n",
    "    The message has been automatically answered by a 200 OK\n",
    "    Currently, implemented for 'NOTIFY', 'INFO' and 'PING' messages.\n",
    "\n",
);

/// find_option(): an option given with '-' or "--". A section's title,
/// named "" there, is no option ("-" and "--" are not one).
pub fn find(arg: &str) -> Option<&'static Opt> {
    let name = arg.strip_prefix('-')?;
    let name = name.strip_prefix('-').unwrap_or(name);
    OPTIONS.iter().find(|o| !matches!(o.1, Header) && o.0 == name)
}

/// C's isspace(), in the C locale.
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// wrap(): a help text with a line longer than size characters broken
/// at its last space, or a word longer than a line where the line ends,
/// and the lines after the first indented by offset spaces, two more in
/// an item starting with '-'. As C's, its count of a line included.
pub fn wrap(input: &str, offset: usize, size: usize) -> Vec<u8> {
    let inp = input.as_bytes();
    let mut out = Vec::with_capacity(inp.len());
    // Where the text of the current line starts.
    let (mut line, mut pos, mut indent) = (0, 0, false);
    for (i, &c) in inp.iter().enumerate() {
        out.push(c);
        if c == b'\n' {
            out.resize(out.len() + offset, b' ');
            line = out.len();
            pos = 0;
            indent = inp.get(i + 1) == Some(&b'-');
        }
        pos += 1;
        if pos <= size {
            continue;
        }
        let mut newline = vec![b' '; 1 + offset + if indent { 2 } else { 0 }];
        newline[0] = b'\n';
        let mut k = out.len() - 1;
        while k > line && !is_space(out[k]) {
            k -= 1;
        }
        if k > line {
            // At the last space: the rest goes to the next line.
            out.splice(k..=k, newline.iter().copied());
            line = k + newline.len();
            pos = out.len() - line + 1;
        } else {
            // A word longer than a line: broken before this character.
            let at = out.len() - 1;
            out.splice(at..at, newline.iter().copied());
            line = out.len() - 1;
            pos = 2;
        }
    }
    out
}

/// help()'s text.
pub fn text() -> Vec<u8> {
    let mut out = HEADER.as_bytes().to_vec();
    for Opt(name, kind, help) in OPTIONS {
        if help.is_empty() {
            continue;
        }
        let formatted = wrap(&help.concat(), 22, 77);
        match kind {
            Header => out.extend_from_slice(b"\n*** "),
            _ => out.extend_from_slice(format!("   -{name:<16}: ").as_bytes()),
        }
        out.extend_from_slice(&formatted);
        out.extend_from_slice(if matches!(kind, Header) { b"\n\n" } else { b"\n" });
    }
    out.extend_from_slice(FOOTER.as_bytes());
    out
}

/// help(): the help on stdout, through a pager when it is a terminal.
pub fn print() {
    let text = text();
    #[cfg(unix)]
    if let Some(mut pager) = pager() {
        if let Some(mut stdin) = pager.stdin.take() {
            let _ = stdin.write_all(&text);
        }
        let _ = pager.wait();
        return;
    }
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(&text);
    let _ = stdout.flush();
}

/// begin_pager(): $PAGER, or the first of pager, less and more in
/// /usr/bin that can be run, with LESS=FRX; none for an empty $PAGER.
/// $PAGER is a file, run as it is, without arguments or a $PATH search.
#[cfg(unix)]
fn pager() -> Option<std::process::Child> {
    use std::ffi::OsString;
    use std::io::IsTerminal;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::process::CommandExt;
    if !std::io::stdout().is_terminal() {
        return None;
    }
    let mut options: Vec<OsString> = ["/usr/bin/pager", "/usr/bin/less", "/usr/bin/more"].map(OsString::from).into();
    if let Some(env) = std::env::var_os("PAGER") {
        if env.is_empty() {
            return None;
        }
        options = vec![env];
    }
    let strerror = |e: i32| unsafe { std::ffi::CStr::from_ptr(libc::strerror(e)) }.to_string_lossy().into_owned();
    let runnable = |o: &OsString| {
        let path = std::ffi::CString::new(o.as_bytes()).ok()?;
        (unsafe { libc::access(path.as_ptr(), libc::X_OK) } == 0).then_some(())
    };
    let Some(path) = options.iter().find(|o| runnable(o).is_some()) else {
        // A $PAGER that is not there is said.
        if options.len() == 1 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            crate::raw::eprintln(&format!("{}: {}", crate::raw::from_os(options[0].clone()), strerror(e)));
        }
        return None;
    };
    // execve(): the file itself, where Command looks a bare name up.
    let mut file = std::path::PathBuf::from(path);
    if !path.as_bytes().contains(&b'/') {
        file = std::path::Path::new(".").join(path);
    }
    let _ = std::io::stdout().flush();
    let spawned = std::process::Command::new(file).arg0(path).env("LESS", "FRX").stdin(std::process::Stdio::piped()).spawn();
    spawned.map_err(|e| crate::raw::eprintln(&format!("execve: {}", strerror(e.raw_os_error().unwrap_or(0))))).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_breaks_as_c() {
        // What C's wrap() gives.
        let wrap = |t: &str, offset, size| String::from_utf8(wrap(t, offset, size)).unwrap();
        assert_eq!(wrap("Load out-of-call scenario.", 22, 77), "Load out-of-call scenario.");
        assert_eq!(wrap("short\nline", 4, 20), "short\n    line");
        // At the last space past the size, the next line indented.
        assert_eq!(wrap(&"a ".repeat(40), 22, 77), format!("{}a\n{}a ", "a ".repeat(38), " ".repeat(22)));
        // 2 more under a line starting with '-'.
        let b = "b ".repeat(10);
        let b = b.trim_end();
        assert_eq!(wrap(&format!("x\n- {}", "b ".repeat(40)), 4, 20), format!("x\n    - {}\n      {b}\n      {b}\n      {b}\n      b ", "b ".repeat(9).trim_end()));
        // C's tests.
        assert_eq!(wrap("abc def ghi", 2, 10), "abc def\n  ghi");
        assert_eq!(wrap("abc\n- def ghi jkl", 2, 10), "abc\n  - def ghi\n    jkl");
        // A word longer than a line: broken where the line ends.
        let x = "x".repeat(80);
        assert_eq!(wrap(&x, 22, 77), format!("{}\n{}xxx", &x[..77], " ".repeat(22)));
        assert_eq!(wrap(&"x".repeat(25), 2, 10), "xxxxxxxxxx\n  xxxxxxxxx\n  xxxxxx");
        let x9 = "x".repeat(9);
        assert_eq!(wrap(&format!("a {}", "x".repeat(25)), 2, 10), format!("a\n  {x9}\n  {x9}\n  xxxxxxx"));
    }

    #[test]
    fn find_as_c() {
        assert!(matches!(find("-h").map(|o| &o.1), Some(Help)));
        assert!(matches!(find("--help").map(|o| &o.1), Some(Help)));
        assert!(matches!(find("--key").map(|o| &o.1), Some(Args(2))));
        assert!(find("-").is_none() && find("--").is_none() && find("h").is_none() && find("-nope").is_none());
    }

    #[test]
    fn help_sections() {
        let text = String::from_utf8(text()).unwrap();
        assert!(text.starts_with("\nUsage:\n"));
        assert!(text.contains("\n*** Scenario file options:\n\n   -sd              : Dumps a default scenario"));
        assert!(text.ends_with("   -2: Fatal error binding a socket\n"));
    }
}

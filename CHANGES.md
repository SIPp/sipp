# Changelog

All notable changes to SIPp are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Changes that may break existing scenarios, command lines or builds are
marked **Breaking**.

## [Unreleased]

### Added

- Several dialogs in a call: `dialog="N"` on `<send>` and `<recv>`, each
  dialog with its own Call-ID, `[cseq]`, peer tag, route set and
  [last_*] keywords; a request with a Call-ID no call has starts a
  dialog of the call waiting for it (#2, by Orgad Shaneh)
- Server transactions: `<recv request start_txn>` keeps the request and
  `<send response_txn>` answers it, with the [last_*] keywords of that
  request, after other requests came; a retransmission of it gets the
  last response sent in it again (#12, by Orgad Shaneh)
- `-round_robin` sends the calls to the addresses of a remote host name
  in turn, over UDP or one socket per call (#33, by Orgad Shaneh)
- A remote host name given without a port is looked up with DNS NAPTR
  and SRV records (RFC 3263) for the transport of `-t`, at startup
  (#117, by Orgad Shaneh)
- SIP over WebSocket (RFC 7118), with no extra library: `-t w1` and `wn`
  over TCP, `-t x1` and `xn` over TLS, with `-ws_path` and
  `-ws_handshake_timeout` (#1028, by Orgad Shaneh, based on #817 by
  Emmanuel Buu)
- Digest authentication with MD5-sess, SHA-256-sess, SHA-512-256 and
  SHA-512-256-sess (RFC 7616), to answer a challenge and in
  `<verifyauth>` (#1004). Of several challenges, the first one with an
  algorithm SIPp supports is answered (#965) (by Orgad Shaneh)
- The AES_192_CM and AES_256_CM SRTP suites of RFC 6188 (#1024, by Orgad
  Shaneh)
- `rtp_stream` plays files over SRTP, as a client and as a server (#974,
  #1007, by Orgad Shaneh)
- `<exec rtp_stream="wait"/>` holds the next message until the playback
  ends, with an optional `timeout` (#1049, by Orgad Shaneh)
- `<exec verify="command"/>` runs a command that the call waits for
  before its next message, without blocking SIPp, and fails the call
  if it exits with a non-zero code (#7, by Orgad Shaneh, based on #423
  by Stanislav Litvinenko)
- `<rtp_stats>` assigns the RTP packets a call received, and the payload
  type and payload of the first, to variables: a scenario can check a
  ringback (#256, by Orgad Shaneh)
- `play_pcap_text` plays a real-time text (RFC 4103) capture to the
  port of the `m=text` line (#403, by Orgad Shaneh)
- `<rtp_dtmf>` assigns the RFC 4733 DTMF digits a call received to a
  variable (#407, by Orgad Shaneh)
- `<recv timeout_variable>` takes the receive timeout from a call
  variable (#968, by Orgad Shaneh)
- `start_rtd` and `rtd` take a comma-separated list of timers (#970, by
  Orgad Shaneh)
- `-m_csv` stops after as many calls as the first `-inf` file has lines
  (#971, by Orgad Shaneh)
- `-users` with `-r` ramps the calls up at the rate (#972, by Orgad
  Shaneh)
- `-rxsn`, a built-in scenario as the receive scenario (#925, by Orgad
  Shaneh)
- `-tls_handshake_timeout`, 10 s by default (#941, by Orgad Shaneh)
- `play_dtmf` takes a payload type after the tone length:
  `play_dtmf="123,200,101"` (#976, by Orgad Shaneh)
- `-primary`, `-secondary` and `-secondary_cfg` as aliases of `-master`,
  `-slave` and `-slave_cfg` (#973, by Orgad Shaneh)
- Keywords in a keyword's parameters, such as
  `[authentication username=[field0] password=[field1]]` (#963, by Orgad
  Shaneh)
- `[last_From.value]`, a header's value without its name, as in
  `To: [last_From.value]` (#132, by Orgad Shaneh)
- A TLS client runs without a certificate when none is given or found
  (#1015, by Orgad Shaneh, based on #601 by Stefan Mititelu)
- `regress/runtests` runs the tests in parallel, each in a network
  namespace of its own (#1017, by Orgad Shaneh)
- With `-max_reconnect` and `-reconnect_close false`, a call goes on
  when its connection fails over, to the backup of a proxy say: what it
  could not send, and a request that the old connection lost without a
  response, go on the new connection. Over TLS too, whose failed writes
  now make the connection again as over TCP (#782, by Orgad Shaneh)

### Changed

- **Breaking:** Numbers in options and scenarios are decimal, or hex
  with `0x`: a leading `0` no longer means octal, and empty, malformed
  or out-of-range values are errors rather than 0 (#1066, by Orgad
  Shaneh)
- **Breaking:** `<ereg search_in="hdr">` matches a header name only at
  the start of a line: `header="To"` no longer finds `X-Forward-To:`
  (#982, by Orgad Shaneh)
- **Breaking:** A fatal error before the scenario loads, such as a bad
  option, exits with 255 as documented, not 1 (#934, by Orgad Shaneh)
- **Breaking:** AKAv1-MD5 checks the MAC over the AMF of the challenge's
  AUTN; `aka_AMF` is ignored (#1013, by Orgad Shaneh)
- **Breaking:** The `-trace_stat` file has periodic (P) and cumulative
  (C) columns for each ResponseTimeRepartition and CallLengthRepartition
  range; `-periodic_rtd` is deprecated and ignored (#19, by Orgad
  Shaneh)
- Default for `-rtp_threadtasks` (media calls per thread) raised from 20
  to 50 (#1116, by Orgad Shaneh)
- pcap play runs in the RTP playback threads, not in a thread per play,
  and audio and video play at the same time. On Linux it sends on
  `IPPROTO_RAW` sockets, and plays start on multiples of 20 ms (#1005,
  #1111, #1113, by Orgad Shaneh)
- Memory and CPU per call are much lower, after 3.7 had raised them
  far above 3.6: at 12000 calls/s the built-in UAS peaks at 164 MB,
  against 1162 MB in 3.7.8 and 282 MB in 3.6.1, and 10000 calls playing
  media take 74 MB, against 220 MB in 3.7.8 and 31 MB in 3.6.1. The
  built-in UAC and UAS keep up with 26000 calls/s, where they fell
  behind and failed calls from 24000. SRTP no longer repeats its AES and
  HMAC setup for each packet, its media threads keep only the session
  keys, and it encrypts with AES-CTR: 5000 SRTP echo calls take a fifth
  less CPU and a quarter less memory. A header is read in one pass
  over the message, where it is, rather than copied for each lookup,
  messages are built without temporary strings, a socket read keeps
  only what it got rather than 64 KB, a Call-ID is found in a hash
  table rather than a tree, RTP makes fewer system calls per packet,
  reading echoes with recvmmsg(), idle playback tasks wake together, and
  the socket loop and RTP echo wait with epoll (#1110, #1117, #1118,
  #1119, #1122-#1131, #1230, #1232-#1234, #1247, by Orgad Shaneh)
- A pass over the calls ends after 10 ms and runs the calls that resume
  first, so a burst of new calls no longer leaves incoming messages
  unread for seconds (#1101), and the call rate starts with the traffic,
  not before the setup (#1000) (by Orgad Shaneh)
- TLS waits for the socket instead of sleeping 200 ms on each
  WANT_READ/WANT_WRITE, which delayed every new connection (#888, by
  Orgad Shaneh)
- Host names resolve to an address of the family of `-i` (#986, by Orgad
  Shaneh)
- A response to a retransmitted request is resent as it was first sent
  (#1025, by Orgad Shaneh)
- A failed RTP check says which patterns failed and why SIPp exits with
  253 (#1019, #1059, by Orgad Shaneh, based on #600 by Stefan Mititelu)
- `-max_socket` counts only the call sockets (#1069, by Orgad Shaneh)
- CMake fails when a requested optional library is missing (#1107, by
  Orgad Shaneh)
- A response goes where the request it answers came from, matched by
  its top Via branch: a request from another address or connection
  than the call's destination, such as a BYE after a proxy fails over,
  is answered there instead of at the destination. `-rsa` still sends
  every message to its address (#240, by Orgad Shaneh)

### Fixed

- Crashes and memory errors (by Orgad Shaneh):
  - buffer overflows when building messages and credentials, in
    rtp_echo and rtp_stream arguments, in long `-i`, `-mi`, `-ci`,
    `-multihome`, `-3pcc` and log file name arguments, in the file names
    made from a long scenario name, and in the AES_192_CM and AES_256_CM
    crypto keywords (#883, #905, #963, #997, #1068, #1147, #1164, #1165,
    #1215)
  - a heap overflow in the help's wrapping of a word longer than a line
    (#1240)
  - use-after-free when another thread hits a fatal error (#885), on TCP
    reconnection (#935, #1175), when one of SIPp's own messages fails to
    send (#991), in an `<ereg search_in="var">` that assigns to the
    variable it searches (#1145), and in a `~user/` path (#1163)
  - crashes with a Call-ID held by a dead call (#943), in 3PCC (#927,
    #944), on a final response to an INVITE repeated before its ACK
    (#942), with over 1024 RTP sockets (#999), with both an `rtp_stream`
    file and pattern (#1003), with `-trace_rtt` in `-rxsf` and `-oocsf`
    calls (#1039), on an option error with `-trace_counts` (#1037), on an
    SRTP key of the wrong length (#1038), on SCTP multihoming (#1092),
    on a response without a blank line after its headers with a pcap
    play (#1138), on a `<label>` without an id in `<init>` (#1158), and
    on `trace <log> on` after `off` with `-ringbuffer_files` (#1156)
  - reads of uninitialized memory in an `<ereg search_in="body">` of a
    message without a body (#1146), in `[server_ip]` when getsockname()
    fails (#1148), and of the sockets of an rtp_stream whose local port
    failed (#1141)
  - a read of the byte before a message that starts with a newline, when
    its Call-ID or To tag is looked up (#1231)
  - a read past the buffer of an `<ereg search_in="hdr">` with 2049 or
    more bytes of the message after the header name, which also cut a
    header longer than 2048 characters (#1254)
  - null strings printed in the actions screen for an `<ereg>` on the
    body or a variable, and in the error of a `<recv>` without request
    or response, and a play_pcap `[keyword]` looked up unterminated
    (#1235)
  - heap corruption when SIGTERM, SIGINT or `-timeout_error` interrupted
    a malloc (#1042, #1052), and a SIGXFSZ handler that wrote a log and
    dropped the trace files unclosed (#1216)
  - data races between the calls and the RTP threads (#977, #1108,
    #1140)
  - memory and socket leaks (#886, #945, #1018)
  - a crash at the end of a call with `-srtpcheck_debug` when its debug
    file can't be created (#1213)
- SIP (by Orgad Shaneh):
  - a late provisional response (#909), a request retransmitted after
    two responses (#910) and a repeated ACK (#911) no longer abort the
    call, and a retransmitted request gets the response to it (#1026)
  - the BYE of an aborted call has the right From, To, CSeq and branch,
    and is sent whatever the mode (#981, #1080, #1081)
  - a message that arrives before a `<nop>` or `<sendCmd>` has run, or a
    command before the SIP message awaited, is kept for the next step
    (#892, #1016, #1077; #1016 based on #664 by @dmbhatti)
  - `-aa` answers an OPTIONS before a UAS's first call, counts it once
    and matches the method whole (#983, #1023, #1083)
  - a call that ends on an answered PING leaves the current calls (#916)
  - a failed check or `stop_call` in any step ends the call as it does
    in a `<recv>` (#1076)
  - a dead call no longer warns about the answers to its BYE or CANCEL,
    nor takes a live call's Call-ID (#984, #1008)
  - a header folded on several lines keeps its CRLFs in the [last_*]
    keywords, rather than going out with a bare LF (#1211)
- Transports (by Orgad Shaneh):
  - TCP: connections close with their last call and are freed once the
    peer closes them (#886, #987), a reset of an accepted connection is
    survived (#988), a refused or reset write resets the connection
    (#1086), and a call whose connection closes before its timewait no
    longer fails (#889)
  - reconnection: failed and refused connections, socket options, lost
    buffered messages and setdest descriptors, and a 3PCC twin socket
    in a TLS run (#1011, #1091, #1095, #1096, #1097, #1168; #1011 based
    on #611 by Alex Rodikov)
  - UDP: `-t un` without `-i` (#937), setdest on a `-t un` call (#939),
    `-max_socket` reuse (#936), `[local_port]` (#923, #938), and an
    `-ip_field` address that does not resolve fails the call rather than
    binding the default address (#1151), and two names of an `-ip_field`
    address share its socket rather than failing to bind it twice (#1212)
  - TLS: intermediate certificates are sent (#940), a handshake that
    arrives in pieces completes (#951), TLS 1.0 and 1.1 work with
    OpenSSL 3 (#990), a verified client can resume its session (#1045),
    calls work with wolfSSL (#1033), a failed handshake drops only its
    peer (#941, #996), and a read that wants more data no longer warns
    (#1032)
  - SCTP: shutdown, refused associations, an association the peer
    aborts (#1226), 3PCC and peer parameters
    (#1088, #1089, #1090, #1093)
  - 3PCC: twin connection resets and losses, the body's last CRLF, and
    a scenario with only `<sendCmd>` and `<recvCmd>` (#969, #985, #1084,
    #1085)
  - `-t` refuses a value that is not a transport and socket mode (#1246)
- RTP, SRTP and pcap play (by Orgad Shaneh):
  - rtp_echo runs per call, so overlapping calls no longer stop or
    re-key each other's echo; it echoes plain RTP, whole packets and from
    the first packet, without spinning, and counts no echo that failed
    to go out (#895, #897, #903, #904, #979, #1001, #1022, #1041, #1109,
    #1139)
  - each stream goes to the c= address of its own media section (#1137),
    and rtp_stream and pcap play take a host name in `-mi` (#1181)
  - SRTP keys are per call (#1002), and crypto lines are parsed per
    media section, with UNENCRYPTED_SRTP, key lifetimes, MKIs, NULL
    suites and a start above sequence number 32768 (#893, #894, #900,
    #1029, #1050, #1051), also with wolfSSL (#1031)
  - SRTP offer/answer: a call without media takes the crypto lines it
    receives (#1178), and an answer handled in `_unexp.main` no longer
    counts as an offer too (#1176)
  - a server's `rtp_stream` pattern goes out over SRTP when its answer
    has keys, as a file does (#1227)
  - an SDP is found with a Content-Type in any case or with parameters
    (`application/sdp;charset=utf-8`), and one sent counts as an offer
    or answer without `[len]` (#1250)
  - the RTP check checks each call's pattern, and a pattern never echoed
    fails (#1021, #1073, #1074)
  - packets go out on time: audio beside video, `play_dtmf` and pcap
    pacing, a play starts at once (#896, #906, #908, #1100, #1102)
  - a paused `rtp_stream` resumes at once, with the timestamp of the
    packet time it resumes in, rather than sending the packet before it
    and the current one together (#1228)
  - the RTCP socket is kept (#898), WAV chunk sizes and short files are
    read right (#902, #1075), a WAV file with no audio no longer hangs
    the playback thread (#1144), a missing `rtp_stream` file fails the
    load again (#975), and `play_dtmf` clears the reserved bit and checks
    its value at load (#907, #992)
  - pcap: each packet's link header is read and IPv6 extension headers
    are skipped (#1072), the `-mp` port is used when the SDP lacks
    `[media_port]` (#978), SDP port counts and TTLs are parsed (#961),
    and a refused m= line (port 0) is skipped as rtp_stream does (#1157)
  - with `-srtpcheck_debug` or `-rtpcheck_debug`, a debug file that
    can't be created is warned about, and rtp_echo and rtp_stream go on
    without it (#1225)
- `rtp_stream` mixes a multi-channel WAV file down to mono, plays only
  its data chunk, and plays files over 2 GB (#863, by Orgad Shaneh,
  based on #864 by Raja amirapu)
- Authentication (by Orgad Shaneh): AKAv1-MD5 with short keys and `0x`
  keys (#926, #964), `-sess` algorithms no longer taken for the plain
  ones (#966), a cnonce of 64 random bits rather than one guessable
  `rand()` value (#1162), and a challenge's opaque, qop and header
  answered whole, not cut at 63, 15 and 2048 characters, as are long
  values in `<verifyauth>` and `-auth_uri` (#1252)
- Scenarios and keywords (by Orgad Shaneh):
  - each scenario's `<init>` runs, `-rxsf`'s too, with call number 0 and
    no line of a SEQUENTIAL `-inf` file (#924, #1078, #1079, #1087)
  - string variables work in `<pause variable>` and arithmetic (#959)
  - `[media_port]` outside a message line (#960), keyword offsets (#1010),
    `\x` escapes (#1061), PRINTF keys (#1063), unknown `-cid_str`
    conversions (#1064), `<urldecode>` of a lone `%` (#912), and the
    uniform distribution's range (#922)
  - scenario load errors name an unknown distribution and find an empty
    CDATA (#1009)
  - sipp.dtd declares what the parser accepts (#662, by Renato Costallat;
    #933, #1012)
  - `[dynamic_id]` goes back to `-dynamicStart` without overflowing an
    int (#1242)
  - an `<ereg search_in="msg">` of a `<send>` searches the message sent
    also after an `<assignstr>`, `<log>` or other action that makes a
    text (#1248)
  - a response's method comes from its CSeq header, in any case, not
    from the first "CSeq" anywhere in the message (#1249)
- Options, statistics and screens (by Orgad Shaneh):
  - `-timeout` fires to the millisecond (#1053), `-nd` works on
    big-endian hosts (#915), and `-tdmmap` frees each call's circuit and
    tries every circuit (#932, #1070)
  - trace files: `-trace_rtt` microseconds (#918), `-trace_shortmsg`
    with `-rfc3339` (#919), `-trace_stat` standard deviation of a single
    call (#1034), `-trace_counts` for `<nop>` (#993), `-trace_screen`
    on every exit (#1055), buffered messages in `-trace_msg` (#1035),
    and the whole SIGUSR2 dump (#957)
  - logs: `-X_overwrite` without `-X_file` no longer fails with "Unable
    to create ''" (#1179), `trace messages on` turns the messages log
    back on (#1174), and a ring buffer log that fails to rotate is kept
    (#1172)
  - an error in the options reaches the `-trace_err` log wherever
    `-trace_err` is on the command line (#1243)
  - an error in the options is timed in RFC 3339, with its UTC offset,
    wherever `-rfc3339` is on the command line (#1245)
  - a `~/` path expands from USERPROFILE when there is no HOME (#1173)
  - `sipp -` and `sipp --` are an invalid argument, not an internal
    error (#1237)
  - screens: periods, rates, times and padding (#920, #921, #928, #929,
    #931, #958, #1056, #1057, #1058)
  - a pager that can't be run no longer leaves a second SIPp printing
    the help (#1241)
  - uniform pauses and `-lost` keep the per-process random seed (#956),
    and `<exec command>` keeps stdin non-blocking (#955)
  - the scenario options take `--`, as the others do (#1238)
  - messages and warnings: a fatal error is printed once, logs opened
    before the scenario loads are named after sipp, variable names, and
    spurious epoll and shutdown warnings, and an unknown `~user` in one
    line (#913, #914, #930, #989, #995, #1054, #1065, #1071, #1180)
  - help texts of `-max_retrans`, `-sendbuffer_warn` and `-timer_resol`,
    and no `-rxrn`, which never worked (#917, #967, #1229, #1239)
  - a remote host or `-slave_cfg` host over 254 characters is refused
    rather than cut short (#1214)
- Documentation and tests (by Orgad Shaneh): the docs build with current
  Sphinx (#949), exit codes, media ports and receive timeouts are
  documented (#950, #952, #953), CONTRIBUTING.md says what makes a PR
  mergeable (#954), and the regress tests run on BSD and macOS (#946,
  #947, #948)

## [3.7.9] - 2026-09-30

### Fixed

- Attribute values are XML-decoded once again, as before 3.7.8, so
  `&amp;lt;` gives `&lt;` (#1062, #1098, by Orgad Shaneh)
- A memory leak in every MD5 digest, since 3.7.8 (#884, by Orgad Shaneh)
- AKAv1-MD5 with wolfSSL lost the last byte of a padded nonce, since
  3.7.8 (#1014, by Orgad Shaneh)
- Configuring without GTest failed, since 3.7.8 (#891, by Orgad Shaneh)
- CMake takes any boolean for `USE_SYSTEM_PUGIXML` and
  `USE_SYSTEM_GTEST`, such as the Fedora package's `1` (#1060, by Peter
  Lemenkov)
- Building with GCC 16: the bundled pugixml is updated to 1.16 (#1047,
  by Orgad Shaneh)

## [3.7.8] - 2026-09-23

### Added

- `-cid_type` selects a built-in Call-ID generator: `uuid`,
  `uuid-compact`, `random` or `timestamp`. The default keeps using
  `-cid_str` (#869, by Darwvin)
- An interactive wizard that builds a command line when SIPp is started
  without arguments on a terminal (#868, by Darwvin)
- `sipp-multi.py`, a helper that starts and supervises several SIPp
  instances described in a CSV file (#873, by Darwvin)
- CMake `USE_SYSTEM_GTEST` builds the unit tests against a system-wide
  GTest (#836, by Peter Lemenkov)
- clang-format configuration and CONTRIBUTING.md (#855, by Peter Lemenkov)

### Changed

- **Breaking:** The scenario XML parser is now pugixml. It is bundled as
  a git submodule (clone with `--recursive`), or taken from the system
  with `-DUSE_SYSTEM_PUGIXML=ON`. Scenario files are no longer limited
  to 64 KB (#858, by Peter Lemenkov)
- Timing uses `std::chrono` (#854, by Peter Lemenkov)

### Removed

- **Breaking:** SIPp's bundled MD5, AKA and base64 code. Building now
  requires OpenSSL (1.1.1 or later) or wolfSSL (#827, #828, #842, by
  Peter Lemenkov)
- The `-c` compression plugin option, for which no plugin was ever
  distributed (#853, by Peter Lemenkov)

### Fixed

- Every call with `-t t1`, `tn`, `l1` or `ln` failed with "Unable to bind
  TCP socket": the 3.7.0 `[local_port]` fix for TCP and TLS is reverted
  (#830, by Orgad Shaneh)
- The BYE of an aborted call follows the dialog's route set (#851, by
  Daniel Donoghue)
- SDP is found in multipart/mixed message bodies (#862, by Mark T)
- Heap-use-after-free when a UDP retransmission fails to send (#876, by
  Orgad Shaneh)
- `get_header()` writes are bounded by its buffer (#881, by Peter Lemenkov)
- Use-after-free and no-op bugs when clearing maps (#839, by Peter Lemenkov)
- Data race in the debug files (#859, by Peter Lemenkov)
- RTP debug dumps of several sessions (#848, by Orgad Shaneh)
- An infinite loop in the build with the bundled gtest (#845, by Orgad
  Shaneh)

## [3.7.7] - 2025-12-30

### Fixed

- Const-correctness of an argument that is modified (#826, by Peter
  Lemenkov)

## [3.7.6] - 2025-12-22

### Added

- `%r` in `-cid_str` inserts a random number, for unique Call-IDs when
  several instances run in parallel (#810, by Maksim Nesterov)
- The `sipp` executable exports its symbols, so that plugins can use
  them (#820, by Orgad Shaneh)

### Changed

- **Breaking:** Building requires a C++17 compiler (by Orgad Shaneh)
- Bundled gtest updated to 1.17 (by Orgad Shaneh)

### Fixed

- SRTP: a buffer overrun and a missing null termination when parsing
  received crypto lines, and mis-parsing of a long input line (#822, by
  Orgad Shaneh)
- The `-trace_logs` file name (by Orgad Shaneh)

## [3.7.5] - 2025-08-19

### Added

- Enable a mixture of server-mode and client-mode operation simultaneously (by Matthew Briggs)
- Support for regexp matching on response codes (by Petr Cisar)
- Support RFC3339 timestamp format and timezone offset (by Costis)
- Send the SNI in the TLS client hello (#754, by Jean-Christophe Grondin)
- Replay raw IP pcap files (#763, by Jérôme Poulin)
- Seed the random generator with the host name and PID too, so that
  instances started together differ (#738, by FalacerSelene)
- A Debian-based Dockerfile (#759, by Orgad Shaneh)

### Fixed

- Out-of-bounds read on invalid XML (#747, by Orgad Shaneh)
- `<nop>` overrides the last action result only if it is a failure
  (#766, by Tolga)
- Fix RTPCHECK functionality regressions (by Jeannot Langlois)
- Fix SRTPCheck testing on unlimited number of calls (by Michal Hajek)
- Use random SSRC for SRTP instead of hardcoded value (by Orgad Shaneh)
- Fix RTPStream crash on thread exit and reduce mutex scope (by Orgad Shaneh)
- Fix memory leaks and file handle leaks (by Orgad Shaneh)
- Fix CSV reports to use fixed precision for floats (by Costis)
- Fix quit behavior to properly terminate (by Orgad Shaneh)
- Mark aborted calls as failed (by Orgad Shaneh)
- Various stability and build fixes (by Orgad Shaneh, Jaco Kroon, Michal Hajek)

## [3.7.4] - 2024-09-10

### Fixed

- Build with wolfSSL (by Orgad Shaneh)
- Docker: update Alpine to 3.20 and fix the version resolving (#749, by
  Orgad Shaneh)

## [3.7.3] - 2024-08-07

### Added

- SHA-256 Digest authentication (RFC 8760) (#676, by Marat Gareev)
- TLS 1.3 (#695, by Orgad Shaneh)
- `-bind_to_device` option (#630, by Ivan Gankevich)
- Comfort noise (audio/CN) media support (#687, by Rafael Vargas)
- TLS verification without a CRL file (#663, by Ivan Ribakov)
- Random SSRC for RTP streams (#599, by Stefan Mititelu)
- `hide` and `display` attributes (#718, by Michael Stovenour)
- A define to use local IP hints (#598, by Stefan Mititelu)
- pcap file paths that start with `~` (#607, by Rajesh Singh)

### Changed

- Bundled gtest updated to 1.14.0; building requires C++14 and CMake 3.5
  (#649, #651, by Orgad Shaneh)

### Removed

- **Breaking:** Remove support for variables in PCAP filenames, originally introduced in 3.7.0. See #673

### Fixed

- Recovered `-mp` and `[auto_media_port]` to maintain backwards compatibility (by Orgad Shaneh)
- Fix crash when using PCAP play with more than one call (by Pete O'Neill)
- Fix pager on macOS by trying less and more too (by Walter Doekes)
- `[next_url]` could return garbage (#724, by Michael Stovenour)
- rtp_stream failed to bind on macOS, and CRLF in injection files (#729,
  by Zac He)
- rtpstream local port allocation (#734, by viktike), and the next RTP
  port was always reset to the minimum (#635, by Stefan Mititelu)
- The RTP playback thread blocked on `select()` (#690, by Shona McNeill)

## [3.7.2] - 2023-11-16

### Fixed

- Remove excessive log

## [3.7.1] - 2023-05-19

### Fixed

- Correctly open the control socket
- The SIPp binary can now be built even when the `gtest` checkout is missing
- rtpstream files are now also found next to the scenario. If it is not found there, it will be treated as a relative path as usual.

## [3.7.0] - 2023-04-02

### Added

- RTPstream can now handle .wav files with a WAV header (by Orgad Shaneh)

### Fixed

- RTPCHECK stability fixes (by Jeannot Langlois)
- Support CRLF-format injection files (by Orgad Shaneh)
- Fix to [next_url] when a display name is present in the contact (by enneig)
- Add 'transport' to the Contact header for UAC scenarios (by Martin Flaska)
- Update built-in scenarios to Copy Record-Route from INVITE to 200OK to comply with RFC 3261 (by kadabusha)
- Fix for local_port keyword using TCP or TLS (by Felippe Silvestre)
- Correct handling of IMS-AKA RES values containing null bytes (by Sergey Zyrianov)
- Fix potential overwrite of auth value when calculating auth (by ZhaohuiLiu)
- Diagnostics improvements:
  - Print, rather than lose, any buffered response time data on exit (by Orgad Shaneh)
  - Add the IPs and remote address family to 'Network family mismatch' log  (by Rob Day)
  - Print OpenSSL error reason when certificate load fails (by Rajesh Singh)
  - Give clear error if multiple command-line parameters are being interpreted as remote_host
- Prevent clock_tick moving backwards (and getting behind wheel_base and causing an assert) (by Rob Day)
- Ensure that sockets are marked as non-blocking before OpenSSL calls are made (by Rob Day)
- Prevent RTPStream crash due to a thread ID of 0 (by Rob Day)
- Cygwin, FreeBSD and Hurd build fixes (by Orgad Shaneh, kadabusha and Zopolis4)
- Static build fixes (by  Aaron Meriwether)

## [3.7.0-rc1] - 2021-10-26

### Added

- B2BUA Media Gateway RTP/SRTP bit pattern testing -- see
  `docs/rtpcheck_xml_syntax_reference.pdf`. Command line examples:
    ```
    # UAS (RTP)
    ./sipp -m 1 -sf sipp_scenarios/pfca_uas.xml \
      -i 127.0.0.3 -t u1 -p 5060 -rtp_echo

    # UAC (RTP)
    ./sipp -m 1 -sf sipp_scenarios/pfca_uac_apattern.xml \
      -t u1 -i 127.0.0.2 -p 5060 127.0.0.3:5060
    ```
    ```
    # UAS (audio SRTP)
    ./sipp -m 1 -sf sipp_scenarios/pfca_uas_audio_crypto_simple.xml \
      -t u1 -i 127.0.0.3 -p 5060 -srtpcheck_debug

    # UAC (audio SRTP)
    ./sipp -m 1 -sf sipp_scenarios/pfca_uac_apattern_crypto_simple.xml \
      -t u1 -i 127.0.0.2 -p 5060 -rtpcheck_debug -srtpcheck_debug \
      127.0.0.3:5060
    ```
  By Jeannot Langlois.
- URL encode/decode `<action>` for scenarios (by Jérôme Poulin).
- Variables in the rtpstream/pcap filenames (by Orgad Shaneh).
- WolfSSL/WolfCrypt library support (as alternative to OpenSSL, by
  Thomas Uhle).

### Removed

- Removed `-mp` in favor of `-min_rtp_port` and `-max_rtp_port`. Also
  removed `[auto_media_port]`. There are way too many (conflicting)
  options to specify ports here.

### Fixed

- Documentation updates. Code cleanups. Build fixes. (By Walter Doekes,
  Thomas Uhle, ChanderG, Lin Sun, Markus Goetzl, Rob Day, Stefan
  Mititelu, Orgad Shaneh, Karn Saheb).
- Fix socket/tcp refcount/order issue (by Orgad Shaneh).
- Fix timezone in [date] on FreeBSD (by kadabusha).
- Track auto-answered messages as a visible counter rather than an error
  log (by Rob Day).
- Unconditionally show index in scenario screen (by Rob Day).

## [3.6.2-rc1] - 2021-10-25

### Removed

- Remove RTP\_STREAM define. The code is always included. (By Orgad Shaneh.)

### Fixed

- Fix crash when abusing authentication method (#503, by Markus).
- Fix crash when trying to change an unset ooc scenario (#463, by
  @jquinn60137).
- Fix various build issues with CMake and/or missing version.h and/or
  compiler warnings. By Walter Doekes, by Silver Chan, Thomas Uhle,
  Orgad Shaneh.
- Various minor documentation fixes. By Walter Doekes, kadabusha, Thomas
  Uhle, Alexander Traud.

## [3.6.1] - 2020-09-16

### Changed

- **Breaking:** CMake is now used as build environment: autoconf and friends are gone
  (#430, by Rob Day (@rkday)). See `build.sh` for CMake invocations.
  For a full build, do:
    ```
    cmake . -DUSE_GSL=1 -DUSE_PCAP=1 -DUSE_SSL=1 -DUSE_SCTP=1
    make -j4
    ```
- Make it easier to deal with large SIP packets by adding an optional
  `-DSIPP_MAX_MSG_SIZE=262144` to the `cmake` command (#422, by Cody Herzog
  (@codyherzog)).

### Fixed

- Consistently unescape XML attributes when loading scenario (#458, by
  Steve Frécinaux (@nud)).
- Fix buffer overflow in screen output (#479, reported by @brettowe).
- Fix nonce count in auth headers (#421, by Cody Herzog (@codyherzog)).
- Fix parser warning when trying to access 0-byte SDP body (by Lin Sun
  (@sunlin7)).
- Fix pcapplay on FreeBSD (#434, by Rob Day (@rkday)).
- Improve build validation (#424, by Stanislav Litvinenko (@dolk13)), a
  few compiler fixes, a few ncurses fixes (including #436, reported by
  @TamerL), build cleanup after CMake (#443, #442, by Orgad Shaneh
  (@orgads)) and libtinfo linker issues (Jeannot Langlois
  (@jeannotlanglois)).
- Improve provided sipp.dtd file (#425, by David M. Lee (@leedm777)),
  and XML fixes by Rob Day.

## [3.6.0] - 2019-06-18

### Added

- Add `play_dtmf` code originally from
  https://sourceforge.net/p/sipp/patches/50/ (Dmitry Kunilov), then
  pull #82 (@horacimacias) and then #141 (@vodik). Compile with
  pcap-play support, and use it by adding `<exec play_dtmf="1234*#"/>`
  similar to how you use `play_pcap_audio`.
  - Add RTP payload 96 in your SDP:
    m=audio [media_port] RTP/AVP 0 96 97
    a=rtpmap:0 PCMU/8000
    a=rtpmap:96 telephone-event/8000
    a=fmtp:96 0-15
    a=rtpmap:97 no-op/8000
  - Exec syntax is `<exec play_dtmf="digits[,length]"/>` where digits
    can be one or more of "0123456789#*ABCD" and length defaults to 200
    and must be between 50 and 2000.
  - Instead of digits a `[field...]` keyword is also accepted.
  - Make sure you add enough `<pause/>` after `play_dtmf`.
- Add `rtp_echo` action (pull #259 by Snom Technology). Compile with
  `--with-rtpstream` and use it by adding `<rtp_echo value="0">` to stop
  the RTP echo enabled via `-rtp_echo`. RTP echo can be restarted via
  `<rtp_echo value="1">` action. Usage example in `regress/github-#0259/uas.xml`
- Added the required constants for G722 (payload 9) and iLBC at 30ms per frame
  to rtp\_stream media actions. (PR #366, by Jasper Hafkenscheid @hafkensite.)
- Add quick and dirty detection of invalid XML (issue #322).
- Added PAGER by default to the extremely large sipp help output.

### Changed

- **Breaking:** Automatic filenames (trace files, error files, etc..) are now created in
  the current working directory instead of in the directory of the scenario
  file. (Issue #399, reported by @sergey-safarov.)
- **Breaking:** Only validates SSL certificate if CA-file is separately specified!
  (PR #335, by Patrick Wildt @bluerise.)
- **Breaking:** Angle brackets `<` and `>` need to be escaped inside XML attributes.
  See #414. So, not `regexp="<(sip:.*)>"` but `regexp="&lt;(sip:.*)&gt;"`.
- Clarify that `-infindex` should takes a basename only (issue #395, reported
  by @sergey-safarov).

### Removed

- Removed unused RTPStream code concerning video streams. Also
  consolidated the rtpstream audio port usage to reuse the global
  `[media_port]` instead of the `[rtpstream_audio_port]`.
  Also the `-min_rtp_port` and `-max_rtp_port` options have been
  removed. Advantages: cleaner code, fewer scenario variables.
  Drawbacks: possible ICMP port unreachable messages for RCTP and video.
  Also, no easy way to discern different streams if you want to bombard
  a single UAS with multiple RTP streams. (Issue #192, reported by
  @atsakiridis.)

### Fixed

- Fix `[routes]` header in UAS scenario's. (Issue #262, reported by
  Stefan Mititelu (@smititelu).)
- last\_Keyword does not search in SIP body anymore (#207, reported by Zoltan).

## [3.5.3] - 2019-06-18

### Fixed

- Fix `[routes]` header in UAS scenario's. (Issue #262, reported by
  Stefan Mititelu (@smititelu).)
  (Backported from b6c7b209 from 3.6.)
- Fix bad Content-Length calculation when whitespace was between the CRLF
  pairs that separate the body. (Issue #337, fixed by Serg Stetsuk
  (@sergstetsuk)).
- Fix crash in pcap play on send failure because of pthread\_cleanup macros.
  (Issue #74, #370, reported by various people.)

## [3.5.2] - 2018-07-13

### Changed

- Document `search_in="hdr"` test.
- Also test without `HAVE_EPOLL`.

### Fixed

- Build issues:
  - Improve ncurses/gsl detection and linkage on various platforms.
    (Issue #205, #271, #275, reported by Paul Malpass, AlexB, Leon Roy,
    Victor Seva.)
  - Fix compile issues on old CentOS and Solaris. (Issue #211, #245, #252,
    reported by sjthomason, mscdex.)
  - Fix newer openssl detection. (Issue #302, #304, #315, #328.)
  - Recompile entire source after a reconfigure.
  - Reduce confusion when someone downloads a tag from git instead of the tar.gz
    with the autogenerated files and valid version.h (#270, reported by AlexB).
  - Remove hardcoded build datetime from binary, for "reproducible builds".
    (#286, by Victor Seva.)
  - Replace underscore in tag-name with tilde, for debian-style "~rc1" version
    suffix.
- Handle Contact header with extra angle brackets ('<...>') outside of the
  uri-parameters (in the contact-params). The contact params should not be
  used in the `next_url`. (Issue #234, reported by Justin Zimmer.)
- Fix TLS issues for during high load. (Issue #241, #243, reported by sgel83,
  and fixes by Rob Day.)
- Fix problem with `get_inet_address` on FreeBSD (#331, reported by tsgan.)
- Retry video RTP bind if port is taken (#276, thanks Corey Farrell).

## [3.5.1] - 2016-03-17

### Fixed

- Fix qop-value in authorization Digest. It can only hold a single value
  (auth, auth-int, ...) and does not take double quotes, in contrast to
  the challenge. Some servers returned a 400 upon receiving this.
  (Issue #191, reported by @artlov.)
- Fix compile error on Cygwin. (Issue #193, reported by @Gankarloo.)

## [3.5.0] - 2016-02-08

### Added

- Clean up source code, fix typo's, alter warning and error messages,
  fix pedantic coding style. Add gtest framework and tests. Add regression
  tests. Fix and improve build scripts (see also: `build.sh`).
- Use better timing with `clock_gettime` (or `clock_get_time` on OSX).
- Don't complain about the dummy variable `_` being used only once.
- Ignore 4x NUL keepalive (next to ignoring the CRLF CRLF keepalive).
- Add `[date]` keyword.
- Add `-trace_screen` option to log screen output in a file.
- Add `-rate_increase` option to increase load periodically.
- Add `-callid_slash_ign` to disable the magic triple slash behaviour.a
- Alter `-aa` to also reply to OPTIONS.
- Allow replaying pcaps with `LINUX_SLL`, `EN10MB` and 802.11 (and ratiotap)
  link layer types. Handle 802.1Q tagged frames.
- Allow starting SIPp without a TERM setting (a "working" terminal).
- Allow m=image in SDP to pcapplay faxes/images.
- `<exec play_pcap_audio="..."/>` and friends:
  - If the argument is not an absolute path, the pcap is searched next
    to the scenario, before falling back to checking the current
    working directory.
  - The argument may be enclosed in brackets, in which case it is
    interpreted as a keyword value; set through the `-key` command line
    option. Example: `<exec play_pcap_audio="[file1]"/>` with option
    `-key file1 /path/to/pcap`.

### Fixed

- Start SDP search in body instead of in header. Fix IPv6 media address in SDP.
- Allow single CR and single LF in SDP.
- Don't confuse cnonce with nonce, improve other auth parsing.
- Don't abort SIPp if the To header is missing.
- Fixes to XML parser; improve `get_peer_tag` behaviour.
- Fix jump recursion crashes.
- Fix a few (potential) memory leaks and dangerous code.
- Remove a few autogenerated files from tree (configure, manpage).
- Fix digest calculation when `qop` is given.

## [3.4.1] - 2014-03-09

Not documented here.

[Unreleased]: https://github.com/SIPp/sipp/compare/v3.7.8...HEAD
[3.7.9]: https://github.com/SIPp/sipp/releases/tag/v3.7.9
[3.7.8]: https://github.com/SIPp/sipp/releases/tag/v3.7.8
[3.7.7]: https://github.com/SIPp/sipp/releases/tag/v3.7.7
[3.7.6]: https://github.com/SIPp/sipp/releases/tag/v3.7.6
[3.7.5]: https://github.com/SIPp/sipp/releases/tag/v3.7.5
[3.7.4]: https://github.com/SIPp/sipp/releases/tag/v3.7.4
[3.7.3]: https://github.com/SIPp/sipp/releases/tag/v3.7.3
[3.7.2]: https://github.com/SIPp/sipp/releases/tag/v3.7.2
[3.7.1]: https://github.com/SIPp/sipp/releases/tag/v3.7.1
[3.7.0]: https://github.com/SIPp/sipp/releases/tag/v3.7.0
[3.7.0-rc1]: https://github.com/SIPp/sipp/releases/tag/v3.7.0_rc1
[3.6.2-rc1]: https://github.com/SIPp/sipp/releases/tag/v3.6.2_rc1
[3.6.1]: https://github.com/SIPp/sipp/releases/tag/v3.6.1
[3.6.0]: https://github.com/SIPp/sipp/releases/tag/v3.6.0
[3.5.3]: https://github.com/SIPp/sipp/releases/tag/v3.5.3
[3.5.2]: https://github.com/SIPp/sipp/releases/tag/v3.5.2
[3.5.1]: https://github.com/SIPp/sipp/releases/tag/v3.5.1
[3.5.0]: https://github.com/SIPp/sipp/releases/tag/v3.5.0
[3.4.1]: https://github.com/SIPp/sipp/releases/tag/v3.4.1

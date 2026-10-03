# sipp-rs

A port of SIPp to Rust that behaves like C SIPp: the same options,
scenarios, messages, logs, screens and exit codes, over UDP, TCP, TLS,
SCTP and WebSocket. It interoperates with C SIPp in both directions.

```sh
cargo build --release
./target/release/sipp-rs -sn uas -i 127.0.0.2 &
./target/release/sipp-rs 127.0.0.2 -sn uac -i 127.0.0.1 -m 100 -r 50
./interop.sh /path/to/c/sipp          # sipp-rs <-> C SIPp, UDP and TCP, both ways
./regress.sh                          # SIPp's own regression tests, none skipped
```

The version is C SIPp's: `git describe --tags --always --first-parent` of
the checkout when it is built (`SIPp v3.7.8-457-g068818c1-rs-TLS...` in
`-v`), else the `SIPP_VERSION` of a release tarball's `include/version.h`,
else the crate's. `[sipp_version]` drops the `v`, as C does.

## What it does

- **Scenario steps:** `<send>` (`retrans`, `start_txn`, `ack_txn`,
  `ontimeout` when the retransmissions run out; `timeout` is taken, as
  sends never block), `<recv>` (`request`/`response`, `optional`, `regexp_match`,
  `response_txn`, `rrs`, `timeout`/`timeout_variable`/`ontimeout`, `optional="global"`,
  `advance_state`, `ignoresdp`), `<recvCmd optional>`,
  `<pause>` and `<timewait>` (`milliseconds`, `variable`, or a distribution: fixed,
  uniform, normal, lognormal, exponential, weibull, pareto, gpareto,
  gamma, negbin), `<nop>`, `hide`/`hiderest` and `<label>`, with a
  `_unexp.main` label for unexpected messages. `<xi:include href>`
  puts in the commands of another file, relative to the including one.
- **Flow control:** `next`, `test` and `chance` on every step, and
  `condexec`/`condexec_inverse`.
- **Actions:** `<ereg>` (search_in msg/body/hdr/var, `check_it`,
  `start_line`, `occurrence`), `<assign>`, `<assignstr>`, `<add>`,
  `<subtract>`, `<multiply>`, `<divide>`, `<sample>`, `<todouble>`,
  `<index>`, `<jump>`, `<pauserestore>`, `<gettimeofday>`, `<strcmp>`,
  `<test>`, `<trim>`, `<urlencode>`, `<urldecode>`, `<lookup>`,
  `<insert>`, `<replace>`, `<setdest>`, `<closecon>`, `<log>`,
  `<warning>`, `<error>`, and `<exec command>` / `<exec verify>` /
  `<exec lua>` / `<exec int_cmd>`.
  Regexps (`<ereg>`, `regexp_match`) are the C library's POSIX extended
  ones, as SIPp compiles them: the same syntax and leftmost-longest
  matches.
- **Variables:** per call, `<Global variables>` shared by all calls, and
  `<User variables>` kept across a `-users` user's calls.
- **Keywords:**
  - addressing: `[service]`, `[remote_ip]`, `[remote_port]`,
    `[local_ip]`, `[local_port]`, `[transport]`, `[local_ip_type]`;
  - media fields: `[media_ip]`, `[media_ip_type]`, `[media_port]`;
  - call and message: `[call_number]`, `[call_id]`, `[pid]`, `[branch]`,
    `[users]`, `[userid]`, `[msg_index]`, `[dynamic_id]`, `[clock_tick]`,
    `[timestamp]`, `[sipp_version]`, `[remote_host]`, `[server_ip]`,
    `[auto_media_port]`, `[last_message]`,
    `[cseq]`, `[len]`, `[peer_tag_param]`, `[date]`;
  - dialog: `[routes]`, `[next_url]`;
  - last received message: `[last_<Header>:]`, `[last_<Header>.value]`,
    `[last_Request_URI]`, `[last_cseq_number]`;
  - `[$var]`, `[fieldN file= line=]` from `-inf` files, and `-key`
    values;
  - `[authentication username= password=]` (also inside injected fields).
  - `[file name=]`: the file's contents, as they are.

  Offsets such as `[local_port+1]` work.
- **Message text** is prepared as SIPp's `clean_cdata()` does:
  indentation goes, a body keeps a final CRLF only when the text had one,
  and `\xNN` escapes are literal bytes. A keyword that comes out empty at
  the start of a line drops that line. `[len]` is filled in last.
- **Bytes** go through as SIPp passes them, UTF-8 or not: those of
  messages, scenario files (UTF-16 and UTF-32 ones decoded as pugixml
  does), `-inf` files, `[file]`, commands and arguments, and so into
  messages, logs, regexps (which match bytes) and `[len]`.
- **Call handling, as in SIPp:**
  - over UDP, a message the call received again gets again the message
    sent right after it (a later response to the same request taking
    over), one nothing answered yet is dropped; a late copy of what the
    call passed is absorbed only as SIPp absorbs it (a provisional, a
    repeated ACK, an INVITE's final response ACKed again, a transaction's
    final response), anything else being unexpected;
  - CSeq numbering, and responses matched to their request's method or
    transaction;
  - the Record-Route route set and remote target;
  - a response goes where the request it answers came from, by its top
    Via branch, for the last four requests from elsewhere than the call's
    destination (another address or connection), but with `-rsa`;
  - UDP retransmissions and their limits, and answering the peer's
    retransmissions while a call lasts; a finished call's Call-ID is
    kept for `-deadcall_wait`, its late messages warned about as SIPp's
    dead calls;
  - Call-IDs matched on what follows `///`;
  - the default behaviours on unexpected messages (ACK, CANCEL or BYE to
    leave the dialog, 200 to a stray BYE/CANCEL), and `-aa`, with the
    messages `<DefaultMessage id>` replaces.
- **Digest authentication:** `<recv auth="true">` keeps the 401/407
  challenge, `[authentication]` answers it (MD5, SHA-256, SHA-512-256 and
  their -sess variants, or AKAv1-MD5 with `aka_K`/`aka_OP` (`aka_AMF` ignored, as the MAC is
  over AUTN's AMF) and
  Milenage checked against TS 35.207's test sets; qop auth or auth-int,
  as SIPp formats it), and `<verifyauth>` checks credentials.
  `-au`, `-ap` and `-auth_uri` set the defaults.
- **Injection files:** `-inf` (SEQUENTIAL, RANDOM or USER, PRINTF, `#`
  comments), the first one being the default for `[fieldN]`, and
  `-infindex` for `<lookup>`.
- **Load:** `-r`/`-rp` rates, `-l`, `-m`, `-m_csv`, or `-users` for a
  fixed number of calls, ramped up at `-r` when it is given.
- **Transports:** `-t u1`, `un` (a UDP socket per client call, shared in
  turn past `-max_socket`), `ui` (a UDP socket per local IP from `-inf`'s
  `-ip_field`, the main one on the first, a server listening on all),
  `t1`/`l1` (one TCP or TLS connection, from `-p` when given) and `tn`/`ln` (one per call,
  closed when the call ends, shared in turn past `-max_socket`). As in SIPp, a
  client listens on its port too, and takes a request on a connection made to
  it (a BYE to its Contact, say) like any other. TLS uses rustls; a
  server needs `-tls_cert`/`-tls_key` (default `cacert.pem`/`cakey.pem`),
  which a client presents too, or goes without, warning, when neither is
  given and neither default file is there. As in SIPp, only
  `-tls_ca` has the peer's chain checked (not its name), a server then
  wanting the client's certificate; `-tls_crl` adds revocation,
  `-tls_version` 1.2 or 1.3 pins the version (1.0 and 1.1 with the
  `legacy-tls` build, below), `-tls_handshake_timeout`
  bounds a handshake (a server drops only that peer), and `SSLKEYLOGFILE` logs
  the keys. `s1`/`sn` are the same over SCTP (Linux's one-to-one
  sockets), with `-multihome` a second local address and `-heartbeat`,
  `-assocmaxret`, `-pathmaxret` and `-pmtu` set as SIPp sets them, but
  for all the peer's addresses at once, which applies `-pmtu` too; each
  message goes unordered (RFC 4168). Where SIPp's SCTP hangs or spins
  (a refused or reconnected association, a peer's close, 3PCC), sipp-rs
  does as SIPp does over TCP.
  `w1`/`wn` and `x1`/`xn` carry SIP over WebSocket (RFC 7118) on TCP and
  on TLS, as in SIPp's pull request #1028: the client's handshake asks for
  `-ws_path`, `-ws_handshake_timeout` bounds it; `[transport]` is `WS`/`WSS`.
  A remote host name without a port is looked up first with DNS NAPTR and
  SRV records (RFC 3263) for the transport, but WebSocket, at startup, as
  in SIPp (the system resolver; none on Windows yet). With `-round_robin`,
  new calls take the name's addresses in turn (UDP, or a socket per call).
- **RTP:**
  - `<exec rtp_stream="file,loops,payload,codec">` plays a file as RTP to
    the peer's SDP address: PCMU, PCMA, G722 or G729, one packet every
    20 ms, from a per-call port allocated from `-min_rtp_port` as SIPp does
    and shown in `[rtpstream_audio_port]`. The port after it is bound
    too, as in SIPp, so that the peer's RTCP draws no ICMP; like SIPp, no
    RTCP (or SRTCP) is sent or read, and a file always plays as audio;
  - `rtp_stream="apattern|vpattern,N,payload,codec"`: a constant payload
    on audio or video (H264 every 160 ms), checked against what the peer
    echoes back; a pattern that never comes back ends the run with
    EXIT_RTPCHECK_FAILED (253) and a warning saying so, as in SIPp;
  - `-rtpcheck_debug`: SIPp's `debugafile` and `debugvfile`, the same
    lines for each packet sent and what came back after it, compared as
    SIPp compares them, and for each pass of its playback thread over
    its calls; a debug file that can't be created is warned about, and
    the run goes on without it;
  - `rtp_stream="pause|resume"` and `pause/resume{a,v}pattern`;
  - `rtp_stream="wait" [timeout=ms]` holds the next step until the file
    or pattern has played; the media thread tells the engine when it has,
    where SIPp polls it every 20 ms;
  - `-rtp_echo`, the `<rtp_echo value>` action, and per-call
    `rtp_echo="start|update|stop{audio,video}"`.
  - `<rtp_stats assign_to="packets[,pt[,payload]]" media=>` assigns the
    RTP packets the call's audio (or video) port received, and the
    payload type and hex payload of the first; `<rtp_dtmf assign_to
    payload_type=>` the digits of the RFC 4733 events that came on the
    audio port, one per event. With either in the scenario, the calls
    count what comes on their `rtp_stream` ports from the first packet,
    their thread reading it when they neither play nor echo, as SIPp.
  - each stream, and each pcap play, goes to the c= address of its own
    media section, else the session one (RFC 4566 5.7); a stream without
    a usable one (c=0.0.0.0, the other IP version) holds, as in SIPp.
    Both skip a first m= line of the kind with port 0 for the second.
- **pcap playback:** `play_pcap_audio`, `play_pcap_image`,
  `play_pcap_video` and `play_pcap_text` (RFC 4103, to the m=text port)
  replay a capture's UDP packets (libpcap or pcapng;
  Ethernet, 802.1Q, Linux cooked or raw IP) on its timing, from the port
  our `[media_port]` gave (else `-mp`, +2 for video, +4 for text) to the peer's, keeping each
  packet's offset from the capture's lowest port (RTP and RTCP). `play_dtmf="digits[,ms[,pt]]"` sends
  RFC 2833 events, and `-sn uac_pcap` is SIPp's built-in scenario. A
  call's audio (with its DTMF) or image, video and text play at once, a new
  play replacing the one on its stream (audio and image share one). As
  SIPp, the plays share a raw socket (root or CAP_NET_RAW), and exit
  with 255 without one.
- **SRTP** (RFC 3711; AES_CM_128, RFC 6188's AES_192_CM and AES_256_CM,
  or NULL with HMAC-SHA1-80/32, checked against the RFCs' test vectors):
  the `[cryptotag…]`, `[cryptosuite…]`,
  `[cryptokeyparams…]` and `[ueaescm128sha1…]` keywords for audio and video,
  the peer's `a=crypto` lines, and SIPp's offer/answer choice between the
  two offered lines. Streams go out encrypted, and a call's echo decrypts
  with the peer's key and re-encrypts with its own.
- **3PCC:** the four built-in scenarios (`-sn 3pcc-C-A`, `3pcc-C-B`,
  `3pcc-A`, `3pcc-B`), `<sendCmd>`/`<recvCmd>`, and the `-3pcc` twin
  connection. Commands go to the call they name, a new call on controller
  B, and mix with C SIPp in any role. Extended mode too: `-master`,
  `-slave` and `-slave_cfg` (or `-primary`, `-secondary` and
  `-secondary_cfg`), with `<sendCmd dest>` and `<recvCmd src>`;
  a peer's end aborts the open calls, as in SIPp. With `-3pcc`, a call
  aborted on an unexpected message aborts the twin's too (`3pcc_abort`).
  A reset twin or peer connection is one for `-max_reconnect`: one we
  made connects again, one we accepted waits for the peer to. A call
  left waiting for a command the lost connection took fails as on a
  closed connection; a command written while A connects again waits.
- **Options:**
  - `-h` prints SIPp's help, byte for byte: `src/help.rs` has SIPp's
    options table, in its order and words, wrapped as SIPp does and
    paged at a terminal (`$PAGER`, else pager, less or more); `-h stat`
    explains the `-trace_stat` columns. Without `-i`, the local IP is the
    one that routes to the remote host;
  - traffic: `-r`, `-rp`, `-l`, `-m`, `-m_csv`, `-d`, `-users`, `-rate_increase`,
    `-rate_max`, `-rate_interval`, `-no_rate_quit`, `-sleep`, `-bg`;
  - timeouts and retransmissions: `-recv_timeout`, `-timeout`,
    `-timeout_error`, `-nr`, `-max_retrans`, `-max_invite_retrans`,
    `-max_non_invite_retrans`, `-T2`;
  - behaviour: `-nd`, `-default_behaviors`, `-aa`, `-pause_msg_ign`,
    `-lost`, `-key`, `-set`;
  - `-tdmmap`: a circuit per call while it runs, named by `[tdmmap]`;
  - control, as SIPp's: the keys (`1`-`9` screens, `+ - * /` rate or
    users by `-rate_scale`, `p` pause, `q` soft and `Q` hard exit, `s`
    screens to file) from the terminal, and those or `c` commands (`set
    rate|rate-scale|users|limit|hide`, `trace error|logs|messages|shortmessages
    on|off`, `dump tasks|variables`, `reset stats`) on the UDP control
    socket (`-cp`, else the first free of 8888-8947; `-ci`), SIGUSR1 as
    `q`, SIGINT/SIGTERM to end at once, and SIGUSR2
    for the screens in the screen file. A terminal
    gets SIPp's screen redrawn each second, the variables (4) and TDM
    map (5) screens included, and the run ends on the screen shown and
    the statistics;
  - `-bind_local`: without `-i`, listen on the local IP SIPp works out
    rather than on all of them; `-bind_to_device`; `-random_base_ssrc`;
    `-gracefulclose` (SCTP: SHUTDOWN or ABORT);
  - `-audiotolerance`, `-videotolerance`: the share of failed echoes
    that fails a pattern's RTP check (default 1.0: all of them);
  - `-max_reconnect`, `-reconnect_close`, `-reconnect_sleep`: a failed
    TCP/TLS/SCTP connection ends the run without a reconnection left, as
    SIPp; else its calls close (or stay), and a client's connection
    opens again. As in SIPp, a TCP or SCTP connect doesn't wait: a
    reconnection is reported as it starts, and a refusal shows later;
    with `-reconnect_close false` the new connection gets what the old
    one did not take, and a request it took with no response yet;
  - `-rtcheck full|loose`: retransmissions told by the whole message or
    by its To, From, Call-ID and CSeq, as SIPp;
  - a scenario message that fails to send fails its call; one of our own
    (an automatic answer, an abort's CANCEL or BYE) is a warning, or an
    error with `-sendbuffer_warn true`;
  - messages: `-base_cseq`, `-cid_str`, `-cid_type`, `-callid_slash_ign`,
    `-rsa`, `-mi`, `-rtp_payload`, and `-dynamicStart`, `-dynamicMax`,
    `-dynamicStep` for `[dynamic_id]`;
  - logs and statistics: `-trace_msg`/`-message_file`,
    `-trace_err`/`-error_file`, `-trace_logs`/`-log_file`,
    `-trace_shortmsg`, `-trace_screen`, `-trace_counts`,
    `-trace_error_codes`, `-trace_rtt`, and `-trace_stat`/`-stf`/`-fd`
    with SIPp's CSV (every column: failure reasons, response times, call
    lengths, counters, periodic and cumulative repartitions), `-rfc3339`,
    `-stat_delimiter`; `-periodic_rtd` is ignored, with SIPp's warning;
    a log that can't be opened or reopened (rotation, trace command,
    SIGUSR2) ends the run with SIPp's error;
  - `-trace_calldebug`/`-calldebug_file`: an aborted call's history, the
    same lines as SIPp's except its scheduler's wakeups;
  - `-srtpcheck_debug`'s `srtpctxdebugfile_uac`/`_uas`: each call's
    account of its SRTP, SIPp's lines in SIPp's order, naming sipp-rs's
    functions, keywords and states where SIPp names its own; made anew
    by each call and written through a stdio-sized buffer, so calls
    overwrite each other as SIPp's do;
  - all of SIPp's built-in scenarios (uac, uas, regexp, branchc,
    branchs, uac_pcap, the 3PCC ones, ooc_default, ooc_dummy), which
    `-sd` prints byte for byte as SIPp does;
  - `-oocsf`/`-oocsn`: a client's out-of-call requests play that
    scenario; `-rxsf` (and `-rxsn`, `-rxinf`): its incoming calls play
    another while it makes its own, each scenario with its statistics;
  - `-plugin file.so`: a plugin adds [keywords], and may replace ours, as
    SIPp's do. SIPp's plugins call its C++ internals, so sipp-rs has its
    own C ABI instead: the `sipp-plugin` crate, with a safe wrapper; a
    keyword gets the text after its name and can render any scenario
    text for the call, such as `[$var]` or `[last_From:]`. See
    `plugin/example` (`[shout [call_id]]`, `[sent]`).
  - `-lua_file f.lua` and `<exec lua="function arg ..."/>`: the function
    reads and writes the call's variables with `sipp.get(name)` and
    `sipp.set(name, value)` (a string, a number or a boolean), and logs
    with `sipp.log(message)`, as in C SIPp (see `docs/scenarios/lua.rst`
    there). A scenario with such an action may use a variable once. It is
    the `lua` feature, on by default, with a Lua 5.4 built from source
    (mlua's `vendored`); `--no-default-features` leaves it out, and then
    both are errors, as in a C SIPp built without Lua.

  The loop keeps SIPp's clock and pace: its clock starts before the
  sockets open, a call runs one step a pass (each pass waits up to a
  millisecond for what comes in, and reads it), and the calls' timers
  and the call rate wake them in a timer cycle, every `-timer_resol`,
  once the clock is past their millisecond: pauses, actions and RTP
  timestamps fall on the same clock values as SIPp's. Its other
  scheduler and socket tuning options (`-max_recv_loops`,
  `-watchdog_*`, `-buff_size`, …) are accepted and ignored, having
  nothing to tune here.

  SIPp's exit codes (0, 1, 97, 99, 254, 255) and its fallback ports when
  5060 is taken (5061 to 5119, then any) also match.

## Media threads

The SIP engine is a single loop; the calls' media run in a pool of
threads (`mediapool.rs`), as SIPp's RTP playback threads
(`rtpstream.cpp`):

- A call joins a thread with room at its first RTP socket or play; a
  thread takes up to `-rtp_threadtasks` calls (50), a new one starts
  when all are full, and threads last until the run ends, as SIPp's
  ("N RTP sending threads active").
- The thread owns the call's RTP and RTCP sockets and does all of its
  media: `rtp_stream` files and patterns (pause, resume, SRTP), the
  pattern's echo check, the call's `rtp_echo` (decrypting and
  re-encrypting with the call's keys, `-srtpcheck_debug`'s log), its
  `play_pcap_*`/`play_dtmf` plays (audio or image, video and text, at
  once), and what came for `rtp_stats`/`rtp_dtmf` (under a mutex the
  engine reads it through, made only when a scenario has them).
- The engine sends commands down a channel and wakes the thread through
  an eventfd: the sockets, a stream with its SRTP contexts (none of it
  goes out with other keys), pause and resume, the peer's new address
  from its SDP, echo start/update/stop, a play, a play moved by our
  `[media_port]` or the peer's SDP, and the call's end. The screen's RTP
  counters are atomics.
- A thread sleeps in `epoll_pwait2()` until its next packet is due.
  `rtp_stream` packets after the first go on the multiples of their
  interval on the thread's clock (SIPp's, 0 to 19 ms ahead), as
  SIPp's, so a thread wakes once a packet time for all its calls, and
  are stamped with that packet time, paused or not, as SIPp's RTP
  timestamps; plays keep their microsecond timing.
  A stream reads what came back after each packet, as SIPp; the sockets
  of an echo, or of a check whose stream ended, are in the epoll set,
  and once packets came the thread lets the next ones gather for up to
  a millisecond before it reads them (waking up per packet, and having
  each sender pay for that wakeup, cost a third more CPU).
- At a call's end its thread reads what the call's sockets still hold,
  then takes the call's RTP check verdict into the mask the exit reads
  once the threads are joined; a pattern replaced by the next
  rtp_stream gets its own verdict then, as in SIPp.
- `-rtp_echo` echoes in two threads of its own, audio and video, as
  SIPp's `rtp_echo_thread()`: `-mb` long at most, and stopped with a
  warning by a receive or send error.

Measured on WSL2 (28 cores, other work running), back to back, CPU
seconds per process (all threads); `r` is sipp-rs before the threads (a
5 ms media loop in the engine). "echo": #0037's UAC (a pattern stream
with its echo check) against its UAS (per-call `rtp_echo`), with calls
long enough for all to overlap; "pcap": a UAC playing `pcap/g711a.pcap`
to a UAS answering a fixed port. Lateness is each packet's (after a
stream's first) against its RTP timestamps, or the capture's timing for
pcap, from a capture on lo; echo is the echo's delay.

| test | impl | UAC CPU | UAS CPU | late p50 / p99 ms | echo p50 / p99 ms | packets | calls ok |
|---|---|---|---|---|---|---|---|
| echo 200 | r | 1.9-2.7 | 1.8-2.6 | 0.8 / 42-44 | 0.9 / 16-21 | 100% | 200 |
| echo 200 | sipp-rs | 1.4-1.6 | 1.4-1.5 | 0.1-0.2 / 0.6-2.0 | 0.4-1.1 / 1.3-1.4 | 100% | 200 |
| echo 200 | C | 1.8-2.0 | 2.5-2.7 | 0.2 / 19 | 0.1 / 1.0 | 100% | 200 |
| echo 500 | r | 5.6-5.9 | 5.2-5.5 | 1.2-1.4 / 44-55 | 1.5-7.7 / 21-22 | 100% | 500 |
| echo 500 | sipp-rs | 6.9-7.2 | 6.0-6.2 | 0.2 / 0.9-1.4 | 0.9 / 1.4 | 100% | 500 |
| echo 500 | C | 10.4-14.5 | 16.7-19.1 | 0.4-1.0 / 19-20 | 0.1-0.3 / 0.9-1.2 | 97-100% | 487-500 |
| echo 1000 | r | 15.3 | 14.4 | 7.8 / 782 | 15 / 67 | 100% | 1000 |
| echo 1000 | sipp-rs | 32.8 | 26.0 | 0.3 / 1.3 | 0.6 / 1.5 | 100% | 1000 |
| echo 1000 | C | 13.4 | 60.3 | 0.4 / 19 | 0.1 / 1.0 | 41% | 396 |
| pcap 500 | r | 1.0 | 0.2 | 0.6 / 1.2 | | 100% | 500 |
| pcap 500 | sipp-rs | 1.6-2.7 | 0.2 | 0.05 / 0.1-0.5 | | 100% | 500 |
| pcap 500 | C | 2.8-3.0 | 0.2 | 0.07 / 0.1-0.2 | | 100% | 500 |

No RTP check failed. A bind() takes 10 ms on this host, which paces
call setup for all three (two binds per call and side, in the engine):
SIP response times were 130-170 ms at the median for sipp-rs, 7-19 s
for C, whose UAS fell behind and failed calls from 500 on. Most of the
threads' CPU is waking up (about 50 us each on this VM): with
`-rtp_threadtasks 100`, 500 calls take 3.5 s (UAC) and 3.2 s (UAS).

## Windows

`sipp-rs.exe` builds on Linux with llvm-mingw
(https://github.com/mstorsjo/llvm-mingw, the UCRT build), as one file that
needs no DLL beyond Windows 10's own:

```sh
LLVM_MINGW=/path/to/llvm-mingw ./windows.sh
# target/x86_64-pc-windows-gnullvm/release/sipp-rs.exe
SIPP=$PWD/wsl-sipp.sh ../regress/runtests -j 1   # from WSL, on its Windows host
```

`wsl-sipp.sh` hands the exe its Linux file paths (the tests' `mktemp`
files) as Windows sees them (`wslpath -w`).

What Linux and Windows do differently is in `src/sys/`:
- The media threads wait on their sockets with WSAPoll(), to the
  millisecond (the run sets a 1 ms timer resolution), where Linux has
  epoll with nanosecond timeouts; they read one datagram at a time, where
  Linux reads a batch with recvmmsg().
- Keys come from the console's key events, or from a pipe on stdin. There
  are no SIGUSR1/SIGUSR2: the control socket does what they do. Ctrl-C
  ends the run, as SIGINT does.
- `-bg` starts the run again, detached from the console, and prints its
  PID as `fork()` did.
- `<exec command>` and `<exec verify>` run through `cmd /C`, where Linux
  has `sh -c`. A killed verify command fails the call by its exit code:
  on Windows, no process ends by a signal.
- Regular expressions: Windows has no POSIX regex, so sipp-rs brings
  musl's (`vendor/musl-regex`, built by `build.rs`), made to read glibc's
  syntax: it matches as glibc does on all 1416 cases of SIPp's scenario
  regexes and edge cases (alternation, backreferences, escapes) tried.
- Not on Windows: SCTP (`-t s1`/`sn` fail as in a SIPp built without it)
  and `-bind_to_device`. pcap plays need an Administrator, whose raw
  sockets they send on, as they need root or CAP_NET_RAW on Linux.
- A quoted keyword value takes `\` as an escape, as SIPp does: write
  Windows paths there with `/`.

Checked on Windows 11, from WSL2 (its mirrored networking shares
127.0.0.1 between the two):
- The unit and integration tests, cross-built and run there, all pass
  but one whose ports this setup reserves; a plugin DLL loads and adds
  its keywords.
- The built-in uac/uas against C SIPp on the Linux side, both ways, UDP
  and TCP: 20 calls of 20.
- SIPp's `regress/runtests` with `SIPP=sipp-rs.exe`, run from WSL: 148
  pass and 9 skip (SCTP, and the two above). Of the 24 that fail, one was
  a Windows bug (a TLS reconnection's handshake, #0857), since fixed. The
  others need what Windows or this setup lacks: signals (SIGUSR1/2, a
  SIGTERM caught), pcap plays as an Administrator, valgrind, `/proc`,
  Perl in `<exec>`, Windows' own error texts, and WSL, which bridges
  127.0.0.1 alone (not 127.0.2.1, or the host's address).

## macOS

`cargo build --release` on macOS, with Xcode's command line tools (ring,
the TLS crypto, has C in it). The media threads wait on a kqueue and wake
up through a pipe, where Linux has epoll and an eventfd; random bytes come
from getentropy(). As on Windows, they read one datagram at a time, and
there is no `-bind_to_device`. macOS has no SCTP: `-t s1`/`sn` fail as in
a SIPp built without it.

The `rust` workflow runs `cargo test` on macOS (the regression suite runs on
Linux only).

## What it doesn't do (yet)

What is missing:
- TLS 1.0 and 1.1 (rustls has neither), unless built with
  `cargo build --release --features legacy-tls`: OpenSSL (the `openssl`
  crate, linking the system's libssl) then does `-tls_version` 1.0 and
  1.1 alone, at security level 0 as SIPp; rustls keeps the rest.

## Checked

- Unit tests (`cargo test`) for templates, SIP parsing, scenarios,
  variables, TCP framing and whole calls over loopback, and the example
  plugin.
- `interop.sh` (25 pairs at once, about 5 s): built-in uac/uas against C
  SIPp in both directions over UDP, TCP and TLS (and WebSocket, 8 more,
  and SCTP `s1`/`sn`, 6 more, when the C SIPp has them), and against
  itself;
  digest auth (MD5 auth-int and SHA-256 auth) with each side verifying the
  other; injection files.
- Load, built-in uac against uas over UDP loopback, one core each: CPU
  per call on a par with C SIPp (about 38 us a side at 10000 cps, 51 us
  with 5 s calls at 5000 cps, where C takes 40-60 us). Both hold 15000
  cps; past that, receive-buffer overflows and the retransmissions they
  cause take both down.
- 10% packet loss on the C side (`-lost 10`), where it fails the same 1
  call in 100 as C SIPp against itself.
- SIPp's `regress/runtests`, through `./regress.sh`: all pass. It builds
  with `--features legacy-tls` (#0990's TLS 1.0 and 1.1) and gives the
  tests an /etc/hosts with localhost on ::1 first (#0646).
- `pfca.sh` (about 2 min): all 51 `sipp_scenarios/pfca_*` SRTP/pattern
  pairs, each way against C SIPp and C against itself, pass all 153 runs.
  That needs the C fixes merged upstream (SIPp PRs #888-#904). Without
  them, C against itself passes 3 of the 51. Run it with the loopback to
  itself: other SIPp tests binding 0.0.0.0:5060 at the same time fail its
  binds.
- RTP: 50 packets of 172 bytes a second, in order, 20.2 ms apart on
  average.
- pcap: `-sn uac_pcap` against a C UAS sends the same 246 packets as C
  SIPp, byte for byte, each within 1.3 ms of the capture's timing (C:
  0.8 ms); `play_dtmf` matches C with SIPp PRs #906-#908. The same
  captures converted to pcapng (`editcap -F pcapng`) give the same
  packets and timing.
- SCTP: `uac`/`uas` against C SIPp built with SCTP, for `s1` and `sn`
  in all four pairings, with and without the tuning options; `-multihome`
  binds the same two addresses as C (`/proc/net/sctp/eps`); getsockopt()
  reads back the same per-address, `-assocmaxret` and linger options as
  C's (and the `-pmtu` C's loses once data flows); a capture shows the
  same chunks (unordered DATA, SHUTDOWN or with `-gracefulclose false`
  ABORT) from the same ports.
- 3PCC: all four roles in sipp-rs, and C and Rust controllers and
  endpoints mixed every way; extended mode's master and slave in all four
  pairings, 20 calls each, and the slave's calls still open when the
  master ends aborted and failed as in C.

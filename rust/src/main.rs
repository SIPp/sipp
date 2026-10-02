//! sipp-rs: a Rust port of SIPp.

// println! and eprintln! that let a write fail, as SIPp's printf(): a
// full disk, the file size limit (SIGXFSZ) or a closed pipe don't end the
// run.
macro_rules! println {
    ($($t:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout(), $($t)*);
    }};
}

macro_rules! eprintln {
    ($($t:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), $($t)*);
    }};
}

mod auth;
mod call;
mod control;
mod dist;
mod dns;
mod help;
mod infile;
mod log;
mod media;
mod mediapool;
mod milenage;
mod net;
mod pcap;
mod lua;
mod plugin;
mod posix;
mod raw;
mod scenario;
mod screen;
mod sip;
mod srtp;
mod stat;
mod sys;
mod tdm;
mod template;
#[cfg(feature = "legacy-tls")]
mod tls_openssl;
mod vars;
mod websocket;
mod wizard;

use call::{Call, Config, Control, Defaults, Env, Outcome, Rng};
use stat::Stats;
use log::Log;
use net::{Net, Peer, Transport, NO_REMOTE};
use scenario::{Expect, Op, Scenario};
use std::borrow::Cow;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap, VecDeque};
use std::fs::File;
use std::io::{IsTerminal, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::process::ExitCode;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// SIGUSR2 asks for the screens in the screen file, as sipp_sigusr2().
static SIGNAL_DUMP: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn on_sigusr2(_: libc::c_int) {
    SIGNAL_DUMP.store(true, Ordering::Relaxed);
}

/// SIGUSR1s not yet seen: each is a 'q', as sipp_sigusr1().
static SIGNAL_QUIT: AtomicU32 = AtomicU32::new(0);

#[cfg(unix)]
extern "C" fn on_sigusr1(_: libc::c_int) {
    SIGNAL_QUIT.fetch_add(1, Ordering::Relaxed);
}

/// SIGINT or SIGTERM: end the run at once, as sipp_sighandler().
static SIGNAL_EXIT: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sigexit(_: libc::c_int) {
    SIGNAL_EXIT.store(true, Ordering::Relaxed);
}

/// SIGXFSZ: a file past the size limit, as manage_oversized_file(),
/// rather than the core dump of the default action.
#[cfg(unix)]
extern "C" fn on_sigxfsz(_: libc::c_int) {
    log::oversized();
}

/// A fault kills the run by the default action, as in C SIPp. This is set
/// before std's runtime starts, since std installs its own SIGSEGV and
/// SIGBUS handler only over the default one, and keeps the main thread's
/// record for it until exit, which valgrind reports (github-#0156).
#[cfg(target_os = "linux")]
#[used]
#[link_section = ".init_array"]
static DEFAULT_FAULTS: extern "C" fn() = default_faults;

#[cfg(target_os = "linux")]
extern "C" fn default_faults() {
    extern "C" fn fault(sig: libc::c_int) {
        // SAFETY: the action is back to the default: the signal kills us.
        unsafe { libc::raise(sig) };
    }
    for sig in [libc::SIGSEGV, libc::SIGBUS] {
        // SAFETY: a one-shot handler, reset to the default when it runs.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = fault as extern "C" fn(libc::c_int) as libc::sighandler_t;
            action.sa_flags = libc::SA_RESETHAND;
            libc::sigaction(sig, &action, std::ptr::null_mut());
        }
    }
}

/// -bg on Windows, which has no fork(): the run again, detached from the
/// console, with this set in its environment, and its PID.
#[cfg(windows)]
const BACKGROUND_ENV: &str = "SIPP_RS_BACKGROUND";

#[cfg(windows)]
fn background(argv: &[String]) -> ExitCode {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    let run = std::env::current_exe().and_then(|exe| {
        Command::new(exe)
            .args(argv)
            .env(BACKGROUND_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
            .spawn()
    });
    match run {
        Ok(child) => {
            println!("Background mode - PID=[{}]", child.id());
            ExitCode::from(EXIT_OTHER)
        }
        Err(_) => {
            eprintln!("Forking error");
            ExitCode::from(EXIT_FATAL_ERROR)
        }
    }
}

fn set_handler(sig: libc::c_int, handler: extern "C" fn(libc::c_int)) {
    // SAFETY: the handlers only store to atomics.
    unsafe { libc::signal(sig, handler as extern "C" fn(libc::c_int) as libc::sighandler_t) };
}

/// The calls by Call-ID. FxHash (rustc's) for its keys: SipHash's
/// resistance to chosen keys only makes a lookup a message slower.
type Calls = HashMap<String, Box<Call>, std::hash::BuildHasherDefault<FxHasher>>;

#[derive(Default)]
struct FxHasher(u64);

impl FxHasher {
    fn add(&mut self, word: u64) {
        self.0 = (self.0.rotate_left(5) ^ word).wrapping_mul(0x517c_c1b7_2722_0a95);
    }
}

impl std::hash::Hasher for FxHasher {
    fn write(&mut self, bytes: &[u8]) {
        let (words, rest) = bytes.as_chunks::<8>();
        for w in words {
            self.add(u64::from_le_bytes(*w));
        }
        for &b in rest {
            self.add(u64::from(b));
        }
    }

    fn write_u8(&mut self, i: u8) {
        self.add(u64::from(i));
    }

    fn write_usize(&mut self, i: usize) {
        self.add(i as u64);
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

/// SIPp's exit codes (include/defines.h).
const EXIT_TEST_OK: u8 = 0;
const EXIT_TEST_FAILED: u8 = 1;
const EXIT_TEST_RES_INTERNAL: u8 = 97;
const EXIT_OTHER: u8 = 99;
const EXIT_FATAL_ERROR: u8 = 255;
const EXIT_BIND_ERROR: u8 = 254;
const EXIT_RTPCHECK_FAILED: u8 = 253;

/// -v's notice after the version, as SIPp's.
const COPYRIGHT: &str = " This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License as
 published by the Free Software Foundation; either version 2 of
 the License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public
 License along with this program; if not, write to the
 Free Software Foundation, Inc.,
 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

 Author: see source files.
";

struct Args {
    /// -tls_cert and -tls_key, or the defaults; None for a client that
    /// goes without.
    tls_files: Option<(String, String)>,
    /// -tls_cert or -tls_key was given.
    tls_named: bool,
    tls_options: net::TlsOptions,
    /// -ws_path and -ws_handshake_timeout.
    ws_path: String,
    ws_timeout: Duration,
    /// -3pcc's host:port, resolved as the run starts.
    twin: Option<String>,
    /// Controller B, which listens for controller A.
    twin_listens: bool,
    /// -3pcc or 3PCC extended mode for a scenario with no command:
    /// open_connections()'s error.
    twin_mode_error: Option<&'static str>,
    /// Calls are started by rate (SIPp's client creation mode).
    creates: bool,
    /// -srtpcheck_debug: each call's srtpctxdebugfile, of SIPp's sendMode,
    /// client or server; neither in a scenario without <send> or <recv>.
    srtpctx: Option<Option<bool>>,
    /// A command no call waits for starts one.
    cmd_starts: bool,
    /// The remote host, which a server's calls started by a command send to.
    given_remote: Option<SocketAddr>,
    /// -round_robin: the remote host's addresses, which new calls take
    /// in turn; the first is the remote host's.
    remotes: Vec<SocketAddr>,
    /// Why -i has no address to bind to, or -round_robin is refused:
    /// SIPp's error when it sets up its sockets.
    local_error: Option<String>,
    /// The NAPTR and SRV records that gave it, for "Resolving remote
    /// host": "SRV name: target:port. ", or "", then -round_robin's
    /// "N addresses. ".
    srv_note: String,
    /// The remote host did not resolve: "Resolving remote host" has no
    /// "Done." and the run fails with `local_error`.
    remote_unknown: bool,
    inject: infile::Injection,
    transport: Transport,
    rtp_echo: bool,
    rtp_ports: (u16, u16),
    /// Without -p, SIPp falls back to another port when 5060 is taken.
    explicit_port: bool,
    scenario: Scenario,
    scenario_name: String,
    cfg: Config,
    remote: Option<SocketAddr>,
    max_calls: Option<u64>,
    rate: f64,
    /// -r given: -users then ramp their calls up at the rate.
    rate_set: bool,
    rate_period: Duration,
    limit: usize,
    timeout: Option<Duration>,
    timeout_error: bool,
    log: Log,
    control_port: Option<u16>,
    stat_file: Option<File>,
    /// -trace_stat's file, or -stf's.
    stat_path: Option<String>,
    stat_period: Duration,
    /// -watchdog_interval: SIPp's watchdog task wakes this often, 0 none.
    watchdog: Duration,
    /// -timer_resol: how often SIPp's timer cycle wakes its tasks.
    timer_resol: Duration,
    call_ids: CallIds,
    /// -master or -slave name, whether master, and -slave_cfg's addresses.
    extended: Option<(String, bool, HashMap<String, String>)>,
    /// -oocsf/-oocsn, and -rxsf/-rxsn with -rxinf's files.
    ooc: Option<Scenario>,
    rx: Option<Scenario>,
    /// -aa: the ooc_dummy scenario of the calls it answers outside any.
    aa: Option<Scenario>,
    /// The scenarios have <rtp_stats> or <rtp_dtmf>: the calls count what
    /// they receive, and decode the events of these payload types.
    counts_received: Option<u128>,
    /// -deadcall_wait: how long a finished call's Call-ID is known.
    deadcall_wait: Duration,
    rx_inject: infile::Injection,
    rate_increase: Option<f64>,
    rate_max: Option<f64>,
    rate_interval: Duration,
    rate_quit: bool,
    rfc3339: bool,
    stat_delimiter: String,
    counts_file: Option<File>,
    codes_file: Option<File>,
    /// An error of SIPp's setup after the options, before its TLS setup.
    setup_error: Option<String>,
    /// -trace_rtt's files of the main, -oocsf and -rxsf scenarios, each
    /// created with its first times to write.
    rtt_paths: [Option<String>; 3],
    /// -rtt_freq: -trace_rtt lines held back before a write.
    rtt_freq: usize,
    screen_file: Option<String>,
    /// The screen file, which -trace_screen opens once the scenario is
    /// loaded, else each SIGUSR2 as rotate_screenf().
    screen_log: log::Sink,
    /// No -l: SIPp's limit from the rate and call length, and the length.
    auto_limit: Option<f64>,
    nostdin: bool,
    /// -ci: the control socket's IP.
    /// -ci, resolved as the control socket is set up.
    control_ip: Option<String>,
    rate_scale: f64,
    /// -max_socket, and -ip_field for -t ui with its IPs.
    max_socket: usize,
    skip_rlimit: bool,
    /// -max_recv_loops: the datagrams one pass reads at most.
    recv_loops: usize,
    ip_field: usize,
    per_ip: Vec<IpAddr>,
    /// -bg: fork, the parent printing the child's PID.
    background: bool,
    /// -sleep: wait this long before starting.
    sleep: Duration,
    /// -set: <Global> variables' first values.
    sets: Vec<(String, String)>,
    /// -rsa: where messages go instead of the remote host.
    rsa: Option<SocketAddr>,
    tdm: Option<tdm::TdmMap>,
    sctp: net::SctpOptions,
    bind_device: Option<String>,
    reconnect: Reconnect,
}

impl Args {
    /// open_connections() connects a -t t1/l1/s1/w1 socket at the start:
    /// a client's, or a 3PCC controller B's or slave's with a remote host.
    fn connects_at_start(&self) -> bool {
        let b_or_slave = (self.twin.is_some() && self.twin_listens) || matches!(self.extended, Some((_, false, _)));
        self.transport.single() && self.given_remote.is_some() && (self.cfg.client || b_or_slave)
    }
}

/// -max_reconnect (-1 for ever), -reconnect_close and -reconnect_sleep.
struct Reconnect {
    left: i64,
    close: bool,
    sleep: Duration,
}

enum ArgsError {
    Exit(u8, String),
    /// An exit with nothing more to say.
    Quit(u8),
    /// A fatal error once the logs are set up, which it goes to.
    Logged(String, Box<Log>),
}

/// SIPp's get_time(): a number with an optional ms/s/m/h unit, seconds by default.
fn duration(opt: &str, v: &str) -> Result<Duration, String> {
    let split = v.find(|c: char| !c.is_ascii_digit() && c != '.').unwrap_or(v.len());
    let n: f64 = v[..split].parse().map_err(|_| format!("{opt}: invalid time '{v}'"))?;
    let ms = match &v[split..] {
        "ms" => n,
        "" | "s" => n * 1e3,
        "m" => n * 60e3,
        "h" => n * 3600e3,
        unit => return Err(format!("{opt}: unknown time unit '{unit}'")),
    };
    Ok(Duration::from_millis(ms as u64))
}

/// get_time() for the options whose unit defaults to milliseconds.
fn duration_ms(opt: &str, v: &str) -> Result<Duration, String> {
    if v.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.').is_empty() {
        return duration(opt, &format!("{v}ms"));
    }
    duration(opt, v)
}

/// An -inf file's name without the directory, which SIPp knows it by.
/// SIPp's scenario::setFileName(): the base name, less a ".xml".
fn scenario_stem(path: &str) -> String {
    let base = path.rsplit('/').next().unwrap_or(path);
    base.strip_suffix(".xml").unwrap_or(base).to_string()
}

fn inf_name(path: &str) -> String {
    path.rsplit(['/', '\\']).next().unwrap_or(path).to_string()
}

/// An -inf file's text, or SIPp's FileContents error.
fn inf_text(path: &str) -> Result<String, ArgsError> {
    let bytes = std::fs::read(raw::os(path)).map_err(|_| ArgsError::Exit(EXIT_FATAL_ERROR, format!("Unable to open file {path}")))?;
    Ok(raw::text_owned(bytes))
}

/// A scenario file's text, its <xi:include>s expanded, or SIPp's error.
fn scenario_file(path: &str) -> Result<String, ArgsError> {
    let bytes = std::fs::read(raw::os(path)).map_err(|_| ArgsError::Exit(EXIT_FATAL_ERROR, format!("Unable to load or parse '{path}' xml scenario file")))?;
    scenario::with_includes(scenario::xml_text(&bytes), path).map_err(|e| ArgsError::Exit(EXIT_FATAL_ERROR, e))
}

/// A built-in scenario by its -sn name.
fn builtin(name: &str) -> Option<&'static str> {
    match name {
        "uac" => Some(scenario::UAC),
        "uas" => Some(scenario::UAS),
        "uac_pcap" => Some(scenario::UAC_PCAP),
        "ooc_default" => Some(scenario::OOC_DEFAULT),
        "ooc_dummy" => Some(scenario::OOC_DUMMY),
        "regexp" => Some(scenario::REGEXP),
        "branchc" => Some(scenario::BRANCHC),
        "branchs" => Some(scenario::BRANCHS),
        other => scenario::BUILTIN_3PCC.iter().find(|(n, _)| *n == other).map(|(_, xml)| *xml),
    }
}

/// The scenario a call of `sc` plays, if the run has one.
fn scenario_of(args: &Args, sc: call::Sc) -> Option<&Scenario> {
    match sc {
        call::Sc::Main => Some(&args.scenario),
        call::Sc::Ooc => args.ooc.as_ref(),
        call::Sc::Rx => args.rx.as_ref(),
        call::Sc::Aa => args.aa.as_ref(),
    }
}

/// scenario::startsWith(): whether a call of the scenario can begin with
/// a new message: what its first <recv> expects, or an optional one
/// before it, past pauses and <nop>s; anything when it begins with
/// another step or has _unexp.main.
fn starts_with(scenario: &Scenario, raw: &str) -> bool {
    if scenario.unexpected_jump.is_some() {
        return true;
    }
    let Some(kind) = sip::kind(raw) else { return false };
    for step in &scenario.steps {
        let Op::Recv { expect, optional, .. } = &step.op else {
            // A <nop> first runs before the message is looked at.
            if let Op::Nop | Op::Pause(_) | Op::Timewait { .. } = step.op {
                continue;
            }
            return true;
        };
        let starts = match (expect, &kind) {
            (Expect::Request(m), sip::Kind::Request(k)) => m == k,
            (Expect::RequestRe(re), sip::Kind::Request(k)) => re.is_match(k),
            (Expect::Response(c), sip::Kind::Response(k)) => c == k && *k != 0,
            (Expect::ResponseRe(re), sip::Kind::Response(k)) => *k != 0 && re.is_match(&k.to_string()),
            _ => false,
        };
        if starts || !optional {
            return starts;
        }
    }
    true
}

/// The port of "host[:port]" or "[v6]:port", 0 if there is none, as
/// SIPp's get_host_and_port() takes it (atol()).
fn given_port(target: &str) -> u16 {
    let after = match target.find('[').and_then(|b| target[b..].find(']').map(|e| b + e)) {
        Some(e) => target[e..].split_once(':').map(|(_, p)| p),
        None => match target.split_once(':') {
            Some((_, p)) if !p.contains(':') => Some(p),
            _ => None,
        },
    };
    let digits = after.map_or("", |p| &p[..p.find(|c: char| !c.is_ascii_digit()).unwrap_or(p.len())]);
    digits.bytes().fold(0u32, |v, d| v.wrapping_mul(10).wrapping_add((d - b'0').into())) as u16
}

/// The NAPTR service and the SRV name prefix of a SIP transport
/// (RFC 3263); none for WebSocket.
fn sip_dns_service(transport: Transport) -> Option<(&'static str, &'static str)> {
    match transport {
        Transport::Udp | Transport::UdpMulti | Transport::UdpPerIp => Some(("SIP+D2U", "_sip._udp.")),
        Transport::TcpSingle | Transport::TcpMulti => Some(("SIP+D2T", "_sip._tcp.")),
        Transport::TlsSingle | Transport::TlsMulti => Some(("SIPS+D2T", "_sips._tcp.")),
        Transport::SctpSingle | Transport::SctpMulti => Some(("SIP+D2S", "_sip._sctp.")),
        Transport::WsSingle | Transport::WsMulti | Transport::WssSingle | Transport::WssMulti => None,
    }
}

/// The host of "host[:port]" or "[v6]:port"; a bare IPv6 address whole,
/// as SIPp's get_host_and_port().
fn host_part(target: &str) -> &str {
    if let Some(b) = target.find('[') {
        if let Some(e) = target[b + 1..].find(']') {
            return &target[b + 1..b + 1 + e];
        }
    }
    match target.split_once(':') {
        Some((h, p)) if !p.contains(':') => h,
        _ => target,
    }
}

/// CallGenerationTask::set_rate(): three times the calls a call length
/// holds at the rate.
fn open_calls_allowed(rate: f64, length_ms: f64, rate_period_ms: u64) -> usize {
    ((3.0 * rate * length_ms / rate_period_ms.max(1) as f64) as usize).max(1)
}

/// -cid_type: how Call-IDs are made.
#[derive(Clone, Copy, PartialEq)]
enum CidMode {
    Format,
    Uuid,
    UuidCompact,
    Random,
    Timestamp,
}

/// SIPp's CallIdBuilder: -cid_str's %u, %p, %s, %r and %%, or a -cid_type.
struct CallIds {
    format: String,
    mode: CidMode,
}

impl CallIds {
    fn make(&self, number: u64, pid: u32, ip: &str, rng: &mut Rng) -> String {
        let hex = |rng: &mut Rng, n: usize| -> Vec<u8> { (0..n).map(|_| rng.next_u32() as u8).collect() };
        let to_hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let micros = || SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_micros());
        match self.mode {
            CidMode::Uuid | CidMode::UuidCompact => {
                let mut b = hex(rng, 16);
                b[6] = (b[6] & 0x0f) | 0x40;
                b[8] = (b[8] & 0x3f) | 0x80;
                let sep = if self.mode == CidMode::Uuid { "-" } else { "" };
                let parts = [&b[..4], &b[4..6], &b[6..8], &b[8..10], &b[10..]].map(to_hex);
                format!("{}@{ip}", parts.join(sep))
            }
            CidMode::Random => format!("{number}-{}@{ip}", to_hex(&hex(rng, 16))),
            CidMode::Timestamp => format!("{}-{number}-{pid}@{ip}", micros()),
            CidMode::Format => {
                use std::fmt::Write;
                let mut out = String::with_capacity(self.format.len() + ip.len() + 32);
                let mut chars = self.format.chars();
                while let Some(c) = chars.next() {
                    if c != '%' {
                        out.push(c);
                        continue;
                    }
                    match chars.next() {
                        Some('u') => _ = write!(out, "{number}"),
                        Some('p') => _ = write!(out, "{pid}"),
                        // SIPp's local_ip, without an IPv6 address's brackets.
                        Some('s') => out += ip.trim_start_matches('[').trim_end_matches(']'),
                        Some('r') => _ = write!(out, "{}", rng.next_u32() >> 1),
                        // "%%", or a '%' ending the format: a '%'.
                        Some('%') | None => out.push('%'),
                        // Not a conversion: kept as it is.
                        Some(c) => {
                            out.push('%');
                            out.push(c);
                        }
                    }
                }
                // Kept by the call: no room to spare.
                out.shrink_to_fit();
                out
            }
        }
    }
}

/// Without -i, SIPp uses the address it would reach the remote host from,
/// or for a server the host name's first address.
/// get_long_long(): decimal, or hex after "0x", the whole value.
fn unsigned(arg: &str, v: &str) -> Result<u64, ArgsError> {
    let n = if let Some(hex) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        v.parse().ok()
    };
    n.ok_or_else(|| ArgsError::Exit(EXIT_FATAL_ERROR, format!("{arg}, \"{v}\" is not a valid integer!")))
}

/// get_bool(): true or false in any case, else a number, non-zero true.
fn boolean(arg: &str, v: &str) -> Result<bool, ArgsError> {
    match v.to_ascii_lowercase().as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => {
            let n = posix::integer(v);
            n.map(|n| n != 0).ok_or_else(|| ArgsError::Exit(EXIT_FATAL_ERROR, format!("{arg}, \"{v}\" is not a valid boolean!")))
        }
    }
}

/// A seed from the clock and the pid, for what SIPp leaves to rand().
fn seed_now() -> u64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    (now.as_nanos() as u64) ^ (u64::from(std::process::id()) << 32)
}

fn default_local_ip(remote: Option<SocketAddr>) -> IpAddr {
    let routed = remote.and_then(|r| {
        let s = UdpSocket::bind(if r.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }).ok()?;
        s.connect(r).ok()?;
        s.local_addr().ok().map(|a| a.ip())
    });
    routed
        .or_else(|| {
            let host = std::fs::read_to_string("/proc/sys/kernel/hostname").ok()?;
            (host.trim(), 0).to_socket_addrs().ok()?.map(|a| a.ip()).find(IpAddr::is_ipv4)
        })
        .unwrap_or(IpAddr::from([127, 0, 0, 1]))
}

/// The -trace_err log the options give: SIPp reads -trace_err,
/// -error_file and -error_overwrite before any other option, so that an
/// error in any goes to it.
#[derive(Default)]
struct ErrorLog {
    trace: bool,
    file: Option<String>,
    overwrite: Option<bool>,
}

/// SIPp's pass over the options for the -trace_err log, before the
/// others: what it got up to a bad -error_overwrite, and the error. It
/// skips what the next pass fails on, an unknown option or a missing
/// argument.
fn error_log(argv: &[String]) -> (ErrorLog, Option<String>) {
    let mut log = ErrorLog::default();
    let mut i = 0;
    while i < argv.len() {
        let Some(help::Opt(name, help::Kind::Args(n), _)) = help::find(&argv[i]) else {
            i += 1;
            continue;
        };
        if i + usize::from(*n) >= argv.len() {
            break;
        }
        match *name {
            "trace_err" => log.trace = true,
            "error_file" => log.file = Some(argv[i + 1].clone()),
            "error_overwrite" => match boolean(&argv[i], &argv[i + 1]) {
                Ok(b) => log.overwrite = Some(b),
                Err(ArgsError::Exit(_, e)) => return (log, Some(e)),
                Err(_) => unreachable!(),
            },
            _ => {}
        }
        i += usize::from(*n) + 1;
    }
    (log, None)
}

/// SIPp's first pass over the options, before it reads any: -h, -v
/// and -sd, which exit there, an unknown option, a missing argument and
/// the remote host's checks, in the order they are given.
fn first_pass(argv: &[String]) -> Result<(), ArgsError> {
    // SIPp reads -rfc3339 in pass -1, before any error of this pass.
    let rfc3339 = argv.iter().any(|a| a == "-rfc3339" || a == "--rfc3339");
    let fatal = |e: String| {
        fatal_before_run(argv, rfc3339, &e);
        ArgsError::Quit(EXIT_FATAL_ERROR)
    };
    let mut remote_host = None::<&String>;
    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        let Some(help::Opt(name, kind, _)) = help::find(arg) else {
            if arg.starts_with('-') {
                // As SIPp: the help on stdout, then the error.
                help::print();
                return Err(fatal(format!("Invalid argument: '{arg}'.\nUse 'sipp -h' for details")));
            }
            if let Some(first) = remote_host {
                return Err(fatal(format!("remote_host given multiple times on command-line ({first} and {arg})")));
            }
            remote_host = Some(arg);
            i += 1;
            continue;
        };
        match kind {
            help::Kind::Help if argv.get(i + 1).is_some_and(|a| a == "stat") => {
                return Err(ArgsError::Exit(EXIT_OTHER, help::STATS.strip_suffix('\n').unwrap_or(help::STATS).to_string()));
            }
            help::Kind::Help => {
                help::print();
                return Err(ArgsError::Quit(EXIT_OTHER));
            }
            // As SIPp's, the build's features after the version, which
            // scripts look for: SCTP on Linux alone.
            help::Kind::Version => {
                let sctp = if cfg!(target_os = "linux") { "-SCTP" } else { "" };
                let lua = if lua::BUILT_IN { "-LUA" } else { "" };
                return Err(ArgsError::Exit(EXIT_OTHER, format!("\n SIPp {}-rs-TLS{sctp}-PCAP{lua}.\n\n{COPYRIGHT}", env!("SIPP_VERSION"))));
            }
            help::Kind::Args(n) => {
                for _ in 0..*n {
                    i += 1;
                    if i >= argv.len() {
                        return Err(fatal(format!("Missing argument for param '{}'.\nUse 'sipp -h' for details", argv[i - 1])));
                    }
                }
            }
            help::Kind::Header | help::Kind::NeedSctp => {}
        }
        if *name == "sd" {
            let name = &argv[i];
            let xml = builtin(name).ok_or_else(|| fatal(format!("Invalid default scenario name '{name}'")))?;
            // Printed with a line end of its own.
            return Err(ArgsError::Exit(EXIT_OTHER, xml.strip_suffix('\n').unwrap_or(xml).to_string()));
        }
        i += 1;
    }
    Ok(())
}

fn parse_args(argv: &[String]) -> Result<Args, ArgsError> {
    let fatal = |e: String| ArgsError::Exit(EXIT_FATAL_ERROR, e);
    let mut xml = scenario::UAC.to_string();
    let mut scenario_name = "uac".to_string();
    let (mut scenario_given, mut max_calls_csv, mut rate_set) = (false, false, false);
    let mut scenario_dir = std::path::PathBuf::new();
    let (mut ip, mut port, mut service) = (None::<String>, None, "service".to_string());
    let (mut min_rtp_port, mut max_rtp_port, mut rtp_echo) = (6000u16, 65535u16, false);
    let (mut remote, mut max_calls, mut rate, mut rate_period_ms, mut limit, mut pause_ms) =
        (None, None, 10.0, 1000, usize::MAX, 0);
    let (mut timeout, mut timeout_error, mut recv_timeout, mut default_behaviors) = (None, false, None, call::BEHAVIOR_ALL);
    let mut auto_answer = false;
    let mut deadcall_wait = Duration::from_millis(33000);
    let mut sendbuffer_warn = false;
    let mut retrans = true;
    let (mut users, mut limit_set) = (None::<u32>, false);
    let (mut base_cseq, mut cid_format, mut cid_type) = (0u32, "%u-%p@%s".to_string(), None::<String>);
    // SIPp's UDP_MAX_RETRANS_INVITE_TRANSACTION and _NON_INVITE_, and T2.
    let (mut max_invite_retrans, mut max_non_invite_retrans, mut max_retrans) = (5u32, 9u32, 9u32);
    let mut t2 = Duration::from_millis(4000);
    let (mut media_ip, mut rtp_payload, mut sets) = (None::<(IpAddr, String)>, 8u8, Vec::<(String, String)>::new());
    let (mut pause_msg_ign, mut callid_slash_ign, mut lost, mut rsa) = (false, false, 0.0f64, None::<SocketAddr>);
    let (mut remote_arg, mut rsa_arg) = (None::<String>, None::<String>);
    let mut tdm = None;
    let (mut bind_local, mut round_robin) = (false, false);
    let (mut random_base_ssrc, mut bind_device, mut rtcheck_loose) = (false, None::<String>, false);
    let mut periodic_rtd = false;
    let mut reconnect = Reconnect { left: 0, close: true, sleep: Duration::from_millis(1000) };
    let mut log_limits = log::Limits::default();
    let (mut audio_tolerance, mut video_tolerance) = (1.0f64, 1.0f64);
    let mut sctp = net::SctpOptions::default();
    let (mut rate_increase, mut rate_max, mut rate_interval, mut rate_quit) = (None, None, None, true);
    let (mut background, mut sleep) = (false, Duration::ZERO);
    let (mut max_socket, mut ip_field) = (50000usize, 0usize);
    let mut recv_loops = 1000usize;
    let mut skip_rlimit = false;
    let mut remote_host = String::new();
    let (mut nostdin, mut control_ip, mut rate_scale) = (false, None::<String>, 1.0f64);
    let (mut extended, mut slave_cfg_file) = (None::<(String, bool)>, None::<HashMap<String, String>>);
    let mut tls_options = net::TlsOptions { handshake_timeout: Duration::from_secs(10), ..Default::default() };
    let (mut ws_path, mut ws_timeout) = (String::from("/"), Duration::from_secs(10));
    let (mut ooc_xml, mut rx_xml, mut rx_inject) = (None::<String>, None::<String>, infile::Injection::default());
    // The -oocsf, -rxsf and -sf files, which SIPp's XML errors name.
    let mut side_files: [Option<String>; 3] = Default::default();
    // The -oocsf/-oocsn and -rxsf/-rxsn scenarios' names, for -trace_rtt.
    let mut side_names: [Option<String>; 2] = Default::default();
    let (mut rfc3339, mut stat_delimiter) = (false, ";".to_string());
    let (mut trace_short, mut short_file, mut trace_screen, mut screen_file) = (false, None, false, None);
    let (mut trace_calldebug, mut calldebug_file) = (false, None);
    let (mut trace_counts, mut trace_codes, mut trace_rtt, mut rtt_freq) = (false, false, false, 200usize);
    let (mut trace_msg, mut trace_err, mut trace_logs) = (false, false, false);
    let (mut message_file, mut error_file, mut log_file) = (None, None, None);
    // -X_overwrite, by X.
    let mut overwrite = HashMap::new();
    let mut keys = HashMap::new();
    let mut lua_file: Option<String> = None;
    let mut transport = Transport::Udp;
    let mut twin = None;
    let (mut tls_cert, mut tls_key) = (None, None);
    let mut inject = infile::Injection::default();
    let (mut auth_user, mut auth_pass, mut auth_uri) = (None, "password".to_string(), None);
    let (mut control_port, mut trace_stat, mut stat_file, mut stat_period) = (None, false, None, Duration::from_secs(60));
    let (mut watchdog, mut timer_resol) = (Duration::from_millis(400), Duration::from_millis(1));
    if argv.is_empty() {
        help::print();
        return Err(ArgsError::Quit(EXIT_OTHER));
    }
    // Before -rfc3339 is read.
    if let (_, Some(e)) = error_log(argv) {
        fatal_before_run(argv, false, &e);
        return Err(ArgsError::Quit(EXIT_FATAL_ERROR));
    }
    first_pass(argv)?;

    // Scenario files are SIPp's pass 2: an error in them comes after
    // any in the options of pass 1, wherever they are given.
    let mut late = None::<ArgsError>;
    let mut it = argv.iter();
    while let Some(arg) = it.next() {
        let mut val = || it.next().ok_or_else(|| fatal(format!("Missing argument for param '{arg}'.\nUse 'sipp -h' for details")));
        // get_long() and get_double(): an integer is decimal, or hex after
        // "0x", and fits the option; in SIPp's words when it is none.
        fn num<T: std::str::FromStr>(opt: &str, v: &str) -> Result<T, ArgsError> {
            let float = std::any::type_name::<T>().starts_with('f');
            let n = if float { v.parse().ok() } else { posix::integer(v).and_then(|n| n.to_string().parse().ok()) };
            let what = if float { "is not a floating point number" } else { "is not a valid integer" };
            n.ok_or_else(|| ArgsError::Exit(EXIT_FATAL_ERROR, format!("{opt}, \"{v}\" {what}!")))
        }
        // As SIPp, "--name" is "-name".
        let opt = if arg.starts_with("--") { &arg[1..] } else { arg.as_str() };
        match opt {
            "-oocsf" | "-rxsf" => {
                let path = val()?;
                let text = match scenario_file(path) {
                    Ok(t) => t,
                    Err(e) => {
                        late.get_or_insert(e);
                        continue;
                    }
                };
                if opt == "-oocsf" { ooc_xml = Some(text) } else { rx_xml = Some(text) }
                side_files[usize::from(opt == "-rxsf")] = Some(path.clone());
                side_names[usize::from(opt == "-rxsf")] = Some(scenario_stem(path));
            }
            "-oocsn" | "-rxsn" => {
                let name = val()?;
                let Some(xml) = builtin(name) else {
                    late.get_or_insert(fatal(format!("Invalid default scenario name '{name}'")));
                    continue;
                };
                if opt == "-oocsn" { ooc_xml = Some(xml.to_string()) } else { rx_xml = Some(xml.to_string()) }
                side_names[usize::from(opt != "-oocsn")] = Some(scenario_stem(name));
            }
            "-rxinf" => {
                let path = val()?;
                // In SIPp, -inf and -rxinf files are all known by base name.
                rx_inject.add(inf_name(path), infile::InFile::parse(path, &inf_text(path)?).map_err(fatal)?);
            }
            "-sn" | "-sf" if scenario_given => {
                val()?;
                return Err(fatal("Only one scenario may be given: -sf and -sn can't be combined or repeated".into()));
            }
            "-sn" => {
                scenario_given = true;
                let name = val()?;
                xml = builtin(name).ok_or_else(|| fatal(format!("Invalid default scenario name '{name}'")))?.to_string();
                scenario_name = name.clone();
            }
            "-sf" => {
                scenario_given = true;
                let path = val()?;
                xml = match scenario_file(path) {
                    Ok(t) => t,
                    Err(e) => {
                        late.get_or_insert(e);
                        continue;
                    }
                };
                side_files[2] = Some(path.clone());
                let p = std::path::Path::new(path);
                // SIPp's getPath(): empty for a name without a directory.
                scenario_dir = p.parent().map(|d| d.to_path_buf()).unwrap_or_default();
                scenario_name = scenario_stem(path);
            }
            // SIPp's IP options drop a port and an IPv6 address's
            // brackets, and resolve what is left.
            "-i" => {
                let v = val()?;
                ip = Some(host_part(v).to_string()).filter(|i| !i.is_empty());
            }
            "-p" => port = Some(num(arg, val()?)?),
            "-s" => service = val()?.clone(),
            "-mp" | "-min_rtp_port" => min_rtp_port = num(arg, val()?)?,
            "-max_rtp_port" => max_rtp_port = num(arg, val()?)?,
            "-rtp_echo" => rtp_echo = true,
            "-m" => max_calls = Some(num(arg, val()?)?),
            "-m_csv" => max_calls_csv = true,
            "-r" => {
                rate = num(arg, val()?)?;
                rate_set = true;
            }
            "-rp" => rate_period_ms = num(arg, val()?)?,
            "-l" => {
                let v = val()?;
                // SIPp's check, of a -users before it.
                if users.is_some() {
                    return Err(fatal("Can not set open call limit (-l) when -users is specified.".into()));
                }
                limit = num(arg, v)?;
                limit_set = true;
            }
            "-users" => users = Some(num(arg, val()?)?),
            "-d" => pause_ms = num(arg, val()?)?,
            "-recv_timeout" => recv_timeout = Some(Duration::from_millis(num(arg, val()?)?)),
            "-timeout" => timeout = Some(duration(arg, val()?).map_err(fatal)?),
            "-timeout_error" => timeout_error = true,
            "-plugin" => plugin::load(val()?).map_err(fatal)?,
            "-lua_file" => lua_file = Some(val()?.clone()),
            "-key" => {
                let name = val()?.clone();
                keys.insert(name, val()?.clone());
            }
            "-nd" => default_behaviors = 0,
            "-default_behaviors" => default_behaviors = call::parse_behaviors(val()?).map_err(fatal)?,
            "-aa" => auto_answer = true,
            "-sendbuffer_warn" => sendbuffer_warn = boolean(arg, val()?)?,
            "-nr" => retrans = false,
            // SIPp keeps [cseq] one below the value, the first request adding one.
            "-base_cseq" => base_cseq = num::<u32>(arg, val()?)?.wrapping_sub(1),
            "-cid_str" => cid_format = val()?.clone(),
            // Checked once the options are read, the last one given.
            "-cid_type" => cid_type = Some(val()?.clone()),
            "-max_retrans" => max_retrans = num(arg, val()?)?,
            "-max_invite_retrans" => max_invite_retrans = num(arg, val()?)?,
            "-max_non_invite_retrans" => max_non_invite_retrans = num(arg, val()?)?,
            "-T2" => t2 = duration_ms(arg, val()?).map_err(fatal)?,
            "-mi" => {
                let v = val()?;
                let host = host_part(v);
                let unknown = || fatal(format!("Unknown RTP address '{host}'.\nUse 'sipp -h' for details"));
                media_ip = Some((dns::addresses(host).map_err(|_| unknown())?[0], host.to_string()));
            }
            "-rtp_payload" => rtp_payload = num(arg, val()?)?,
            "-max_socket" => max_socket = num(arg, val()?)?,
            "-max_recv_loops" => recv_loops = num(arg, val()?)?,
            "-buff_size" => net::set_buff_size(num(arg, val()?)?),
            "-ip_field" => ip_field = num(arg, val()?)?,
            "-set" => {
                let name = val()?.clone();
                sets.push((name, val()?.clone()));
            }
            "-rate_increase" => rate_increase = Some(num(arg, val()?)?),
            "-rate_max" => rate_max = Some(num(arg, val()?)?),
            "-rate_interval" => rate_interval = Some(duration(arg, val()?).map_err(fatal)?),
            "-no_rate_quit" => rate_quit = false,
            "-bg" => background = true,
            "-rfc3339" => rfc3339 = true,
            "-stat_delimiter" => stat_delimiter = val()?.clone(),
            "-sleep" => sleep = duration(arg, val()?).map_err(fatal)?,
            "-pause_msg_ign" => pause_msg_ign = true,
            "-callid_slash_ign" => callid_slash_ign = true,
            "-lost" => lost = num(arg, val()?)?,
            "-bind_local" => bind_local = true,
            "-round_robin" => round_robin = true,
            "-random_base_ssrc" => random_base_ssrc = true,
            "-periodic_rtd" => periodic_rtd = true,
            "-max_reconnect" => reconnect.left = num(arg, val()?)?,
            "-reconnect_close" => reconnect.close = boolean(arg, val()?)?,
            "-reconnect_sleep" => reconnect.sleep = duration_ms(arg, val()?).map_err(fatal)?,
            "-max_log_size" => log_limits.max_size = unsigned(arg, val()?)?,
            "-ringbuffer_size" => log_limits.ring_size = unsigned(arg, val()?)?,
            "-ringbuffer_files" => log_limits.ring_files = num(arg, val()?)?,
            "-audiotolerance" => audio_tolerance = num(arg, val()?)?,
            "-videotolerance" => video_tolerance = num(arg, val()?)?,
            "-bind_to_device" => bind_device = Some(val()?.clone()),
            // The SCTP options of a SIPp built without it.
            "-multihome" | "-heartbeat" | "-assocmaxret" | "-pathmaxret" | "-pmtu" | "-gracefulclose" if !cfg!(target_os = "linux") => {
                return Err(fatal(format!("SCTP support is required for the {arg} option.")));
            }
            "-multihome" => {
                let v = val()?;
                let host = host_part(v);
                sctp.multihome = Some(dns::addresses(host).map_err(|_| fatal(format!("Can't get multihome IP address in getaddrinfo, multihome_ip='{host}'")))?[0]);
            }
            "-heartbeat" => sctp.heartbeat = num(arg, val()?)?,
            "-assocmaxret" => sctp.assocmaxret = num(arg, val()?)?,
            "-pathmaxret" => sctp.pathmaxret = num(arg, val()?)?,
            "-pmtu" => sctp.pmtu = num(arg, val()?)?,
            "-rtcheck" => {
                rtcheck_loose = match val()?.as_str() {
                    "full" => false,
                    "loose" => true,
                    other => return Err(fatal(format!("Unknown retransmission detection method: {other}"))),
                }
            }
            "-gracefulclose" => sctp.graceful = boolean(arg, val()?)?,
            "-dynamicStart" => {
                let start = num(arg, val()?)?;
                template::dynamic::START.store(start, Ordering::Relaxed);
                template::dynamic::NEXT.store(start, Ordering::Relaxed);
            }
            "-dynamicMax" => template::dynamic::MAX.store(num(arg, val()?)?, Ordering::Relaxed),
            "-dynamicStep" => template::dynamic::STEP.store(num(arg, val()?)?, Ordering::Relaxed),
            "-tdmmap" => tdm = Some(tdm::TdmMap::parse(val()?).map_err(fatal)?),
            "-rsa" => {
                let v = val()?;
                // Resolved once -i is known.
                rsa_arg = Some(v.clone());
            }
            // Timing and resource knobs of SIPp's scheduler and sockets, which
            // sipp-rs has no counterpart of.
            "-deadcall_wait" => deadcall_wait = duration_ms(arg, val()?).map_err(fatal)?,
            "-watchdog_interval" => watchdog = duration_ms(arg, val()?).map_err(fatal)?,
            "-timer_resol" => timer_resol = duration_ms(arg, val()?).map_err(fatal)?,
            "-send_timeout" | "-max_sched_loops"
            | "-watchdog_reset" | "-watchdog_minor_threshold" | "-watchdog_major_threshold"
            | "-watchdog_minor_maxtriggers" | "-watchdog_major_maxtriggers"
            | "-rtp_buffsize" | "-f" => {
                val()?;
            }
            "-skip_rlimit" => skip_rlimit = true,
            "-trace_msg" => trace_msg = true,
            "-trace_err" => trace_err = true,
            "-trace_logs" => trace_logs = true,
            "-trace_shortmsg" => trace_short = true,
            "-trace_calldebug" => trace_calldebug = true,
            "-calldebug_file" | "-shortmessage_file" | "-screen_file" | "-message_file" | "-error_file" | "-log_file" => {
                let name = Some(val()?.clone());
                match opt {
                    "-calldebug_file" => calldebug_file = name,
                    "-shortmessage_file" => short_file = name,
                    "-screen_file" => screen_file = name,
                    "-message_file" => message_file = name,
                    "-error_file" => error_file = name,
                    "-log_file" => log_file = name,
                    _ => unreachable!(),
                }
            }
            "-trace_screen" => trace_screen = true,
            "-trace_counts" => trace_counts = true,
            "-trace_error_codes" => trace_codes = true,
            "-trace_rtt" => trace_rtt = true,
            "-rtt_freq" => rtt_freq = num(arg, val()?)?,
            // false: the log is added to when it is first opened.
            "-message_overwrite" | "-error_overwrite" | "-log_overwrite" | "-screen_overwrite" | "-shortmessage_overwrite"
            | "-calldebug_overwrite" => {
                let kind = &opt[1..opt.len() - "_overwrite".len()];
                overwrite.insert(kind.to_string(), boolean(arg, val()?)?);
            }
            "-t" => {
                let v = val()?;
                // SIPp's check: a transport's letter, then 1, n or i.
                let b = v.as_bytes();
                if b.len() != 2 || !b"utslwx".contains(&b[0]) || !b"1ni".contains(&b[1]) {
                    return Err(fatal(format!("Invalid argument for -t param : '{v}'.\nUse 'sipp -h' for details")));
                }
                // Linux alone has SCTP: elsewhere, as a SIPp built without it.
                if b[0] == b's' && !cfg!(target_os = "linux") {
                    return Err(fatal("To use SCTP transport you must compile SIPp with lksctp".into()));
                }
                transport = match v.as_str() {
                    "u1" => Transport::Udp,
                    "un" => Transport::UdpMulti,
                    "ui" => Transport::UdpPerIp,
                    "t1" => Transport::TcpSingle,
                    "tn" => Transport::TcpMulti,
                    "l1" => Transport::TlsSingle,
                    "ln" => Transport::TlsMulti,
                    "s1" => Transport::SctpSingle,
                    "sn" => Transport::SctpMulti,
                    "w1" => Transport::WsSingle,
                    "wn" => Transport::WsMulti,
                    "x1" => Transport::WssSingle,
                    "xn" => Transport::WssMulti,
                    _ => return Err(fatal("You can only use a perip socket with UDP!".into())),
                }
            }
            "-nostdin" => nostdin = true,
            "-rtp_threadtasks" => media::counters::TASKS_PER_THREAD.store(num(arg, val()?)?, Ordering::Relaxed),
            "-mb" => media::counters::MEDIA_BUFSIZE.store(num(arg, val()?)?, Ordering::Relaxed),
            "-ci" => {
                let v = val()?;
                control_ip = Some(host_part(v).to_string());
            }
            "-rate_scale" => rate_scale = num(arg, val()?)?,
            // SIPp's SRTP/RTP debug dumps; they don't change the run.
            // rtp_echo's, the SRTP parameters and -rtpcheck_debug's are
            // written, not the SRTP contexts' srtpctxdebugfile.
            "-srtpcheck_debug" => media::echo_debug::ON.store(true, Ordering::Relaxed),
            "-rtpcheck_debug" => media::rtp_debug::ON.store(true, Ordering::Relaxed),
            "-inf" => {
                let path = val()?;
                // Known by its name without the directory, as in SIPp.
                inject.add(inf_name(path), infile::InFile::parse(path, &inf_text(path)?).map_err(fatal)?);
            }
            "-infindex" => {
                let file = val()?.clone();
                let field = val()?;
                let field: usize = field.parse().map_err(|_| fatal(format!("Invalid field specification for -infindex: {field}")))?;
                inject.get_mut(&file).ok_or_else(|| fatal(format!("Could not find file for -infindex: {file}")))?.build_index(field);
            }
            "-tls_cert" => tls_cert = Some(val()?.clone()),
            "-tls_ca" => tls_options.ca = Some(val()?.clone()),
            "-tls_crl" => tls_options.crl = Some(val()?.clone()),
            "-tls_version" => tls_options.version = Some(num(arg, val()?)?),
            "-tls_key" => tls_key = Some(val()?.clone()),
            "-tls_handshake_timeout" => tls_options.handshake_timeout = duration_ms(arg, val()?).map_err(fatal)?,
            "-ws_path" => ws_path = val()?.clone(),
            "-ws_handshake_timeout" => ws_timeout = duration_ms(arg, val()?).map_err(fatal)?,
            "-au" => auth_user = Some(val()?.clone()),
            "-ap" => auth_pass = val()?.clone(),
            "-auth_uri" => auth_uri = Some(val()?.clone()),
            // SIPp checks these against the ones before them only.
            "-3pcc" => {
                if extended.is_some() {
                    return Err(fatal("-3PCC option is not compatible with -master/-primary and -slave/-secondary options".into()));
                }
                if slave_cfg_file.is_some() {
                    return Err(fatal("-3pcc and -slave_cfg/-secondary_cfg options are not compatible".into()));
                }
                let v = val()?;
                twin = Some(v.clone());
            }
            "-cp" => control_port = Some(num(arg, val()?)?),
            "-master" | "-primary" | "-slave" | "-secondary" => {
                let name = val()?.clone();
                if extended.is_some() {
                    return Err(fatal("-slave/-secondary and -master/-primary options are not compatible".into()));
                }
                if twin.is_some() {
                    return Err(fatal("-master/-primary and -slave/-secondary options are not compatible with -3PCC option".into()));
                }
                extended = Some((name, opt == "-master" || opt == "-primary"));
            }
            "-slave_cfg" | "-secondary_cfg" => {
                let file = val()?.clone();
                if twin.is_some() {
                    return Err(fatal("-slave_cfg/-secondary_cfg and -3pcc options are not compatible".into()));
                }
                // parse_slave_cfg(), there and then.
                slave_cfg_file = Some(slave_cfg(&file).map_err(fatal)?);
            }
            "-trace_stat" => trace_stat = true,
            "-stf" => stat_file = Some(val()?.clone()),
            "-fd" => stat_period = duration(arg, val()?).map_err(fatal)?,
            _ if arg.starts_with('-') => {
                // As SIPp: the help on stdout, then the error.
                help::print();
                return Err(fatal(format!("Invalid argument: '{arg}'.\nUse 'sipp -h' for details")));
            }
            host => {
                // first_pass() checked it.
                remote_host = host_part(host).to_string();
                remote_arg = Some(host.to_string());
            }
        }
    }
    if let Some(e) = late {
        return Err(e);
    }
    let ow = |kind: &str| overwrite.get(kind).copied().unwrap_or(true);

    let names = inject.names().chain(rx_inject.names()).map(str::to_string).collect();
    let mut checks = scenario::Checks::default();
    checks.inject = (names, inject.default_name().map(str::to_string));
    checks.file = side_files[2].take();
    checks.peers = slave_cfg_file.as_ref().map(|m| m.keys().cloned().collect()).unwrap_or_default();
    let mut scenario = scenario::parse_checked(&xml, &keys, rtp_payload, &mut checks).map_err(fatal)?;
    if tdm.is_none() && xml.contains("[tdmmap]") {
        return Err(fatal("[tdmmap] keyword without -tdmmap parameter on command line".into()));
    }
    // SIPp's call length for its default -l: the pauses' 99th percentiles
    // added up, -d for those that take it, and at least a second.
    let length: f64 = scenario
        .steps
        .iter()
        .map(|s| match &s.op {
            Op::Pause(scenario::PauseLen::Dist(d)) => d.p99(),
            Op::Pause(scenario::PauseLen::Default) => pause_ms as f64,
            _ => 0.0,
        })
        .sum();
    let auto_limit = (!limit_set && users.is_none()).then_some(length.max(pause_ms as f64).max(1000.0));
    let mut side = |xml: Option<String>, file: Option<String>| -> Result<Option<Scenario>, ArgsError> {
        checks.file = file;
        xml.map(|x| scenario::parse_checked(&x, &keys, rtp_payload, &mut checks).map_err(fatal)).transpose()
    };
    let [ooc_file, rx_file, _] = side_files;
    let (ooc, rx) = (side(ooc_xml, ooc_file)?, side(rx_xml, rx_file)?);
    let aa = side(auto_answer.then(|| scenario::OOC_DUMMY.to_string()), None)?;
    let has_media = [Some(&scenario), ooc.as_ref(), rx.as_ref()].into_iter().flatten().any(Scenario::has_media);
    let counts_received = [Some(&scenario), ooc.as_ref(), rx.as_ref()].into_iter().flatten().filter_map(Scenario::counts_received).reduce(|a, b| a | b);
    for (name, _) in &sets {
        if !scenario.global_vars.contains(name) {
            return Err(fatal(format!("Can not set the global variable {name}, because it does not exist.")));
        }
    }
    if !scenario.steps.iter().any(|s| matches!(s.op, Op::Send { .. } | Op::Recv { .. } | Op::SendCmd { .. } | Op::RecvCmd { .. })) {
        return Err(fatal("Unable to determine creation mode of the tool (server, client)".into()));
    }
    if let Some(file) = &lua_file {
        lua::load(file).map_err(fatal)?;
    }
    // SIPp lowercases the mode first.
    let cid_mode = match cid_type.as_deref().map(str::to_ascii_lowercase).as_deref() {
        None | Some("default" | "format" | "legacy") => CidMode::Format,
        Some("uuid") => CidMode::Uuid,
        Some("uuid-compact" | "uuidcompact" | "uuid32") => CidMode::UuidCompact,
        Some("random" | "random-hex") => CidMode::Random,
        Some("timestamp" | "time") => CidMode::Timestamp,
        Some(_) => {
            let given = cid_type.unwrap_or_default();
            return Err(fatal(format!("Unknown Call-ID mode '{given}'. Use default, format, legacy, uuid, uuid-compact, uuidcompact, uuid32, random, random-hex, timestamp, or time.")));
        }
    };
    // computeSippMode(). A client sends the first SIP message (a 3PCC
    // controller may get a command first); a scenario with no SIP is a
    // server, which needs no remote host.
    let first = |f: fn(&Op) -> bool| scenario.steps.iter().map(|s| &s.op).find(|op| f(op));
    let send_mode = first(|op| matches!(op, Op::Send { .. } | Op::Recv { .. })).map(|op| matches!(op, Op::Send { .. }));
    let client = send_mode == Some(true);
    // Calls are started by rate when the first message or command sends.
    let creates = matches!(
        first(|op| matches!(op, Op::Send { .. } | Op::Recv { .. } | Op::SendCmd { .. } | Op::RecvCmd { .. })),
        Some(Op::Send { .. } | Op::SendCmd { .. })
    );
    // The first command: a <sendCmd> for controller A or a master.
    let first_cmd = first(|op| matches!(op, Op::SendCmd { .. } | Op::RecvCmd { .. }));
    let (uses_twin, drives_twin) = (first_cmd.is_some(), matches!(first_cmd, Some(Op::SendCmd { .. })));
    let extended = match (extended, slave_cfg_file) {
        (Some((name, master)), Some(addrs)) => Some((name, master, addrs)),
        (Some(_), None) | (None, Some(_)) => {
            return Err(fatal("-slave_cfg/-secondary_cfg option must be used with -slave/-secondary or -master/-primary option".into()))
        }
        (None, None) => None,
    };
    if max_calls_csv {
        let lines = inject.default_name().and_then(|n| inject.get(n)).map(|f| f.lines());
        let lines = lines.ok_or_else(|| fatal("-m_csv needs an -inf file".into()))?;
        if max_calls.is_some() {
            return Err(fatal("-m and -m_csv are mutually exclusive".into()));
        }
        max_calls = Some(lines as u64);
    }
    if let Some((_, master, _)) = &extended {
        if uses_twin && drives_twin && !master {
            return Err(fatal("Inconsistency between command line and scenario: master scenario but -master/-primary option not set".into()));
        }
        if uses_twin && !drives_twin && *master {
            return Err(fatal("Inconsistency between command line and scenario: slave scenario but -slave/-secondary option not set".into()));
        }
    }
    if uses_twin && twin.is_none() && extended.is_none() {
        return Err(fatal(match drives_twin {
            true => "sendCmd message found in scenario but no twin sipp address has been passed! Use -3pcc option or 3pcc extended mode".into(),
            false => "recvCmd message found in scenario but no twin sipp address has been passed! Use -3pcc option\n".into(),
        }));
    }
    // A name takes an address in the family of -i when it has one.
    let prefer_v6 = ip.as_deref().and_then(|i| dns::addresses(i).ok()).map(|a| a[0].is_ipv6());
    // SIPp's texts; "Done." comes as the run starts, where SIPp resolves
    // the remote host.
    let unknown = |host: &str| fatal(format!("Unknown remote host '{host}'.\nUse 'sipp -h' for details"));
    if let Some(v) = rsa_arg {
        println!("Resolving remote sending address {}...", host_part(&v));
        let target = if v.contains(':') { v.clone() } else { format!("{v}:5060") };
        rsa = net::resolve(target.as_str(), prefer_v6).ok().flatten();
        if rsa.is_none() {
            return Err(unknown(host_part(&v)));
        }
    }
    let mut srv_note = String::new();
    // open_connections() refuses -round_robin with a single connection
    // before it resolves the remote host.
    let refused = (round_robin && transport.single() && remote_arg.is_some()).then(|| "-round_robin needs UDP or one socket per call (-t un, tn, ln...)".to_string());
    let mut remotes = Vec::new();
    let mut unknown_remote = None::<String>;
    if let Some(host) = remote_arg.filter(|_| refused.is_none()) {
        // A host name without a port: its NAPTR and SRV records first
        // (RFC 3263), for the transport of -t, taking the first target
        // that resolves.
        let port = given_port(&host);
        let (mut records, mut srv_name, mut naptr) = (Vec::new(), String::new(), false);
        if let (0, false, Some((service, prefix))) = (port, dns::is_numeric_host(&remote_host), sip_dns_service(transport)) {
            let mut rng = call::Rng::new(seed_now());
            (records, srv_name, naptr) = dns::sip_srv_lookup(&remote_host, service, prefix, &mut |n| (rng.next_u32() as u64 % (n as u64 + 1)) as u32);
        }
        if records.len() == 1 && records[0].target == "." {
            eprint!("Resolving remote host '{remote_host}'... ");
            return Err(fatal(format!("SRV {srv_name}: the service is not available")));
        }
        // gai_getsockaddr(): a warning for each name that does not resolve.
        let resolve = |host: &str, port: u16| match net::resolve((host, port), prefer_v6) {
            Ok(addr) => addr,
            Err(e) => {
                let e = e.to_string();
                log::defer_warning(format!("getaddrinfo failed: {}", e.strip_prefix("failed to lookup address information: ").unwrap_or(&e)));
                None
            }
        };
        let mut resolved_host = remote_host.as_str();
        if records.is_empty() {
            remote = resolve(&remote_host, if port == 0 { 5060 } else { port });
        }
        for r in records.iter().filter(|r| r.port != 0 && r.target != ".") {
            if let Some(addr) = resolve(&r.target, r.port) {
                remote = Some(addr);
                resolved_host = &r.target;
                srv_note = format!("{}SRV {srv_name}: {}:{}. ", if naptr { "NAPTR, " } else { "" }, r.target, r.port);
                break;
            }
        }
        if remote.is_none() {
            // open_connections() fails with its screens up, below.
            unknown_remote = Some(format!("Unknown remote host '{remote_host}'.\nUse 'sipp -h' for details"));
        }
        // get_remote_addresses(): with -round_robin, every address of the
        // name that resolved (the SRV target's), in the family of the
        // first, which the calls take in turn.
        if let (true, Some(first)) = (round_robin, remote) {
            remotes = (resolved_host, first.port()).to_socket_addrs().map_or(Vec::new(), |a| a.filter(|a| a.is_ipv6() == first.is_ipv6()).collect());
            remote = remotes.first().copied().or(remote);
            if remotes.len() > 1 {
                srv_note += &format!("{} addresses. ", remotes.len());
            }
        }
    }
    if client && remote.is_none() && refused.is_none() && unknown_remote.is_none() {
        return Err(fatal("Missing remote host parameter. This scenario requires it".into()));
    }
    // Once the trace files are open, as SIPp's check: it writes their
    // last statistics.
    let setup_error = (ooc.is_some() && !client).then(|| "SIPp cannot use out-of-call scenarios when running in server mode".to_string());
    // Controller B, a slave, or a server's controller A or master: a
    // command that no call waits for starts one, which sends to the
    // remote host if there is one.
    let cmd_starts = uses_twin && (!drives_twin || !creates);
    let given_remote = remote;
    let remote = remote.filter(|_| client);
    if transport == Transport::UdpPerIp && inject.default_name().is_none() {
        return Err(fatal("You must use the -inf option when using -t ui.\nUse 'sipp -h' for details".into()));
    }
    let mut local_error = None;
    let (mut bind_ip, local_ip) = match &ip {
        Some(text) => {
            let ip = local_address(text, given_remote).unwrap_or_else(|(ip, e)| {
                local_error = Some(e);
                ip
            });
            (ip, ip)
        }
        // -bind_local: the address SIPp works out, rather than all of them.
        None => {
            let local = default_local_ip(remote);
            // SIPp binds on any address of the local IP's family.
            let any = if local.is_ipv6() { IpAddr::from([0u16; 8]) } else { IpAddr::from([0, 0, 0, 0]) };
            (if bind_local { local } else { any }, local)
        }
    };
    let local_error = refused.or(unknown_remote.clone()).or(local_error);
    let pid = std::process::id();
    let file = |name: Option<String>, kind: &str| name.unwrap_or_else(|| format!("{scenario_name}_{pid}_{kind}.log"));
    let mut log = Log::default();
    log.rfc3339 = rfc3339;
    log.callid_slash_ign = callid_slash_ign;
    if log_limits.ring_size > 0 && log_limits.max_size > 0 {
        return Err(fatal("Ring Buffer options and maximum log size are mutually exclusive.".into()));
    }
    log.limits = log::Limits { scenario: scenario_name.clone(), pid, ..log_limits };
    // SIPp reads the captures and rtp_stream files as it loads the
    // scenario: before it has a name for its files, and before them.
    log.errors = log::Sink::new(error_file.clone().unwrap_or_else(|| format!("sipp_{pid}_errors.log")), "errors", ow("error"));
    log.print_all = trace_err;
    if let Err(e) = scenario.load_pcaps(&scenario_dir, &mut log) {
        return Err(ArgsError::Logged(e, Box::new(log)));
    }
    // Each log named even when off, for the trace command to turn it on.
    // Those on are opened in SIPp's order, the first that can't be ending
    // the run.
    log.errors.path = file(error_file, "errors");
    let limits = log.limits.clone();
    let sink = |path: String, kind: &'static str, on: bool| {
        // -message_overwrite for the messages, -log_overwrite for the logs.
        let mut sink = log::Sink::new(path, kind, ow(kind.trim_end_matches('s')));
        if on && sink.rotate(&limits).is_err() {
            return Err(format!("Unable to create '{}'", sink.path));
        }
        Ok(sink)
    };
    let csv = |on: bool, kind: &str| {
        let path = format!("{scenario_name}_{pid}_{kind}.csv");
        on.then(|| File::create(&path).map_err(|_| format!("Unable to create '{path}'"))).transpose()
    };
    // SIPp writes the counts' header as it opens their file: one it fails
    // on, that of a <recv> without request or response, ends the run.
    let counts_csv = || {
        let mut f = csv(trace_counts, "counts")?;
        let lose = lost > 0.0 || scenario.steps.iter().any(|s| s.lost.is_some());
        if let (Some(f), Err(part)) = (f.as_mut(), screen::counts(&scenario, None, &stat_delimiter, rfc3339, lose)) {
            let _ = raw::write(f, &part);
            return Err("Unknown count file message type:".to_string());
        }
        Ok(f)
    };
    let opened = (|| {
        let logs = sink(file(log_file, "logs"), "logs", trace_logs)?;
        let messages = sink(file(message_file, "messages"), "messages", trace_msg)?;
        let short = sink(file(short_file, "shortmessages"), "shortmessages", trace_short)?;
        let calldebug = sink(file(calldebug_file, "calldebug"), "calldebug", trace_calldebug)?;
        let screen = sink(file(screen_file, "screen"), "screen", trace_screen)?;
        Ok((logs, messages, short, calldebug, screen, counts_csv()?, csv(trace_codes, "error_codes")?))
    })();
    let (logs, messages, short, calldebug, screen_log, counts_file, codes_file) = match opened {
        Ok(o) => o,
        Err(e) => return Err(ArgsError::Logged(e, Box::new(log))),
    };
    (log.logs, log.messages, log.short, log.calldebug) = (logs, messages, short, calldebug);
    let screen_file = trace_screen.then(|| screen_log.path.clone());
    // Each scenario's own, named after it, as its RTD names are its own.
    let rtt_paths = [Some(&scenario_name), side_names[0].as_ref(), side_names[1].as_ref()]
        .map(|n| n.filter(|_| trace_rtt).map(|n| format!("{n}_{pid}_rtt.csv")));
    // -t ui: the IPs of -inf's -ip_field, the main socket on the first,
    // and a server's on all of them, as SIPp resolves them.
    let mut per_ip = Vec::new();
    if transport == Transport::UdpPerIp {
        let name = inject.default_name().unwrap_or("").to_string();
        let file = inject.get(&name).ok_or_else(|| fatal("You must use the -inf option when using -t ui.".into()))?;
        let resolve = |line: usize, log: &mut Log| {
            let v = file.field(line, ip_field);
            log.flush_deferred();
            match (v.as_str(), 0).to_socket_addrs().map(|mut a| a.next()) {
                Ok(Some(a)) => Ok(a.ip()),
                Ok(None) => Err(v),
                Err(e) => {
                    let e = e.to_string();
                    log.warning(&format!("getaddrinfo failed: {}", e.strip_prefix("failed to lookup address information: ").unwrap_or(&e)));
                    Err(v)
                }
            }
        };
        match resolve(0, &mut log) {
            Ok(ip) => per_ip.push(ip),
            Err(v) => return Err(ArgsError::Logged(format!("Unknown host '{v}'.\nUse 'sipp -h' for details"), Box::new(log))),
        }
        for line in (0..file.lines()).filter(|_| !client) {
            match resolve(line, &mut log) {
                Ok(ip) if !per_ip.contains(&ip) => per_ip.push(ip),
                Ok(_) => {}
                Err(v) => return Err(ArgsError::Logged(format!("Unknown remote host '{v}'.\nUse 'sipp -h' for details"), Box::new(log))),
            }
        }
        bind_ip = per_ip[0];
    }
    if periodic_rtd {
        log.warning("-periodic_rtd is deprecated and ignored: the statistics file has periodic (P) and cumulative (C) repartition columns");
    }
    // Opened with the first row, as SIPp's CStat::dumpData().
    let stat_path = trace_stat.then(|| stat_file.unwrap_or_else(|| format!("{scenario_name}_{pid}_.csv")));

    Ok(Args {
        tls_named: tls_cert.is_some() || tls_key.is_some(),
        tls_files: Some((tls_cert.unwrap_or_else(|| "cacert.pem".into()), tls_key.unwrap_or_else(|| "cakey.pem".into()))),
        tls_options,
        ws_path,
        ws_timeout,
        twin_mode_error: match (uses_twin, twin.is_some(), extended.is_some()) {
            (false, true, _) => Some("TwinSipp Mode enabled but thirdPartyMode is different from 3PCC_CONTROLLER_B and 3PCC_CONTROLLER_A\n"),
            (false, false, true) => Some("extendedTwinSipp Mode enabled but thirdPartyMode is different from MASTER and SLAVE\n"),
            _ => None,
        },
        twin: twin.filter(|_| uses_twin),
        twin_listens: !drives_twin,
        creates,
        cmd_starts,
        given_remote,
        remotes,
        local_error,
        srv_note,
        remote_unknown: unknown_remote.is_some(),
        inject,
        transport,
        rtp_echo,
        srtpctx: media::echo_debug::ON.load(Ordering::Relaxed).then_some(send_mode),
        rtp_ports: (min_rtp_port, max_rtp_port),
        scenario,
        scenario_name,
        // SIPp's user_port: -p 0 is none.
        explicit_port: port.is_some_and(|p| p != 0),
        cfg: Config {
            local: SocketAddr::new(bind_ip, port.unwrap_or(5060)),
            // SIPp's local_ip_w_brackets and media_ip: -i and -mi as
            // given, or the address it works out.
            local_ip: match (local_ip, &ip) {
                (IpAddr::V6(_), Some(text)) => format!("[{text}]"),
                (IpAddr::V6(v6), None) => format!("[{v6}]"),
                (_, text) => text.clone().unwrap_or_else(|| local_ip.to_string()),
            },
            media_ip: media_ip.as_ref().map_or(local_ip, |m| m.0),
            media_ip_text: media_ip.map(|m| m.1).or(ip).unwrap_or_else(|| local_ip.to_string()),
            auth_user: auth_user.unwrap_or_else(|| service.clone()),
            auth_pass,
            auth_uri,
            service,
            // SIPp: min_rtp_port, moved up if -rtp_echo finds it taken.
            media_port: min_rtp_port,
            default_pause: Duration::from_millis(pause_ms),
            recv_timeout,
            default_behaviors,
            auto_answer,
            sendbuffer_warn,
            retrans,
            users,
            base_cseq,
            max_invite_retrans: max_invite_retrans.min(max_retrans),
            max_non_invite_retrans: max_non_invite_retrans.min(max_retrans),
            t2,
            pause_msg_ign,
            lost,
            remote_host,
            rfc3339,
            client,
            // rand(): 31 bits.
            rtcheck_loose,
            audio_tolerance,
            video_tolerance,
            ssrc_base: if random_base_ssrc { call::Rng::new(seed_now()).next_u32() >> 1 } else { 0xCA11_0000 },
            scenario_dir,
            has_media,
            rsa: rsa.is_some(),
            callid_slash_ign,
        },
        remote,
        max_calls,
        rate,
        rate_set,
        rate_period: Duration::from_millis(rate_period_ms),
        limit: match users {
            Some(u) => u as usize,
            None if !limit_set => open_calls_allowed(rate, auto_limit.unwrap_or(0.0), rate_period_ms),
            None => limit,
        },
        timeout: timeout.filter(|t| !t.is_zero()),
        timeout_error,
        log,
        control_port,
        stat_file: None,
        stat_path,
        stat_period,
        watchdog,
        timer_resol,
        call_ids: CallIds { format: cid_format, mode: cid_mode },
        extended,
        ooc,
        rx,
        aa,
        counts_received,
        deadcall_wait,
        rx_inject,
        rate_increase,
        rate_max,
        // SIPp: -fd's period unless set.
        rate_interval: rate_interval.unwrap_or(stat_period),
        rate_quit,
        background,
        sleep,
        max_socket,
        skip_rlimit,
        recv_loops,
        ip_field,
        per_ip,
        nostdin,
        control_ip,
        rate_scale,
        counts_file,
        codes_file,
        setup_error,
        rtt_paths,
        rtt_freq: rtt_freq.max(1),
        screen_file,
        screen_log,
        auto_limit,
        rfc3339,
        stat_delimiter,
        sets,
        rsa,
        tdm,
        sctp,
        bind_device,
        reconnect,
    })
}

/// The TCP connection between the two 3PCC controllers.
struct Twin {
    listener: Option<TcpListener>,
    stream: Option<TcpStream>,
    /// Controller A's: where B listens, which a reset connects to again.
    to: Option<SocketAddr>,
    buf: Vec<u8>,
    /// What waits for the connection, kept across A's reconnections.
    out: TwinOut,
    closed: bool,
    /// read_error() on the connection.
    error: Option<std::io::Error>,
}

/// A read's error on a 3PCC connection, in read_error()'s words.
fn twin_error(e: &std::io::Error) -> String {
    format!("Error on TCP connection, remote peer probably closed the socket: {}", net::os_error(e))
}

/// Reads what a 3PCC connection has into `buf`: Ok(true) once the peer
/// closed it.
fn read_twin(s: &mut TcpStream, buf: &mut Vec<u8>) -> std::io::Result<bool> {
    let mut chunk = [0u8; 4096];
    loop {
        match s.read(&mut chunk) {
            Ok(0) => return Ok(true),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) => return Err(e),
        }
    }
}

/// What waits for a 3PCC connection, as SIPp's ss_out: all it is sent
/// while a connect is in progress (SIPp's socket is congested till then).
#[derive(Default)]
struct TwinOut {
    connecting: bool,
    bytes: Vec<u8>,
    /// The commands in `bytes`, in order: what is left of each, and the
    /// command to trace once it is written whole (SIPp's untraced
    /// buffer), not one that was cut short.
    cmds: VecDeque<(usize, Option<String>)>,
    /// Those written whole since, for the -trace_msg file.
    written: Vec<String>,
}

impl TwinOut {
    fn queue(&mut self, data: &[u8], cmd: Option<&str>) {
        self.bytes.extend_from_slice(data);
        self.cmds.push_back((data.len(), cmd.map(String::from)));
    }

    /// `n` bytes of `bytes` gone out.
    fn wrote(&mut self, mut n: usize) {
        self.bytes.drain(..n);
        while let Some(front) = self.cmds.front_mut() {
            if n < front.0 {
                front.0 -= n;
                return;
            }
            n -= front.0;
            if let Some((_, Some(cmd))) = self.cmds.pop_front() {
                self.written.push(cmd);
            }
        }
    }
}

/// flush(): what waits for a 3PCC connection, once a connect in progress
/// is done, as far as the connection takes it; the connect's failure.
fn flush_twin(s: &mut TcpStream, out: &mut TwinOut) -> std::io::Result<()> {
    if out.connecting {
        match net::connect_state(sys::AsRawFd::as_raw_fd(s), true) {
            None => return Ok(()),
            Some(r) => r?,
        }
        out.connecting = false;
    }
    while !out.bytes.is_empty() {
        match s.write(&out.bytes) {
            Ok(0) => return Err(std::io::Error::from_raw_os_error(sys::EPIPE)),
            Ok(n) => out.wrote(n),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// A command to a 3PCC connection: after what waits, and waiting too
/// while a connect is in progress. One that a reset left without a
/// connection is a broken pipe, as the write to SIPp's socket is. Only
/// a command that was not taken fails; one that waits goes once the
/// connection is made, again if need be. Traced as SIPp's write(): sent
/// once written whole, now or from what waits, or why not.
fn write_twin(s: Option<&mut TcpStream>, out: &mut TwinOut, cmd: &str, log: &mut Log) -> std::io::Result<()> {
    // SIPp ends each command with ESC.
    let data = format!("{cmd}\x1b");
    let bytes = raw::bytes(&data);
    let failed = |log: &mut Log, e: std::io::Error| {
        log.send_error("TCP", &data);
        Err(e)
    };
    let Some(s) = s else { return failed(log, std::io::Error::from_raw_os_error(sys::EPIPE)) };
    // SIPp's write() flushes what waits first, failing the command if
    // that fails.
    if !out.connecting && !out.bytes.is_empty() {
        flush_twin(s, out)?;
    }
    if out.connecting || !out.bytes.is_empty() {
        out.queue(&bytes, Some(cmd));
        return Ok(());
    }
    loop {
        match s.write(&bytes) {
            Ok(n) if n == bytes.len() => {
                log.sent("TCP control", cmd);
                return Ok(());
            }
            Ok(0) => return failed(log, std::io::Error::from_raw_os_error(sys::EPIPE)),
            Ok(n) => {
                log.truncated("TCP", n, &data);
                out.queue(&bytes[n..], None);
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                out.queue(&bytes, Some(cmd));
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return failed(log, e),
        }
    }
}

/// The commands `buf` has in full, each ended by ESC.
fn twin_commands(buf: &mut Vec<u8>, out: &mut Vec<String>) {
    while let Some(end) = buf.iter().position(|&b| b == 0x1b) {
        out.push(raw::text(&buf[..end]).into_owned());
        buf.drain(..=end);
    }
}

impl Twin {
    /// connect_to_peer(): without waiting, as SIPp's connect(); a refusal
    /// shows on the first read.
    fn connect(addr: SocketAddr) -> std::io::Result<TcpStream> {
        let sock = socket2::Socket::new(socket2::Domain::for_address(addr), socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
        sock.set_nonblocking(true)?;
        match sock.connect(&addr.into()) {
            Err(e) if e.raw_os_error() != Some(sys::EINPROGRESS) => return Err(e),
            _ => {}
        }
        Ok(sock.into())
    }

    fn poll(&mut self) -> Vec<String> {
        if self.stream.is_none() {
            if let Some(Ok((s, _))) = self.listener.as_ref().map(TcpListener::accept) {
                let _ = s.set_nonblocking(true);
                self.stream = Some(s);
                self.out = TwinOut::default();
            }
        }
        let Some(stream) = self.stream.as_mut() else { return Vec::new() };
        match flush_twin(stream, &mut self.out).and_then(|()| read_twin(stream, &mut self.buf)) {
            Ok(closed) => self.closed = closed,
            Err(e) => {
                // drop_connection(): out of the poll set, till a reconnection.
                self.error = Some(e);
                self.stream = None;
            }
        }
        let mut out = Vec::new();
        twin_commands(&mut self.buf, &mut out);
        out
    }

    fn send(&mut self, cmd: &str, log: &mut Log) -> std::io::Result<()> {
        if self.stream.is_none() && self.to.is_none() {
            // Controller B, until A connects again.
            return Err(std::io::Error::from_raw_os_error(sys::ENOTCONN));
        }
        write_twin(self.stream.as_mut(), &mut self.out, cmd, log)
    }
}

/// The 3PCC connections, which the calls write their commands to.
#[derive(Default)]
struct TwinLinks {
    twin: Option<Twin>,
    /// -master / -slave: 3PCC extended mode's peers.
    peers: Option<Peers>,
    /// The command that could not go, for the engine to fail its call:
    /// the error, the extended mode peer it was for, and whether it was
    /// a 3pcc_abort.
    failed: Option<(std::io::Error, Option<String>, bool)>,
    /// Controller A's twin connection, closed by B: SIPp's twinSippSocket
    /// left null.
    gone: bool,
}

impl call::Commands for TwinLinks {
    fn send_cmd(&mut self, dest: Option<&str>, cmd: &str, abort: bool, log: &mut Log) -> std::io::Result<()> {
        let sent = match (dest, self.twin.as_mut(), self.peers.as_mut()) {
            // sendCmdBuffer() only goes to a twin SIPp connected.
            (None, Some(twin), _) if abort && twin.stream.is_none() && twin.to.is_none() => return Ok(()),
            (Some(d), _, Some(peers)) => match peers.send(d, cmd, log) {
                Some(r) => r,
                None => return Ok(()),
            },
            (None, Some(twin), _) => twin.send(cmd, log),
            (None, None, _) if self.gone && !abort => Err(std::io::Error::from_raw_os_error(sys::ENOTCONN)),
            _ => return Ok(()),
        };
        sent.map_err(|e| {
            let kind = e.kind();
            self.failed = Some((e, dest.map(String::from), abort));
            kind.into()
        })
    }
}

/// 3PCC extended mode: our listener for the other instances' commands,
/// and a connection to each peer our <sendCmd dest=>s name, the master
/// connecting at once and a slave when first reached.
struct Peers {
    listener: TcpListener,
    incoming: Vec<(TcpStream, Vec<u8>)>,
    /// None while a reset leaves it without a connection.
    outgoing: HashMap<String, Option<TcpStream>>,
    /// What waits for each of them, kept across its reconnections.
    out: HashMap<String, TwinOut>,
    /// -slave_cfg: each instance's host, and the address of those
    /// resolved as SIPp does, when it connects to them.
    hosts: HashMap<String, String>,
    addrs: HashMap<String, SocketAddr>,
    dests: Vec<String>,
    connected: bool,
    closed: bool,
    /// A peer host that doesn't resolve ends the run.
    fatal: Option<String>,
    /// read_error() on a connection, and the peer it goes to if we made it.
    error: Option<(std::io::Error, Option<String>)>,
}

impl Peers {
    /// connect_to_all_peers().
    fn connect(&mut self, log: &mut Log) {
        self.connected = true;
        // SIPp's peer map: by name.
        let mut dests = self.dests.clone();
        dests.sort();
        for d in &dests {
            if let Some(host) = self.hosts.get(d) {
                let host = host_part(host);
                println!("Resolving peer address : {host}...");
                match resolve_logged(self.hosts[d].as_str(), log) {
                    Some(a) => {
                        self.addrs.insert(d.clone(), a);
                    }
                    None => {
                        self.fatal = Some(format!("Unknown peer host '{host}'.\nUse 'sipp -h' for details"));
                        return;
                    }
                }
            }
            // Without waiting, as SIPp: a refusal shows once polled.
            match self.addrs.get(d).copied().map(Twin::connect) {
                Some(Ok(s)) => {
                    let _ = s.set_nodelay(true);
                    self.out.entry(d.clone()).or_default().connecting = true;
                    self.outgoing.insert(d.clone(), Some(s));
                }
                Some(Err(e)) => {
                    self.fatal = Some(error_no("Unable to connect a twin sipp socket \nUse 'sipp -h' for details", &e).0);
                    return;
                }
                None => log.warning(&format!("get_peer_socket: Peer {d} not found")),
            }
        }
    }

    /// The command to `dest`, or None when there is no such peer.
    fn send(&mut self, dest: &str, cmd: &str, log: &mut Log) -> Option<std::io::Result<()>> {
        match self.outgoing.get_mut(dest) {
            Some(s) => Some(write_twin(s.as_mut(), self.out.entry(dest.to_string()).or_default(), cmd, log)),
            None => {
                log.warning(&format!("get_peer_socket: Peer {dest} not found"));
                None
            }
        }
    }

    fn poll(&mut self, log: &mut Log) -> Vec<String> {
        while let Ok((s, _)) = self.listener.accept() {
            let _ = s.set_nonblocking(true);
            self.incoming.push((s, Vec::new()));
            if !self.connected {
                self.connect(log);
            }
        }
        let mut out = Vec::new();
        let mut i = 0;
        while let Some((s, buf)) = self.incoming.get_mut(i) {
            let read = read_twin(s, buf);
            twin_commands(buf, &mut out);
            match read {
                Ok(closed) => self.closed |= closed,
                Err(e) => {
                    // drop_connection().
                    self.error.get_or_insert((e, None));
                    self.incoming.remove(i);
                    continue;
                }
            }
            i += 1;
        }
        // The connections we made carry nothing to us, but end, or fail,
        // as the peer does. A peer that ends closes the one it made to us
        // first, which ends the run before SIPp mostly reads this one.
        if self.closed || self.error.is_some() {
            return out;
        }
        let mut names: Vec<String> = self.outgoing.keys().cloned().collect();
        names.sort();
        for name in names {
            let Some(Some(s)) = self.outgoing.get_mut(&name) else { continue };
            match flush_twin(s, self.out.entry(name.clone()).or_default()).and_then(|()| read_twin(s, &mut Vec::new())) {
                Ok(closed) => self.closed |= closed,
                Err(e) => {
                    self.outgoing.insert(name.clone(), None);
                    self.error.get_or_insert((e, Some(name)));
                }
            }
        }
        out
    }
}

/// parse_slave_cfg(): "name;host:port" lines.
/// gai_getsockaddr(): a host:port's first address, getaddrinfo()'s
/// failure warned about as SIPp does.
fn resolve_logged(host: &str, log: &mut Log) -> Option<SocketAddr> {
    match host.to_socket_addrs() {
        Ok(mut a) => a.next(),
        Err(e) => {
            let e = e.to_string();
            log.warning(&format!("getaddrinfo failed: {}", e.strip_prefix("failed to lookup address information: ").unwrap_or(&e)));
            None
        }
    }
}

/// parse_slave_cfg(): each peer's host as the file gives it, resolved
/// once the connections are made.
fn slave_cfg(path: &str) -> Result<HashMap<String, String>, String> {
    let text = std::fs::read_to_string(path).map_err(|_| format!("Can not open -slave_cfg/-secondary_cfg file {path}"))?;
    let mut out = HashMap::new();
    for line in text.lines() {
        let mut f = line.split(';');
        let (Some(name), Some(host)) = (f.next(), f.next()) else { continue };
        out.insert(name.trim().to_string(), host.trim().to_string());
    }
    Ok(out)
}

/// A queue kept in blocks of a fixed size, so that growing it moves
/// nothing it holds: the -deadcall_wait expiries of a fast run's calls
/// (33 s of them at thousands a second) would stall the loop for ms to
/// copy them each time a single buffer doubled.
struct Fifo<T> {
    blocks: VecDeque<VecDeque<T>>,
}

impl<T> Fifo<T> {
    const BLOCK: usize = 4096;

    fn new() -> Fifo<T> {
        Fifo { blocks: VecDeque::new() }
    }

    fn push(&mut self, v: T) {
        match self.blocks.back_mut() {
            Some(b) if b.len() < Self::BLOCK => b.push_back(v),
            _ => {
                let mut b = VecDeque::with_capacity(Self::BLOCK);
                b.push_back(v);
                self.blocks.push_back(b);
            }
        }
    }

    fn front(&self) -> Option<&T> {
        self.blocks.front().and_then(VecDeque::front)
    }

    fn pop(&mut self) -> Option<T> {
        let b = self.blocks.front_mut()?;
        let v = b.pop_front();
        if b.is_empty() {
            self.blocks.pop_front();
        }
        v
    }
}

/// SIPp's deadcall: a finished call's Call-ID and how it ended, kept for
/// -deadcall_wait to tell its late messages apart from out-of-call ones.
struct Dead {
    reason: Cow<'static, str>,
    until: Instant,
    /// The BYE or CANCEL an aborted call ended with.
    aborted_with: Option<&'static str>,
}

/// An <exec verify> command running: the call that waits for it, none
/// once that call is gone, and the command for the logs.
struct Verify {
    child: std::process::Child,
    call: Option<String>,
    /// Or the <init> call in Engine::inits that waits for it.
    init: Option<usize>,
    command: String,
}

/// An <init> call that waits for its <exec verify> commands, which SIPp's
/// main loop runs on as a task: the rest of <init> runs when they end.
struct InitCall {
    call: Box<Call>,
    scenario: Box<Scenario>,
    stats: Stats,
    rx: bool,
}

#[derive(Default, Clone, Copy)]
struct Counters {
    created: u64,
    successful: u64,
    failed: u64,
    /// Ended as neither (an unexpected PING answered).
    discarded: u64,
    /// The patterns whose checks failed: bit id - 1, as SIPp's mask.
    rtp_errors: u64,
    /// A call of the main scenario failed an rtp_echo: its stats'
    /// getRtpEchoErrors().
    echo_errors: bool,
}

/// The -trace_stat CSV, in SIPp's columns and formats.
fn write_stats(f: &mut File, first: bool, e: &Engine) {
    use std::io::Write;
    if first {
        let _ = raw::write(f, &format!("{}\n", e.stats.csv_header()));
    }
    let target = match e.args.cfg.users {
        Some(u) => stat::Target::Users(u),
        None => stat::Target::Rate(e.rate),
    };
    let _ = writeln!(f, "{}", e.stats.csv_row(target));
}

struct Engine {
    args: Args,
    defaults: Defaults,
    net: Net,
    pid: u32,
    calls: Calls,
    /// Call wakeups, earliest first; an entry is stale unless it matches
    /// the call's `scheduled`.
    timers: BinaryHeap<Reverse<(Instant, String)>>,
    /// A tree, as SIPp's: a hash table of a fast run's dead calls would
    /// stall the loop for ms each time it grew and rehashed them all.
    dead: BTreeMap<Rc<str>, Dead>,
    /// Dead calls in the order they expire: the wait is the same for all.
    dead_expiry: Fifo<(Instant, Rc<str>)>,
    /// Calls whose Call-ID a newer call took, so far: their keys.
    displaced: u64,
    /// The Call-IDs of calls' other dialogs, to the calls' keys; none is
    /// a call's key or a dead call's too, as in SIPp's one listener map.
    aliases: HashMap<String, String>,
    /// The calls a request of a Call-ID no call has may start a dialog
    /// of, oldest first, and the next one's place.
    new_dialog_calls: BTreeMap<u64, String>,
    new_dialog_seq: u64,
    /// Calls of the -oocsf, -rxsf and -aa scenarios, which SIPp neither
    /// counts as open nor waits for at the end.
    side_calls: usize,
    /// The scenario's global and user variable names, and the globals.
    scopes: vars::Scopes,
    /// -users: the users without a call, taken from the back and given
    /// back at the front as SIPp does, and each user's variables.
    free_users: VecDeque<u32>,
    user_vars: HashMap<u32, vars::Table>,
    /// The call rate, which -rate_increase changes, and since when and
    /// after how many calls it holds, less those -l held back (since on
    /// SIPp's clock).
    rate: f64,
    rate_since: (u64, i64),
    last_ramp: Instant,
    /// -users with -r: the calls still ramp up to the users at the rate.
    ramping: bool,
    /// -oocsf's and -rxsf's statistics.
    side_stats: [Option<Stats>; 3],
    /// Engine loops in the last second, for the screen's resolution.
    loops: u64,
    keyboard: Option<control::Keyboard>,
    /// A terminal on stdout gets SIPp's screen each second.
    live_screen: bool,
    /// The screen shown (1-9), whether hidden steps stay so, -rate_scale,
    /// and 'p'.
    screen: u8,
    hide: bool,
    rate_scale: f64,
    traffic_paused: bool,
    /// -trace_rtt's files, as the paths in Args.
    rtt_files: [Option<File>; 3],
    /// SIPp's next_number: the number of the next call made.
    next_number: u64,
    /// -round_robin: the remote address the next call takes.
    next_remote: usize,
    /// A call ended as it ran, rather than on a message it read: SIPp
    /// reads its sockets once more before it quits.
    ended_running: bool,
    /// The loop is handling the messages it read.
    reading: bool,
    counters: Counters,
    stats: Stats,
    control: Control,
    rng: Rng,
    rtp_ports: media::RtpPorts,
    echo: Option<media::Echo>,
    links: TwinLinks,
    start: Instant,
    timed_out: bool,
    /// SIPp's quitting of 11 and up: a forced exit, not waiting for calls.
    forcing: bool,
    /// -trace_stat: the header still to write, and the last row's time.
    stat_first: bool,
    /// SIPp's last_woken_calls: its tasks woken from the timer wheel since
    /// the scenario screen was last drawn: calls whose timer fired, dead
    /// calls expiring, and its screen, statistics and watchdog tasks.
    woken: u64,
    /// When the watchdog task next wakes.
    next_watchdog: Option<Instant>,
    /// SIPp's CallGenerationTask, of a scenario that starts calls: alive
    /// until it wakes after the run started quitting, when it is due (on
    /// SIPp's clock).
    generator: Option<Option<u64>>,
    /// SIPp's last_paused_calls and last_running_calls, sampled at its
    /// timer cycle.
    paused: usize,
    running: usize,
    /// The loop's passes (wrapping), and the calls that ran a step in
    /// this one.
    pass: u32,
    ran: usize,
    /// SIPp's last_timer_cycle.
    last_cycle: u64,
    /// The clock (SIPp's clock_tick) of the timer cycle the loop is in,
    /// where SIPp wakes its tasks: the calls whose timer is due, and the
    /// call generation task.
    cycle: Option<u64>,
    /// SIPp's run queue: the calls that ran a step, which run on at the
    /// loop's next pass, and those whose pass it is (`due`, from before
    /// its read: what a message ran waits for the pass after).
    turns: Vec<String>,
    due: Vec<String>,
    last_stat: Instant,
    control_sock: Option<UdpSocket>,
    /// The run has ended and SIPp would have closed its sockets.
    sockets_closed: bool,
    /// The <exec verify> commands running, and those a call just started,
    /// which finish() gives the call's key.
    verify: Vec<Verify>,
    verify_started: Vec<(std::process::Child, String)>,
    inits: Vec<Option<InitCall>>,
}

impl Engine {
    /// The Env of a call of `sc`, and that call.
    fn env_of(&mut self, id: &str) -> (Env<'_>, &mut Call) {
        self.try_env_of(id).expect("no such call")
    }

    fn try_env_of(&mut self, id: &str) -> Option<(Env<'_>, &mut Call)> {
        let call = self.calls.get_mut(id)?;
        let (scenario, stats, inject) = match call.sc {
            call::Sc::Ooc => (self.args.ooc.as_ref().unwrap(), self.side_stats[0].as_mut().unwrap(), &mut self.args.inject),
            call::Sc::Rx => (self.args.rx.as_ref().unwrap(), self.side_stats[1].as_mut().unwrap(), &mut self.args.rx_inject),
            call::Sc::Aa => (self.args.aa.as_ref().unwrap(), self.side_stats[2].as_mut().unwrap(), &mut self.args.inject),
            call::Sc::Main => (&self.args.scenario, &mut self.stats, &mut self.args.inject),
        };
        let env = Env {
            scenario,
            defaults: &self.defaults,
            cfg: &self.args.cfg,
            net: &mut self.net,
            pid: self.pid,
            stats,
            log: &mut self.args.log,
            control: &mut self.control,
            rng: &mut self.rng,
            rtp_ports: &mut self.rtp_ports,
            twin: &mut self.links,
            inject,
            verify: &mut self.verify_started,
        };
        Some((env, call))
    }

    /// runInit(): the <init> steps of the -sf, -oocsf and -rxsf scenarios,
    /// each in a call of its own.
    fn run_init(&mut self) {
        let inits = [
            (self.args.scenario.init.take(), false),
            (self.args.ooc.as_mut().and_then(|s| s.init.take()), false),
            (self.args.rx.as_mut().and_then(|s| s.init.take()), true),
        ];
        for (init, rx) in inits {
            if let Some(init) = init {
                self.run_one_init(init, rx);
            }
        }
    }

    fn run_one_init(&mut self, init: Box<Scenario>, rx: bool) {
        let stats = Stats::new(&init.layout);
        // Number 0: an <init> leaves the call numbers to the calls.
        let mut call = Call::new(0, "///main-init".into(), Peer { addr: SocketAddr::from(([0, 0, 0, 0], 0)), conn: None });
        call.srtpctx = self.args.srtpctx.and_then(|mode| call::srtpctx_open(mode, &mut self.args.log));
        call.set_vars(vars::Vars::new(self.scopes.clone(), None));
        // The line the first call reads, which it leaves to that call.
        let rng = &mut self.rng;
        let inject = if rx { &mut self.args.rx_inject } else { &mut self.args.inject };
        match inject.assign(0, || rng.next_u32(), false) {
            Ok(lines) => call.lines = lines,
            Err(e) => self.control.fatal = Some(e),
        }
        let mut init = InitCall { call: Box::new(call), scenario: init, stats, rx };
        self.init_step(&mut init, |call, env| {
            call.advance(env);
        });
        self.keep_init(init);
    }

    /// Runs `f` on an <init> call, in its scenario and statistics.
    fn init_step(&mut self, init: &mut InitCall, f: impl FnOnce(&mut Call, &mut Env)) {
        let mut env = Env {
            scenario: &init.scenario,
            defaults: &self.defaults,
            cfg: &self.args.cfg,
            net: &mut self.net,
            pid: self.pid,
            stats: &mut init.stats,
            log: &mut self.args.log,
            control: &mut self.control,
            rng: &mut self.rng,
            rtp_ports: &mut self.rtp_ports,
            twin: &mut self.links,
            inject: if init.rx { &mut self.args.rx_inject } else { &mut self.args.inject },
            verify: &mut self.verify_started,
        };
        f(&mut init.call, &mut env);
    }

    /// An <init> call that waits for <exec verify> commands stays, for
    /// their end to run the rest of it; else it is gone, and leaves the
    /// commands it started to run on, ignored.
    /// exit()'s flush of the srtpctxdebugfiles of the calls still open:
    /// the newest first, as glibc's list of FILEs has them.
    fn close_srtpctx(&mut self) {
        let inits = self.inits.iter_mut().flatten().map(|i| &mut i.call.srtpctx);
        let mut files: Vec<_> = self.calls.values_mut().map(|c| &mut c.srtpctx).chain(inits).filter_map(Option::take).collect();
        files.sort_by_key(|f| std::cmp::Reverse(f.seq));
        drop(files);
    }

    fn keep_init(&mut self, init: InitCall) {
        let slot = (init.call.verify_pending > 0).then_some(self.inits.len());
        for (child, command) in self.verify_started.drain(..) {
            self.verify.push(Verify { child, call: None, init: slot, command });
        }
        if slot.is_some() {
            self.inits.push(Some(init));
        }
    }

    fn env(&mut self) -> (Env<'_>, &mut Calls) {
        (
            Env {
                scenario: &self.args.scenario,
                defaults: &self.defaults,
                cfg: &self.args.cfg,
                net: &mut self.net,
                pid: self.pid,
                stats: &mut self.stats,
                log: &mut self.args.log,
                control: &mut self.control,
                rng: &mut self.rng,
                rtp_ports: &mut self.rtp_ports,
                twin: &mut self.links,
                inject: &mut self.args.inject,
                verify: &mut self.verify_started,
            },
            &mut self.calls,
        )
    }

    /// read_error() and reset_connection(): a connection failed. Without
    /// a reconnection left (-max_reconnect) the run ends; else its calls
    /// close (-reconnect_close), and after -reconnect_sleep a client's
    /// shared connection is opened again for the calls left on it.
    fn connection_failed(&mut self, conn: Option<net::ConnId>, why: &str) {
        // What it had buffered goes on its reconnection, for the calls that
        // stay on it; -reconnect_close drops it with its calls, as SIPp's
        // close_calls() does.
        let unsent = conn.map(|c| self.net.take_unsent(c)).unwrap_or_default();
        let r = &mut self.args.reconnect;
        if r.left == 0 {
            self.control.fatal = Some(why.to_string());
            return;
        }
        self.args.log.warning(why);
        if r.left > 0 {
            r.left -= 1;
        }
        let (close, sleep) = (r.close, r.sleep);
        let ids: Vec<String> = match conn {
            Some(c) => self.call_ids(|call| call.peer.conn == Some(c)),
            None => Vec::new(),
        };
        if close {
            self.args.log.warning("Closing calls, because of TCP reset or close!");
            for id in &ids {
                let (mut env, call) = self.env_of(id);
                let outcome = call.connection_closed(&mut env);
                self.finish(id, outcome);
            }
            // A client call's own connection goes with its last call:
            // there is nothing left to reconnect, nor to sleep for.
            if conn.is_some() && self.args.cfg.client && !self.net.transport.single() {
                return;
            }
        }
        std::thread::sleep(sleep);
        if conn.is_none() || !self.args.cfg.client {
            return;
        }
        // The shared connection, or a call's own, that its calls stay on.
        let reconnected = if self.net.transport.single() {
            let Some(remote) = self.args.remote else { return };
            self.net.reconnect(self.args.rsa.unwrap_or(remote))
        } else {
            let Some(to) = ids.first().and_then(|id| self.calls.get(id)).map(|c| c.peer.addr) else { return };
            self.net.reconnect_call(to, ids.len())
        };
        match reconnected {
            Ok(fresh) => {
                // Its bind's warning, as when -p is the main socket's.
                self.net_warnings();
                self.args.log.warning("Socket required a reconnection.");
                if let Some(f) = fresh.filter(|_| !close) {
                    self.net.requeue(f, unsent);
                }
                for id in ids.iter().filter(|_| !close) {
                    if self.calls.contains_key(id) {
                        let (mut env, call) = self.env_of(id);
                        call.peer.conn = fresh;
                        // resume_calls(): a request that may be lost with
                        // the old connection goes on the new one.
                        call.reconnected(&mut env);
                    }
                }
            }
            Err(e) => {
                // A failed TLS handshake, which connect() warned about.
                self.net_warnings();
                match net::handshake_failed(&e) {
                    Some(_) => self.args.log.warning("Could not reconnect TLS socket"),
                    None => self.args.log.warning(&format!("Could not reconnect TCP socket, errno = {} ({})", e.raw_os_error().unwrap_or(0), net::os_error(&e))),
                }
                for id in ids.iter().filter(|_| !close) {
                    let (mut env, call) = self.env_of(id);
                    let outcome = call.connection_closed(&mut env);
                    self.finish(id, outcome);
                }
            }
        }
    }

    /// What the network layer warned about, logged in its turn.
    /// Net::poll(), and the buffered messages it wrote, traced as sent
    /// before what it read.
    fn poll_net(&mut self, buf: &mut [u8], got: &mut Vec<net::Received>) {
        self.net.poll_into(buf, got);
        for t in std::mem::take(&mut self.net.traces) {
            self.args.log.trace_msg(&t);
        }
        for m in std::mem::take(&mut self.net.written) {
            self.args.log.sent(self.net.transport.name(), &m);
        }
    }

    fn net_warnings(&mut self) {
        for w in std::mem::take(&mut self.net.warnings) {
            self.args.log.warning(&w);
        }
    }

    fn finish(&mut self, id: &str, outcome: Outcome) {
        if let Some(ids) = self.calls.get_mut(id).map(|c| c.take_dialog_ids()).filter(|ids| !ids.is_empty()) {
            for dialog_id in ids {
                self.alias(dialog_id, id);
            }
        }
        for (child, command) in self.verify_started.drain(..) {
            self.verify.push(Verify { child, call: Some(id.to_string()), init: None, command });
        }
        // write_error()'s ERROR(): a broken pipe with no reconnection left
        // ends the run in the send, before the call is counted.
        if matches!(outcome, Outcome::Failed) && self.args.reconnect.left == 0 {
            if let Some((_, why)) = self.net.resets.first() {
                self.control.fatal = Some(why.clone());
                return;
            }
        }
        // sendCmdMessage(): a command not sent deletes the call, failed,
        // before its connection is reset; without a reconnection left the
        // run ends in the send, before the call is counted. Controller B
        // has none to reset until A connects again.
        if let Some((e, dest, abort)) = self.links.failed.take() {
            let reset = e.raw_os_error() != Some(sys::ENOTCONN);
            if !reset || self.args.reconnect.left != 0 {
                let outcome = match outcome {
                    Outcome::Running | Outcome::StopNow | Outcome::Success => self.calls.get_mut(id).map_or(outcome, |c| c.cmd_not_sent()),
                    o => o,
                };
                self.finish(id, outcome);
            }
            match reset {
                true => self.twin_write_failed(e, dest),
                false => {
                    self.args.log.warning(&format!("Unable to send TCP message: {}", net::os_error(&e)));
                    self.net.send_errors += 1;
                }
            }
            if abort && self.control.fatal.is_none() {
                self.args.log.warning("sendCmdBuffer returned -1");
            }
            return;
        }
        let ok = match outcome {
            Outcome::Running => return self.reschedule(id, true),
            Outcome::StopNow => {
                self.control.stop_now = true;
                return self.reschedule(id, true);
            }
            Outcome::Success => Some(true),
            Outcome::Failed => Some(false),
            Outcome::Discarded => None,
        };
        let call = self.calls.remove(id).expect("finishing an unknown call");
        if call.verify_pending > 0 {
            // Its commands run on, and their end is ignored.
            for v in self.verify.iter_mut().filter(|v| v.call.as_deref() == Some(id)) {
                v.call = None;
            }
        }
        // SIPp ends a call at a <recv> as it reads the message; one that
        // ends past it, or anywhere else, ends as it runs, which its loop
        // follows with a read of the sockets.
        let sc = scenario_of(&self.args, call.sc);
        let at = sc.and_then(|sc| sc.steps.get(call.index()).or(sc.steps.last()));
        // A call a message aborts ends as SIPp reads it too.
        let aborted = self.reading && matches!(outcome, Outcome::Failed);
        if !aborted && !matches!(at.map(|s| &s.op), Some(Op::Recv { .. } | Op::RecvCmd { .. })) {
            self.ended_running = true;
        }
        if call.user_id > 0 {
            self.free_users.push_front(call.user_id);
        }
        if let Some(map) = self.args.tdm.as_mut() {
            map.give_back(call.circuit());
        }
        let mut call = call;
        call.release_request_sources(&mut self.net);
        // A -t tn/ln client's call owns its connection.
        if let (true, true, Some(conn)) = (self.args.cfg.client, self.net.transport.per_call(), call.peer.conn) {
            self.net.close(conn);
        }
        // On SIPp's clock: clock_tick at its end less at its start.
        let length = Duration::from_millis(call::tick_ms(Instant::now()).saturating_sub(call::tick_ms(call.created)));
        match call.sc {
            call::Sc::Main => {
                self.counters.echo_errors |= call.echo_failed();
                match ok {
                    Some(true) => self.counters.successful += 1,
                    Some(false) => self.counters.failed += 1,
                    None => self.counters.discarded += 1,
                }
                self.stats.ended(ok, call.fail, length);
            }
            call::Sc::Ooc => self.side_stats[0].as_mut().unwrap().ended(ok, call.fail, length),
            call::Sc::Rx => self.side_stats[1].as_mut().unwrap().ended(ok, call.fail, length),
            call::Sc::Aa => self.side_stats[2].as_mut().unwrap().ended(ok, call.fail, length),
        }
        if call.sc != call::Sc::Main {
            self.side_calls -= 1;
        }
        if let Some(seq) = call.wait_seq {
            self.new_dialog_calls.remove(&seq);
        }
        for dialog_id in call.dialog_ids() {
            if self.aliases.get(dialog_id).is_some_and(|key| key == id) {
                self.aliases.remove(dialog_id);
            }
        }
        // A dead call leaves a live call's Call-ID to it: the live call
        // that took the Call-ID from this one keeps its messages. Each
        // dialog's Call-ID has one too.
        if let Some(reason) = call.dead.as_ref().filter(|_| !self.args.deadcall_wait.is_zero()) {
            let until = Instant::now() + self.args.deadcall_wait;
            for dead_id in std::iter::once(call.id.as_str()).chain(call.dialog_ids()) {
                if !self.calls.contains_key(dead_id) && !self.aliases.contains_key(dead_id) {
                    let dead_id: Rc<str> = dead_id.into();
                    self.dead_expiry.push((until, dead_id.clone()));
                    self.dead.insert(dead_id, Dead { reason: reason.clone(), until, aborted_with: call.aborted_with });
                }
            }
        }
    }

    /// listen(): the messages of a dialog's Call-ID go to the call with
    /// this key, from a dead call silently; a live call runs on without
    /// them.
    fn alias(&mut self, dialog_id: String, key: &str) {
        if self.calls.contains_key(&dialog_id) || self.aliases.contains_key(&dialog_id) {
            self.args.log.warning(&format!("Call-ID '{dialog_id}' is already in use by another call"));
            self.displace(&dialog_id);
        }
        self.dead.remove(dialog_id.as_str());
        self.aliases.insert(dialog_id, key.to_string());
    }

    /// get_listener(): the key of the call or dead call a message's
    /// Call-ID is for, else the Call-ID a new call takes. SIPp finds the
    /// call by what follows "///", so a scenario can send requests with
    /// other Call-IDs and still get the answers; a dialog of a call can
    /// have a Call-ID with '///' of its own.
    fn listener_key<'a>(&self, full: &'a str) -> Cow<'a, str> {
        let id = match self.args.cfg.callid_slash_ign {
            true => full,
            false => full.split_once("///").map_or(full, |(_, rest)| rest),
        };
        let known = |k: &str| self.calls.contains_key(k) || self.aliases.contains_key(k) || self.dead.contains_key(k);
        let id = if id.len() != full.len() && known(full) { full } else { id };
        self.aliases.get(id).map_or(Cow::Borrowed(id), |key| Cow::Owned(key.clone()))
    }

    /// take_new_dialog(): the call a request of a Call-ID no call has
    /// starts a dialog of, if one waits for it: its key.
    fn take_new_dialog(&mut self, raw: &str) -> Option<String> {
        let key = self.new_dialog_calls.values().find(|key| {
            let call = self.calls.get_mut(*key).unwrap();
            scenario_of(&self.args, call.sc).is_some_and(|sc| call.take_new_dialog(sc, raw))
        })?;
        let key = key.clone();
        for dialog_id in self.calls.get_mut(&key).unwrap().take_dialog_ids() {
            self.alias(dialog_id, &key);
        }
        Some(key)
    }

    /// Another call or dead call takes the Call-ID of this live call over:
    /// it runs on under a key of its own, getting none of its messages.
    fn displace(&mut self, id: &str) {
        let Some(mut call) = self.calls.remove(id) else { return };
        self.displaced += 1;
        let key = format!("{id}\0{}", self.displaced);
        call.scheduled = None;
        call.displaced = true;
        if call.verify_pending > 0 {
            for v in self.verify.iter_mut().filter(|v| v.call.as_deref() == Some(id)) {
                v.call = Some(key.clone());
            }
        }
        if let Some(seq) = call.wait_seq {
            self.new_dialog_calls.insert(seq, key.clone());
        }
        for dialog_id in call.dialog_ids() {
            if let Some(k) = self.aliases.get_mut(dialog_id).filter(|k| *k == id) {
                k.clone_from(&key);
            }
        }
        self.calls.insert(key.clone(), call);
        self.reschedule(&key, false);
    }

    /// Queues the call's next wakeup; it `ran`, and is among those SIPp's
    /// next timer cycle finds running.
    fn reschedule(&mut self, id: &str, ran: bool) {
        let Some(call) = self.calls.get_mut(id) else { return };
        if ran && call.ran_in != self.pass {
            call.ran_in = self.pass;
            self.ran += 1;
        }
        if call.turn && !call.turn_queued {
            call.turn_queued = true;
            self.turns.push(id.to_string());
        }
        let next = call.next_wakeup();
        if next != call.scheduled {
            call.scheduled = next;
            if let Some(t) = next {
                self.timers.push(Reverse((t, id.to_string())));
            }
        }
    }

    /// A new call, or false when -tdmmap has no circuit left for it, which
    /// counts it created and failed as SIPp does.
    fn start_call(&mut self, id: String, peer: Peer, user: u32, incoming: bool, sc: call::Sc) -> bool {
        // SIPp counts a scenario's calls in its own statistics, and only
        // the main scenario's towards -m and the exit code.
        match sc {
            call::Sc::Main => {
                self.counters.created += 1;
                self.stats.created(incoming);
            }
            call::Sc::Ooc => self.side_stats[0].as_mut().unwrap().created(incoming),
            call::Sc::Rx => self.side_stats[1].as_mut().unwrap().created(incoming),
            call::Sc::Aa => self.side_stats[2].as_mut().unwrap().created(incoming),
        }
        // SIPp numbers every call it makes, rather than answers for
        // -oocsf or -aa, from one counter.
        let number = match sc {
            call::Sc::Main | call::Sc::Rx => {
                self.next_number += 1;
                self.next_number - 1
            }
            _ => self.counters.created,
        };
        // As SIPp's call::init(): the file first, which a call refused for
        // want of a circuit writes too.
        let srtpctx = self.args.srtpctx.and_then(|mode| call::srtpctx_open(mode, &mut self.args.log));
        let circuit = match self.args.tdm.as_mut() {
            None => None,
            Some(map) => match map.take(self.rng.next_u32()) {
                Some(n) => Some((n, map.name(n))),
                None => {
                    self.args.log.warning("Can't create new outgoing call: all tdm_map circuits busy");
                    if user > 0 {
                        self.free_users.push_front(user);
                    }
                    let st = match sc {
                        call::Sc::Main => {
                            self.counters.failed += 1;
                            &mut self.stats
                        }
                        call::Sc::Ooc => self.side_stats[0].as_mut().unwrap(),
                        call::Sc::Rx => self.side_stats[1].as_mut().unwrap(),
                        call::Sc::Aa => self.side_stats[2].as_mut().unwrap(),
                    };
                    st.ended(Some(false), Some(stat::Fail::OutboundCongestion), Duration::ZERO);
                    return false;
                }
            },
        };
        // -rsa: everything goes there, the keywords still naming the peer.
        let (peer, keywords) = match self.args.rsa {
            Some(rsa) => (Peer { addr: rsa, conn: peer.conn }, Some(peer.addr)),
            None => (peer, None),
        };
        let mut call = Call::new(number, id.clone(), peer);
        call.turns = true;
        call.srtpctx = srtpctx;
        call.sc = sc;
        if let Some((n, name)) = circuit {
            call.set_circuit(n, name);
        }
        if self.args.log.calldebug.is_open() {
            call.start_debug(&self.args.log);
        }
        call.set_origin(self.args.cfg.base_cseq, keywords);
        call.user_id = user;
        let table = (user > 0).then(|| self.user_vars.entry(user).or_default().clone());
        call.set_vars(vars::Vars::new(self.scopes.clone(), table));
        let rng = &mut self.rng;
        let inject = if sc == call::Sc::Rx { &mut self.args.rx_inject } else { &mut self.args.inject };
        match inject.assign(user, || rng.next_u32(), true) {
            Ok(lines) => call.lines = lines,
            Err(e) => self.control.fatal = Some(e),
        }
        // The newest call takes the Call-ID's messages over, from a dead
        // call silently; a live one runs on without them.
        if self.calls.contains_key(&id) {
            self.args.log.warning(&format!("Call-ID '{id}' is already in use by another call"));
            self.displace(&id);
        } else if !self.aliases.is_empty() && self.aliases.remove(&id).is_some() {
            self.args.log.warning(&format!("Call-ID '{id}' is already in use by another call"));
        }
        self.dead.remove(id.as_str());
        if scenario_of(&self.args, sc).is_some_and(|s| s.new_dialogs) {
            call.wait_seq = Some(self.new_dialog_seq);
            self.new_dialog_calls.insert(self.new_dialog_seq, id.clone());
            self.new_dialog_seq += 1;
        }
        if sc != call::Sc::Main {
            self.side_calls += 1;
        }
        self.calls.insert(id, Box::new(call));
        true
    }

    /// -rate_increase every -rate_interval, up to -rate_max, where the run
    /// ends unless -no_rate_quit.
    fn ramp(&mut self, now: Instant) {
        let Some(step) = self.args.rate_increase.filter(|s| *s != 0.0) else { return };
        if now.duration_since(self.last_ramp) < self.args.rate_interval {
            return;
        }
        self.last_ramp = now;
        // SIPp's ratetask's wakeup.
        self.woken += 1;
        self.rate += step;
        if let Some(max) = self.args.rate_max.filter(|m| *m > 0.0 && self.rate > *m) {
            self.rate = max;
            if self.args.rate_quit {
                self.control.quitting = true;
            }
        }
        self.rate_since = (call::tick_ms(now), self.counters.created as i64);
        if let Some(length) = self.args.auto_limit {
            self.args.limit = open_calls_allowed(self.rate, length, self.args.rate_period.as_millis() as u64);
        }
    }

    /// In SIPp's timer cycle (see run_timers()), the call generation
    /// task's last wakeup, which ends it once quitting.
    fn timer_cycle(&mut self, tick: Instant) {
        if self.generator.is_some() {
            // It wakes for its next call, at the rate from its last change;
            // paused, or for -users, only when a call ends.
            let next = (!self.traffic_paused && self.args.cfg.users.is_none()).then(|| self.generator_wake());
            match next {
                _ if !self.control.quitting => self.generator = Some(next),
                Some(at) if self.cycle.is_some_and(|c| c > at) => {
                    self.generator = None;
                    self.woken += 1;
                }
                Some(_) => {}
                None => self.generator = None,
            }
        }
        // The ratetask wakes on while the calls end.
        if self.control.quitting && self.rate_task() && tick.duration_since(self.last_ramp) >= self.args.rate_interval {
            self.last_ramp = tick;
            self.woken += 1;
        }
    }

    /// The millisecond SIPp's call generation task wakes after for the
    /// next call at the rate, counted from the rate's last change.
    fn generator_wake(&self) -> u64 {
        let (since, base) = self.rate_since;
        let n = (self.counters.created as i64 - base + 1).max(1) as f64;
        since + (n * self.args.rate_period.as_millis() as f64 / self.rate.max(1.0)) as u64
    }

    /// SIPp's ratetask, of -rate_increase, until a hard quit.
    fn rate_task(&self) -> bool {
        self.args.rate_increase.is_some_and(|s| s != 0.0) && !self.forcing
    }

    /// What SIPp's timer cycle counts as paused, `woken` calls just woken.
    fn count_paused(&mut self, woken: usize) {
        let stat_task = self.args.stat_path.is_some() || self.args.counts_file.is_some() || self.args.codes_file.is_some();
        let tasks = 1 + usize::from(!self.args.watchdog.is_zero()) + usize::from(stat_task) + usize::from(self.generator.is_some()) + usize::from(self.rate_task());
        // Those that ran in the pass before are in SIPp's run queue still.
        self.running = self.ran.min(self.calls.len());
        self.paused = self.calls.len().saturating_sub(woken + self.running) + self.dead.len() + tasks;
    }

    fn generate_calls(&mut self, now: Instant) {
        // Only scenarios that start by sending start calls by themselves;
        // one with only commands has no remote host.
        let remote = self.args.given_remote;
        if self.control.quitting || self.traffic_paused || !self.args.creates {
            return;
        }
        // Counted from the last rate change, as SIPp's set_rate() does,
        // so the first call is one period/rate after it, on its clock.
        let at_rate = |e: &Engine, tick: u64| {
            let (since, base) = e.rate_since;
            let ms = tick.saturating_sub(since);
            (base + calls_by_rate(Duration::from_millis(ms), e.rate, e.args.rate_period) as i64).max(0) as u64
        };
        let due = if self.args.cfg.users.is_some() {
            // As many calls as there are users, at the rate while ramping up.
            let due = self.counters.created + self.free_users.len() as u64;
            if self.ramping { due.min(at_rate(self, call::tick_ms(now))) } else { due }
        } else {
            self.ramp(now);
            // The task makes them as it wakes, in a timer cycle once past
            // the next call's millisecond.
            match self.cycle {
                Some(tick) if tick > self.generator_wake() => at_rate(self, tick),
                _ => return,
            }
        };
        let due = self.args.max_calls.map_or(due, |m| due.min(m));
        // A late loop catches up on the rate, but in slices, as SIPp's
        // call generation stops once its millisecond clock ticks: the calls
        // made so far must still get their timers and messages, when a
        // bind() is slow or the peer falls behind.
        let burst = call::tick_ms(Instant::now());
        // The call generation task's wakeup, at the rate (not for -users
        // once it ramped up: calls ending run it then).
        if self.counters.created < due && (self.args.cfg.users.is_none() || self.ramping) {
            self.woken += 1;
        }
        while self.counters.created < due && self.calls.len() - self.side_calls < self.args.limit && !self.control.stop_now && self.control.fatal.is_none() && call::tick_ms(Instant::now()) == burst {
            let user = if self.args.cfg.users.is_some() { self.free_users.pop_back().unwrap_or(0) } else { 0 };
            let id = self.args.call_ids.make(self.next_number, self.pid, &self.args.cfg.local_ip, &mut self.rng);
            // -round_robin: the remote host's next address.
            let remote = match self.args.remotes.len() {
                0 | 1 => remote,
                n => {
                    self.next_remote += 1;
                    Some(self.args.remotes[(self.next_remote - 1) % n])
                }
            };
            let dest = remote.map(|r| self.args.rsa.unwrap_or(r));
            let conn = match dest.map(|d| self.net.connect(d)).unwrap_or(Ok(None)) {
                Ok(c) => c,
                Err(e) => {
                    let Some(fail) = self.connect_failed(&e) else {
                        // The call was made before its connect ended the run.
                        if !self.net.transport.single() {
                            self.counters.created += 1;
                            self.next_number += 1;
                            self.stats.created(false);
                        }
                        break;
                    };
                    self.counters.created += 1;
                    self.next_number += 1;
                    self.counters.failed += 1;
                    self.stats.created(false);
                    self.stats.ended(Some(false), Some(fail), Duration::ZERO);
                    if user > 0 {
                        self.free_users.push_front(user);
                    }
                    if self.control.fatal.is_some() {
                        break;
                    }
                    continue;
                }
            };
            if !self.start_call(id.clone(), Peer { addr: remote.unwrap_or(NO_REMOTE), conn }, user, false, call::Sc::Main) {
                continue;
            }
            if self.net.transport == Transport::UdpPerIp {
                // -t ui: the local IP comes from the call's line of the
                // first -inf, as SIPp resolves it; a host it can't, or an
                // address it can't bind, is its ERROR().
                let inject = &self.args.inject;
                let field = inject.default_name().and_then(|name| {
                    let line = *self.calls[&id].lines.get(name)?;
                    Some((name.to_string(), inject.get(name)?.field(line, self.args.ip_field)))
                });
                match field {
                    Some((file, v)) => {
                        if self.udp_per_ip_socket(&id, &file, &v) {
                            continue;
                        }
                    }
                    None => self.args.log.warning(&format!("Call-Id '{id}': no IP address in -ip_field {}", self.args.ip_field)),
                }
            }
            let (mut env, call) = self.env_of(&id);
            let outcome = call.advance(&mut env);
            self.finish(&id, outcome);
            self.check_ramp();
        }
        // SIPp counts the calls -l holds back as made: the rate does not
        // catch up on them once calls end.
        if self.calls.len() - self.side_calls >= self.args.limit && self.counters.created < due {
            self.rate_since.1 -= (due - self.counters.created) as i64;
        }
    }

    /// -t ui: the call's socket on the address of its -ip_field `v`; true
    /// on SIPp's ERROR() for it, the run ending.
    fn udp_per_ip_socket(&mut self, id: &str, file: &str, v: &str) -> bool {
        let ip = match (v, 0).to_socket_addrs().map(|mut a| a.next()) {
            Ok(Some(a)) => Some(a.ip()),
            Ok(None) => None,
            Err(e) => {
                let e = e.to_string();
                self.args.log.warning(&format!("getaddrinfo failed: {}", e.strip_prefix("failed to lookup address information: ").unwrap_or(&e)));
                None
            }
        };
        let Some(ip) = ip else {
            self.control.fatal = Some(format!("Unknown host '{v}' in the -ip_field of {file}"));
            return true;
        };
        match self.net.udp_call_socket(Some(ip)) {
            Ok(sock) => self.calls.get_mut(id).unwrap().peer.conn = sock,
            Err(e) => {
                let (text, code) = error_no("Unable to bind UDP socket", &e);
                (self.control.fatal, self.control.fatal_code) = (Some(text), Some(code));
                return true;
            }
        }
        false
    }

    /// A connection refused or failed at connect(): the call's failure,
    /// or None when the run must end.
    fn connect_failed(&mut self, e: &std::io::Error) -> Option<stat::Fail> {
        if e.get_ref().is_some_and(|i| i.is::<net::NoCallSocket>()) {
            self.control.fatal = Some(e.to_string());
            return None;
        }
        // SIPp connects without waiting: a refusal shows on the
        // shared connection's read (its reset path), or on a
        // call's own connection's first send.
        let why = net::os_error(e);
        let handshake = net::handshake_failed(e);
        self.net_warnings();
        let errno = |n: i32| format!("errno = {n} ({})", net::os_error(&std::io::Error::from_raw_os_error(n)));
        let fail = if let (Some(n), true) = (handshake, self.net.transport.single()) {
            // SIPp makes the connection at the start.
            self.control.fatal = Some(format!("Unable to connect a TCP socket.\nUse 'sipp -h' for details, {}", errno(n)));
            return None;
        } else if !self.net.transport.single() {
            // connect_socket_if_needed(), for a call's own: its TLS
            // handshake failed, or its connect() did at once.
            let n = handshake.or(e.raw_os_error()).unwrap_or(0);
            let peer_error = handshake.is_none() && n == sys::EINVAL;
            let text = if peer_error { "Unable to connect a TCP/SCTP/TLS socket, remote peer error" } else { "Unable to connect a TCP/SCTP/TLS socket" };
            let r = &mut self.args.reconnect;
            if r.left == 0 {
                self.control.fatal = Some(if peer_error { text.to_string() } else { format!("{text}, {}", errno(n)) });
                return None;
            }
            r.left -= i64::from(r.left > 0);
            self.args.log.warning(text);
            // Only the call fails; the others go on.
            stat::Fail::TcpConnect
        } else {
            self.connection_failed(None, &format!("Error on TCP connection, remote peer probably closed the socket: {why}"));
            // Fatal: SIPp ends before any call is made.
            if self.control.fatal.is_some() {
                return None;
            }
            stat::Fail::TcpClosed
        };
        Some(fail)
    }

    /// The ramp ends once the calls are up to the users, not after as
    /// many calls as the users: shorter calls end during the ramp.
    fn check_ramp(&mut self) {
        if self.ramping && self.free_users.is_empty() {
            self.ramping = false;
        }
    }

    fn on_packet(&mut self, msg: &Arc<str>, src: Peer) {
        let raw: &str = msg;
        // sipMsgCheck(): no "SIP/2.0" anywhere is no SIP, bar the usual
        // keep-alives.
        if !raw.contains("SIP/2.0") {
            if raw != "\r\n\r\n" && raw != "\0\0\0\0" {
                self.args.log.warning(&format!("non SIP message discarded: \"{raw}\" ({})", raw.len()));
            }
            return;
        }
        // Indexed for its headers.
        sip::index(msg);
        // get_call_id(), which says so of a line feed without its CR.
        let id = sip::call_id(raw).unwrap_or_else(|pos| {
            self.args.log.warning(&format!("Missing CR during header scan at pos {pos}"));
            ""
        });
        // As get_trimmed_call_id() leaves it, after a "///".
        let trimmed = if self.args.cfg.callid_slash_ign { id } else { id.split_once("///").map_or(id, |(_, rest)| rest) };
        if trimmed.is_empty() {
            // process_message(): one warning.
            self.args.log.warning(&format!("SIP message without a valid Call-ID: header discarded: '{raw}'"));
            return;
        }
        self.args.log.received(self.net.transport.name(), raw);
        // A -trace_msg file that could not be rotated: SIPp exits there.
        if log::fatal_deferred() {
            return;
        }
        let mut id = self.listener_key(id);
        if !self.new_dialog_calls.is_empty() && !self.calls.contains_key(&*id) && !self.dead.contains_key(&*id) {
            // A request that starts a dialog of a call waiting for it.
            if let Some(key) = self.take_new_dialog(raw) {
                id = key.into();
            }
        }
        if !self.calls.contains_key(&*id) {
            if let Some(dead) = self.dead.get_mut(&*id) {
                let trace = format!("-----------------------------------------------\nDead call {id} received a {} message:\n\n{raw}\n", self.net.transport.name());
                // The 200 to the aborting BYE or CANCEL, and the 487 to the
                // cancelled INVITE, only trail the call.
                let answer = match (sip::kind(raw), sip::cseq_method(raw)) {
                    (Some(sip::Kind::Response(200)), Some(m)) => Some(m),
                    (Some(sip::Kind::Response(487)), Some("INVITE")) => Some("CANCEL"),
                    _ => None,
                };
                if answer.is_some() && answer == dead.aborted_with {
                    self.args.log.trace_msg(&trace);
                    return;
                }
                self.stats.dead_call();
                self.args.log.warning(&format!("Dead call {id} ({}), received '{raw}'", dead.reason));
                self.args.log.trace_msg(&trace);
                dead.until = Instant::now() + self.args.deadcall_wait;
                self.dead_expiry.push((dead.until, id.as_ref().into()));
                return;
            }
            // A server's new call, or a mixed run's -rxsf call. What its
            // scenario can't begin with would only take the next call's
            // place: a response, or a request -aa or -oocsf answers, goes
            // where a client's does.
            let incoming = match (self.args.cfg.client, self.args.rx.as_ref()) {
                (false, _) => Some((call::Sc::Main, &self.args.scenario)),
                (true, Some(rx)) => Some((call::Sc::Rx, rx)),
                (true, None) => None,
            };
            // get_reply_code(): a "SIP/2.0" with no code isn't one.
            let response = matches!(sip::kind(raw), Some(sip::Kind::Response(1..)));
            let out_of_call = incoming.is_none_or(|(_, s)| !starts_with(s, raw) && (response || self.args.ooc.is_some() || call::auto_answered(&self.args.cfg, raw)));
            let sc = match incoming {
                Some((call::Sc::Main, _)) if !out_of_call => {
                    // -m and quitting hold back the main scenario's calls only.
                    if self.args.max_calls.is_some_and(|m| self.counters.created >= m) || self.control.quitting {
                        self.stats.out_of_call();
                        self.args.log.trace_msg("Discarded message for new calls while quitting\n");
                        return;
                    }
                    call::Sc::Main
                }
                Some((sc, _)) if !out_of_call => sc,
                _ if self.args.ooc.is_some() => {
                    if response {
                        self.stats.out_of_call();
                        return;
                    }
                    let method = raw.split(|c: char| c.is_ascii_whitespace()).next().unwrap_or("");
                    self.args.log.warning(&format!("Received out-of-call {method} message, using the out-of-call scenario"));
                    self.stats.auto_answered();
                    call::Sc::Ooc
                }
                _ if call::auto_answered(&self.args.cfg, raw) => {
                    self.stats.auto_answered();
                    call::Sc::Aa
                }
                _ => {
                    self.stats.out_of_call();
                    self.args.log.warning(&format!("Discarding message which can't be mapped to a known SIPp call:\n{raw}"));
                    return;
                }
            };
            // SIPp's 3PCC controller B, slave, and passive controller A or
            // master count every call they make as outgoing.
            let incoming = !(self.args.cmd_starts && sc == call::Sc::Main);
            if !self.start_call(id.to_string(), src, 0, incoming, sc) {
                return;
            }
        }
        let (mut env, call) = self.env_of(&id);
        call.request_came(&mut env, raw, src);
        let mut outcome = call.on_message(&mut env, msg.clone());
        // An -aa call is done once it has answered (SIPp PR #1023).
        if call.sc == call::Sc::Aa && matches!(outcome, Outcome::Running) {
            outcome = Outcome::Success;
        }
        self.finish(&id, outcome);
    }

    /// The calls' next turns, in the order they took the last.
    fn run_turns(&mut self) {
        // No command to fail, which finish() would see to.
        let no_cmds = self.links.twin.is_none() && self.links.peers.is_none() && !self.links.gone;
        let pass = self.pass;
        let mut ran = 0;
        let mut due = std::mem::take(&mut self.due);
        for id in due.drain(..) {
            let Some((mut env, call)) = self.try_env_of(&id) else { continue };
            call.turn_queued = false;
            if !std::mem::take(&mut call.turn) {
                continue;
            }
            let outcome = call.advance(&mut env);
            // The call runs on, with nothing else for finish() to do: its
            // reschedule() here, with the call at hand.
            if matches!(outcome, Outcome::Running) && no_cmds && env.verify.is_empty() && !call.has_dialog_ids() {
                if call.ran_in != pass {
                    call.ran_in = pass;
                    ran += 1;
                }
                let next = call.next_wakeup();
                let moved = next != call.scheduled;
                call.scheduled = next;
                let again = call.turn;
                call.turn_queued = again;
                if let Some(t) = next.filter(|_| moved) {
                    self.timers.push(Reverse((t, id.clone())));
                }
                if again {
                    self.turns.push(id);
                }
                continue;
            }
            self.finish(&id, outcome);
        }
        self.due = due;
        self.ran += ran;
    }

    fn run_timers(&mut self, now: Instant) {
        // SIPp wakes its tasks in its timer cycle, every -timer_resol, once
        // its clock is past their millisecond; a run that is over ends
        // before it.
        let tick = call::tick_ms(now);
        if tick - self.last_cycle <= self.args.timer_resol.as_millis() as u64 || self.done() {
            self.cycle = None;
            return;
        }
        self.cycle = Some(tick);
        self.last_cycle = tick;
        let by = call::epoch() + Duration::from_millis(tick);
        let mut due = Vec::new();
        while self.timers.peek().is_some_and(|Reverse((t, _))| *t < by) {
            let Reverse((t, id)) = self.timers.pop().unwrap();
            if let Some(call) = self.calls.get_mut(&id).filter(|c| c.scheduled == Some(t)) {
                call.scheduled = None;
                due.push(id);
            }
        }
        let firing = due.iter().filter(|id| self.calls.get(*id).is_some_and(|c| c.next_wakeup().is_some_and(|t| t < by))).count();
        self.count_paused(firing);
        for id in due {
            if self.calls.get(&id).is_some_and(|c| c.next_wakeup().is_some_and(|t| t < by)) {
                self.woken += 1;
                let (mut env, call) = self.env_of(&id);
                let outcome = call.on_timer(&mut env, now);
                self.finish(&id, outcome);
            } else {
                self.reschedule(&id, false);
            }
            self.check_ramp();
        }
        while self.dead_expiry.front().is_some_and(|(t, _)| *t < by) {
            let (t, id) = self.dead_expiry.pop().unwrap();
            if self.dead.get(&id).is_some_and(|d| d.until == t) {
                self.dead.remove(&id);
                self.woken += 1;
            }
        }
    }

    /// write_error() on a 3PCC connection: a connection gone or refused
    /// is reset, in read_error()'s words but for a broken pipe. Any other
    /// error SIPp only warns about, and then takes the connection the
    /// error left dead for a clean close: A stops reconnecting, and the
    /// call waits for ever. It is a reset too, as if read.
    fn twin_write_failed(&mut self, e: std::io::Error, dest: Option<String>) {
        // nb_net_send_errors.
        self.net.send_errors += 1;
        match e.raw_os_error() {
            Some(sys::EPIPE) => self.twin_failed("Broken pipe on TCP connection, remote peer probably closed the socket", dest),
            Some(sys::ECONNRESET | sys::ECONNREFUSED | sys::ENOTCONN) => self.twin_failed(&twin_error(&e), dest),
            _ => {
                self.args.log.warning(&format!("Unable to send TCP message: {}", net::os_error(&e)));
                self.twin_failed(&twin_error(&e), dest);
            }
        }
    }

    /// -3pcc: call::close_twin_calls(), the calls of any scenario waiting
    /// at a <recvCmd> when the twin connection is lost. How many failed.
    fn close_twin_calls(&mut self) -> usize {
        let waiting = |c: &Call| {
            let sc = match c.sc {
                call::Sc::Main => Some(&self.args.scenario),
                call::Sc::Ooc => self.args.ooc.as_ref(),
                call::Sc::Rx => self.args.rx.as_ref(),
                call::Sc::Aa => self.args.aa.as_ref(),
            };
            matches!(sc.and_then(|sc| sc.steps.get(c.index())).map(|s| &s.op), Some(Op::RecvCmd { .. }))
        };
        let ids = self.call_ids(waiting);
        for id in &ids {
            let Some(call) = self.calls.get_mut(id) else { continue };
            let outcome = call.twin_lost();
            self.finish(id, outcome);
        }
        ids.len()
    }

    /// read_error() and write_error() on a 3PCC connection (`dest` names
    /// the extended mode peer of one we made), and reset_connection():
    /// without a reconnection left (-max_reconnect) the run ends; else,
    /// after -reconnect_sleep, a connection we made is made again. One we
    /// accepted is the peer's to make again, and the listener waits for
    /// it: SIPp "reconnects" it to the peer's own port instead, which
    /// never works.
    fn twin_failed(&mut self, why: &str, dest: Option<String>) {
        let to = match (&self.links.twin, &self.links.peers, &dest) {
            (Some(twin), _, None) => twin.to,
            (_, Some(peers), Some(d)) => peers.addrs.get(d).copied(),
            _ => None,
        };
        let r = &mut self.args.reconnect;
        if r.left == 0 {
            self.control.fatal = Some(why.to_string());
            return;
        }
        self.args.log.warning(why);
        if r.left > 0 {
            r.left -= 1;
        }
        let (close, sleep) = (r.close, r.sleep);
        if close {
            self.args.log.warning("Closing calls, because of TCP reset or close!");
            // SIPp closes none, as no call uses it for SIP: those waiting
            // for a command on it wait for ever.
            if self.links.twin.is_some() {
                self.close_twin_calls();
            }
        }
        let Some(to) = to else { return };
        std::thread::sleep(sleep);
        let fresh = match Twin::connect(to) {
            Ok(s) => {
                self.args.log.warning("Socket required a reconnection.");
                Some(s)
            }
            Err(e) => {
                self.args.log.warning(&format!("Could not reconnect TCP socket, errno = {} ({})", e.raw_os_error().unwrap_or(0), net::os_error(&e)));
                None
            }
        };
        match (self.links.twin.as_mut(), self.links.peers.as_mut(), dest) {
            (Some(twin), _, None) => {
                twin.stream = fresh;
                twin.buf.clear();
                twin.out.connecting = true;
            }
            (_, Some(peers), Some(d)) => {
                peers.out.entry(d.clone()).or_default().connecting = true;
                peers.outgoing.insert(d, fresh);
            }
            _ => {}
        }
    }

    /// rtp_stream="wait": the calls whose streams the media threads saw
    /// play out go on, as they end and not polled for.
    fn rtp_played(&mut self) {
        let ended = mediapool::take_ended();
        if ended.is_empty() {
            return;
        }
        for id in self.call_ids(|c| c.rtp_waiting_task().is_some_and(|t| ended.contains(&t))) {
            let (mut env, call) = self.env_of(&id);
            let outcome = call.rtp_played(&mut env);
            self.finish(&id, outcome);
        }
    }

    /// reap_verify_commands(): the <exec verify> commands that exited wake
    /// the calls that wait for them, without waiting for the others.
    fn reap_verify(&mut self) {
        let mut i = 0;
        while i < self.verify.len() {
            let Ok(Some(status)) = self.verify[i].child.try_wait() else {
                i += 1;
                continue;
            };
            let done = self.verify.remove(i);
            if let Some(id) = done.call {
                let (mut env, call) = self.env_of(&id);
                let outcome = call.verify_done(&mut env, &done.command, status);
                self.finish(&id, outcome);
            } else if let Some(mut init) = done.init.and_then(|slot| self.inits[slot].take()) {
                self.init_step(&mut init, |call, env| {
                    call.verify_done(env, &done.command, status);
                });
                // Its commands that remain, and those it starts now.
                let slot = done.init.unwrap();
                let pending = init.call.verify_pending > 0;
                for (child, command) in self.verify_started.drain(..) {
                    self.verify.push(Verify { child, call: None, init: pending.then_some(slot), command });
                }
                if pending {
                    self.inits[slot] = Some(init);
                } else {
                    for v in self.verify.iter_mut().filter(|v| v.init == Some(slot)) {
                        v.init = None;
                    }
                }
            }
        }
    }

    /// Commands from the twin SIPp: to their Call-ID's call, else to the call
    /// waiting for one, else (controller B) to a new call.
    fn poll_twin(&mut self) {
        let cmds = match (self.links.twin.as_mut(), self.links.peers.as_mut()) {
            (Some(twin), _) => twin.poll(),
            (None, Some(peers)) => peers.poll(&mut self.args.log),
            _ => return,
        };
        if let Some(e) = self.links.peers.as_mut().and_then(|p| p.fatal.take()) {
            self.control.fatal = Some(e);
            return;
        }
        // flush(): the commands that waited, traced once written whole.
        let written = match (self.links.twin.as_mut(), self.links.peers.as_mut()) {
            (Some(twin), _) => std::mem::take(&mut twin.out.written),
            (None, Some(peers)) => peers.out.values_mut().flat_map(|o| std::mem::take(&mut o.written)).collect(),
            _ => Vec::new(),
        };
        for cmd in written {
            self.args.log.sent("TCP control", &cmd);
        }
        for cmd in cmds {
            self.args.log.received("TCP control", &cmd);
            // A command has no start line: its headers begin at once.
            let headers = format!("CMD\r\n{cmd}");
            let named = sip::header(&headers, "Call-ID").map(|id| self.listener_key(id).into_owned());
            let mut id = named.clone().filter(|id| self.calls.contains_key(id));
            if let Some(dead) = named.as_ref().filter(|_| id.is_none()).and_then(|n| self.dead.get(n.as_str())) {
                // deadcall::process_twinSippCom().
                let trace = format!("Received twin message for dead ({}) call {}:{cmd}\n", dead.reason, named.as_deref().unwrap_or(""));
                self.stats.dead_call();
                self.args.log.trace_msg(&trace);
                continue;
            }
            if id.is_none() {
                let (env, calls) = self.env();
                id = calls.iter().find(|(_, c)| c.waits_for_command(&env)).map(|(id, _)| id.clone());
            }
            let id = match id {
                Some(id) => id,
                None if self.args.cmd_starts && !self.args.max_calls.is_some_and(|m| self.counters.created >= m) => {
                    // The new call takes the Call-ID the command names, as in SIPp.
                    let id = match named {
                        Some(id) => id,
                        None => self.args.call_ids.make(self.next_number, self.pid, &self.args.cfg.local_ip, &mut self.rng),
                    };
                    let remote = self.args.given_remote;
                    let conn = remote.and_then(|r| self.net.connect(r).ok().flatten());
                    if !self.start_call(id.clone(), Peer { addr: remote.unwrap_or(NO_REMOTE), conn }, 0, false, call::Sc::Main) {
                        continue;
                    }
                    id
                }
                _ => {
                    self.stats.out_of_call();
                    self.args.log.warning(&format!("Discarding message which can't be mapped to a known SIPp call:\n{cmd}"));
                    continue;
                }
            };
            let (mut env, call) = self.env_of(&id);
            let outcome = call.on_command(&mut env, &cmd);
            self.finish(&id, outcome);
        }
        let error = match (self.links.twin.as_mut(), self.links.peers.as_mut()) {
            (Some(twin), _) => twin.error.take().map(|e| (e, None)),
            (_, Some(peers)) => peers.error.take(),
            _ => None,
        };
        // A read's error, or a write's of what waited: only a write
        // breaks a pipe.
        match error {
            Some((e, dest)) if e.raw_os_error() == Some(sys::EPIPE) => self.twin_write_failed(e, dest),
            Some((e, dest)) => self.twin_failed(&twin_error(&e), dest),
            None => {}
        }
        // SIPp's hard quit: every open call is aborted, and fails.
        if self.links.peers.as_ref().is_some_and(|p| p.closed) {
            self.args.log.warning("One of the twin instances has ended -> exiting");
            self.links.peers = None;
            self.control.quitting = true;
            self.forcing = true;
            self.abort_all();
        }
        // Controller B quits at once, A as its calls end, those waiting for
        // a command failing; neither notices once its last call ended, as
        // SIPp quits before it reads again.
        if self.links.twin.as_ref().is_some_and(|t| t.closed) && !self.done() {
            self.links.twin = None;
            self.control.quitting = true;
            if self.args.twin_listens {
                self.args.log.warning("3PCC controller A has ended -> exiting");
                self.forcing = true;
                self.abort_all();
            } else {
                self.links.gone = true;
                let failed = self.close_twin_calls();
                if failed > 0 {
                    self.args.log.warning(&format!("The remote peer closed the TCP connection, failing {failed} call(s)"));
                }
            }
        }
        self.count_sockets();
    }

    /// SIPp's pollnfds: the control and stdin sockets, and the 3PCC twin
    /// ones (-3pcc's listener and connection, extended mode's listener
    /// and its connections each way), besides Net's own.
    fn count_sockets(&mut self) {
        let twin = self.links.twin.as_ref().map_or(0, |t| usize::from(t.listener.is_some()) + usize::from(t.stream.is_some()));
        let peers = self.links.peers.as_ref().map_or(0, |p| 1 + p.incoming.len() + p.outgoing.values().flatten().count());
        self.net.other_sockets = usize::from(self.control_sock.is_some()) + usize::from(!self.args.nostdin) + twin + peers;
    }

    /// The calls `keep` picks, the oldest first, as SIPp's task list has
    /// them.
    fn call_ids(&self, keep: impl Fn(&Call) -> bool) -> Vec<String> {
        let mut ids: Vec<(Instant, &String)> = self.calls.iter().filter(|(_, c)| keep(c)).map(|(id, c)| (c.created, id)).collect();
        ids.sort();
        ids.into_iter().map(|(_, id)| id.clone()).collect()
    }

    /// -timeout without -timeout_error: every open call is aborted and failed.
    fn abort_all(&mut self) {
        for id in self.call_ids(|_| true) {
            let (mut env, call) = self.env_of(&id);
            call.abort_now(&mut env);
            self.finish(&id, Outcome::Failed);
        }
    }

    fn done(&self) -> bool {
        let finished = self.counters.successful + self.counters.failed + self.counters.discarded;
        self.control.stop_now
            || self.control.fatal.is_some()
            || self.args.log.dead
            // SIPp waits for the main scenario's calls only.
            || (self.calls.len() == self.side_calls
                && (self.control.quitting || self.args.max_calls.is_some_and(|m| finished >= m)))
    }

    /// A key or command; true when the run must stop now.
    fn control_input(&mut self, input: control::Input) -> bool {
        let request = match input {
            control::Input::Key(k) => control::key(k),
            control::Input::Command(c) => match control::command(&c) {
                Ok(r) => Some(r),
                Err(e) => {
                    self.args.log.warning(&e);
                    None
                }
            },
        };
        let Some(request) = request else { return false };
        use control::Request;
        match request {
            Request::Screen(n) => self.screen = n,
            Request::Rate(steps) => {
                let by = steps * self.rate_scale;
                match self.args.cfg.users {
                    Some(u) => self.set_users((u as f64 + by).max(0.0) as u32),
                    None => self.set_rate(self.rate + by),
                }
            }
            Request::PauseTraffic => {
                self.traffic_paused = !self.traffic_paused;
                if !self.traffic_paused {
                    // As set_paused(false): counted afresh from now.
                    self.set_rate(self.rate);
                }
            }
            Request::DumpScreens => {
                if let Some(path) = self.args.screen_file.clone() {
                    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
                        self.print_screens(&mut f);
                    }
                }
            }
            Request::Quit if self.control.quitting => return true,
            Request::Quit => self.control.quitting = true,
            Request::QuitNow => return true,
            Request::SetRate(r) if self.args.cfg.users.is_some() => {
                let _ = r;
                self.args.log.warning("Rates can not be set in a user-based benchmark.");
            }
            Request::SetRate(r) => self.set_rate(r),
            Request::SetRateScale(s) => self.rate_scale = s,
            Request::SetUsers(_) if self.args.cfg.users.is_none() => {
                self.args.log.warning("Users can not be changed at run time for a rate-based benchmark.");
            }
            Request::SetUsers(u) => self.set_users(u),
            Request::SetLimit(_) if self.args.cfg.users.is_some() => {
                self.args.log.warning("Can not set call limit for a user-based benchmark.");
            }
            Request::SetLimit(l) => {
                self.args.limit = l;
                self.args.auto_limit = None;
            }
            Request::SetHide(h) => self.hide = h,
            Request::Trace(log, on) => self.args.log.trace(&log, on),
            Request::Nothing => {}
            Request::DumpTasks => {
                let lines: Vec<String> = self.call_ids(|_| true).iter().map(|id| format!("Call {id} (index {})", self.calls[id].index())).collect();
                for l in lines {
                    self.args.log.warning(&l);
                }
            }
            Request::DumpVariables => {
                let mut names: Vec<&String> = self.args.scenario.global_vars.iter().chain(&self.args.scenario.user_vars).collect();
                names.sort();
                let line = format!("Variables: {}", names.iter().map(|n| format!("${n}")).collect::<Vec<_>>().join(", "));
                self.args.log.warning(&line);
            }
            Request::ResetStats => self.stats.reset_cumulative(),
        }
        false
    }

    /// CallGenerationTask::set_rate(): from now on, and -l with it.
    fn set_rate(&mut self, rate: f64) {
        self.rate = rate.max(0.0);
        self.rate_since = (call::tick_ms(Instant::now()), self.counters.created as i64);
        if let Some(length) = self.args.auto_limit {
            self.args.limit = open_calls_allowed(self.rate, length, self.args.rate_period.as_millis() as u64);
        }
    }

    /// set_users(): new users join, and those past the count retire as
    /// their calls end.
    fn set_users(&mut self, users: u32) {
        let old = self.args.cfg.users.unwrap_or(0);
        for id in old + 1..=users {
            self.free_users.push_front(id);
        }
        if users < old {
            self.free_users.retain(|&id| id <= users);
        }
        self.args.cfg.users = Some(users);
        self.args.limit = users as usize;
        if self.args.rate_set {
            self.ramping = !self.free_users.is_empty();
        }
        self.rate_since = (call::tick_ms(Instant::now()), self.counters.created as i64);
    }

    /// SIPp's warning for each <recv> without request or response, as it
    /// draws the scenario screen.
    fn warn_recvs(&mut self) {
        let shown = |s: &&scenario::Step| !s.hide && matches!(s.op, Op::Recv { expect: Expect::Nothing, .. });
        for _ in self.args.scenario.steps.iter().filter(shown) {
            self.args.log.warning("<recv> without request/response?");
        }
    }

    /// The screen a terminal shows each second, as SIPp's curses one.
    fn draw_screen(&mut self) {
        if !self.live_screen {
            return;
        }
        if screen::is_scenario(self.screen) {
            self.warn_recvs();
        }
        let info = self.screen_info();
        let no_map = tdm::TdmMap::default();
        let map = self.args.tdm.as_ref().unwrap_or(&no_map);
        let lines = screen::by_number(self.screen, &self.args.scenario, &self.stats, map, &info, false);
        // draw_scenario_screen() counts the wakeups afresh.
        if screen::is_scenario(self.screen) {
            self.woken = 0;
            self.control.woken = 0;
        }
        let mut out = String::from("\x1b[H\x1b[2J");
        for l in lines {
            out += &l;
            out += "\r\n";
        }
        if let Some(cmd) = self.keyboard.as_ref().and_then(|k| k.typing()) {
            out += &format!("\r\nCommand: {cmd}");
        }
        let _ = raw::write(&mut std::io::stdout(), &out);
        let _ = std::io::stdout().flush();
    }

    fn lose_packets(&self) -> bool {
        self.args.cfg.lost > 0.0 || self.args.scenario.steps.iter().any(|s| s.lost.is_some())
    }

    /// dumpDataRtt() of each scenario: the response times held back, or
    /// with `full` only those of -rtt_freq times.
    fn write_rtts(&mut self, full: bool) {
        let freq = if full { self.args.rtt_freq } else { 1 };
        let [ooc, rx, aa] = &mut self.side_stats;
        if let Some(aa) = aa {
            aa.rtts.clear();
        }
        let stats = [Some(&mut self.stats), ooc.as_mut(), rx.as_mut()];
        for ((st, path), file) in stats.into_iter().zip(&self.args.rtt_paths).zip(&mut self.rtt_files) {
            let Some(st) = st else { continue };
            let Some(path) = path else {
                st.rtts.clear();
                continue;
            };
            if st.rtts.is_empty() || st.rtts.len() < freq {
                continue;
            }
            let d = &st.delimiter;
            if file.is_none() {
                let Ok(mut f) = File::create(path) else {
                    exit_now(&mut self.keyboard, &format!("Unable to open rtt file '{path}' !"));
                };
                let _ = writeln!(f, "Date_ms{d}response_time_ms{d}rtd_no");
                *file = Some(f);
            }
            let f = file.as_mut().expect("opened above");
            for (date, rtt, rtd) in std::mem::take(&mut st.rtts) {
                let _ = raw::write(f, &format!("{date:.3}{d}{rtt:.3}{d}{}\n", st.rtd_names()[rtd]));
            }
        }
    }

    fn screen_info(&self) -> screen::Info<'_> {
        // SIPp's paused tasks, as its last timer cycle counted them: its
        // calls, which wait for a message or a timer as they do here, but
        // those that ran in the pass before it (in the run queue still),
        // its dead calls, and its screen, watchdog, statistics and call
        // generation tasks.
        let paused = self.paused;
        let woken = self.woken + self.control.woken;
        screen::Info {
            // SIPp's creationMode: what the first message or command does.
            server: !self.args.creates,
            users: self.args.cfg.users,
            rate: self.rate,
            rate_period: self.args.rate_period,
            duration: self.args.cfg.default_pause,
            // A TCP/TLS/SCTP client has no socket of its own there, but SIPp
            // shows the port its main socket took.
            local_port: self.net.local_addr().map_or(self.args.cfg.local.port(), |a| a.port()),
            // SIPp's clock_tick.
            elapsed: call::epoch().elapsed(),
            // SIPp's remote_ip, whenever a remote host is given (a 3PCC
            // controller A with only commands too). Unresolved (-round_robin
            // refused), its empty remote_ip and default remote_port.
            remote: self.args.given_remote.map_or(":5060".into(), |r| format!("{}:{}", r.ip(), r.port())),
            transport: self.net.transport.name(),
            max_calls: self.args.max_calls,
            limit: self.args.limit,
            running: self.running,
            paused,
            woken,
            auto_answer: self.args.cfg.auto_answer,
            open_sockets: if self.sockets_closed { 0 } else { self.net.open_sockets() },
            net_errors: (self.net.send_errors, self.net.recv_errors),
            // rtpstream_shutdown() stops the threads before the last screens.
            rtp_threads: if self.sockets_closed { 0 } else { media::counters::threads() },
            rtp_echo: self.echo.is_some(),
            lose_packets: self.lose_packets(),
            loops: self.loops,
            state: if self.forcing {
                screen::State::Forcing
            } else if self.control.quitting {
                screen::State::Waiting
            } else if self.traffic_paused {
                screen::State::Paused
            } else {
                screen::State::Running
            },
            last_error: self.args.log.last_warning.as_deref(),
            third_party: self.third_party_footer(),
        }
    }

    /// get_lines()'s footer for SIPp's thirdPartyMode.
    fn third_party_footer(&self) -> Option<&'static str> {
        let drives = !self.args.twin_listens;
        if !self.args.scenario.steps.iter().any(|s| matches!(s.op, Op::SendCmd { .. } | Op::RecvCmd { .. })) {
            return None;
        }
        Some(match (&self.args.extended, self.args.twin.is_some()) {
            (Some((_, true, _)), _) if self.args.creates => "-----------------------3PCC extended mode - Master side -------------------------",
            (Some((_, true, _)), _) => "------------------ 3PCC extended mode - Master side (passive) --------------------",
            (Some(_), _) => "----------------------- 3PCC extended mode - Slave side -------------------------",
            (None, true) if drives && self.args.creates => "----------------------- 3PCC Mode - Controller A side -------------------------",
            (None, true) if drives => "------------------ 3PCC Mode - Controller A side (passive) --------------------",
            (None, true) => "----------------------- 3PCC Mode - Controller B side -------------------------",
            (None, false) => return None,
        })
    }

    /// print_screens(): every screen, to the screen file.
    fn print_screens(&mut self, f: &mut File) {
        self.warn_recvs();
        let info = self.screen_info();
        for line in screen::all(&self.args.scenario, &self.stats, &info) {
            let _ = raw::write(f, &format!("{line}\n"));
        }
    }

    /// SIGUSR2: the screens to -trace_screen's file, or else to the
    /// screen file created afresh, and -trace_rtt's times.
    fn signal_dump(&mut self) {
        if let Some(path) = self.args.screen_file.clone() {
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
                self.print_screens(&mut f);
            }
        } else {
            // Kept open until the next one, as SIPp's rotate_screenf().
            let mut screen = std::mem::take(&mut self.args.screen_log);
            match screen.rotate(&self.args.log.limits) {
                Ok(()) => {
                    if let Some(f) = screen.file.as_mut() {
                        self.print_screens(f);
                    }
                }
                Err(_) => self.control.fatal = Some(format!("Unable to create '{}'", screen.path)),
            }
            self.args.screen_log = screen;
        }
        // Its scenario screen counts the wakeups afresh.
        self.woken = 0;
        self.control.woken = 0;
        self.write_rtts(false);
    }

    /// print_closing_stats() on stdout, and -trace_screen's file.
    fn closing_screens(&mut self) {
        // The file first, as sipp_exit() writes it, whatever the way out.
        if self.args.screen_file.is_some() {
            self.warn_recvs();
        }
        if screen::is_scenario(self.screen) {
            self.warn_recvs();
        }
        let mut info = self.screen_info();
        let no_map = tdm::TdmMap::default();
        let map = self.args.tdm.as_ref().unwrap_or(&no_map);
        if let Some(path) = &self.args.screen_file {
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
                for line in screen::all(&self.args.scenario, &self.stats, &info) {
                    let _ = raw::write(&mut f, &format!("{line}\n"));
                }
                info.woken = 0;
            }
        }
        let mut stdout = std::io::stdout().lock();
        for line in screen::closing(self.screen, &self.args.scenario, &self.stats, map, &info) {
            let _ = raw::write(&mut stdout, &format!("{line}\n"));
        }
        drop(stdout);
        self.woken = 0;
        self.control.woken = 0;
    }


    /// The files SIPp opens once the scenario is loaded: -trace_screen's,
    /// as rotate_screenf() (the screens join it later), and -trace_counts'
    /// header.
    fn open_counts(&mut self) {
        self.write_counts(false);
    }

    /// A -trace_counts header or row: one that fails ended the run as
    /// the file was opened.
    fn write_counts(&mut self, row: bool) {
        let lose = self.lose_packets();
        let counts = screen::counts(&self.args.scenario, row.then_some(&self.stats), &self.stats.delimiter, self.args.rfc3339, lose);
        if let (Some(f), Ok(line)) = (self.args.counts_file.as_mut(), counts) {
            let _ = raw::write(f, &format!("{line}\n"));
        }
    }

    /// SIGXFSZ: as SIPp's stop_all_traces(), no more -trace_stat and
    /// -trace_rtt rows either.
    fn check_oversized(&mut self) {
        self.args.log.check_oversized();
        if std::mem::take(&mut self.args.log.stop_stats) {
            (self.args.stat_path, self.args.stat_file) = (None, None);
            self.args.rtt_paths = Default::default();
        }
    }

    /// A row, and a new period for the (P) columns, as SIPp's stattask.
    fn dump_stats(&mut self) {
        self.args.log.flush_deferred();
        self.stats.sync_warnings(self.args.log.warnings);
        if let (None, Some(path)) = (&self.args.stat_file, &self.args.stat_path) {
            match File::create(path) {
                Ok(f) => self.args.stat_file = Some(f),
                Err(_) => exit_now(&mut self.keyboard, &format!("Unable to open stat file '{path}' !")),
            }
        }
        if let Some(mut f) = self.args.stat_file.take() {
            write_stats(&mut f, self.stat_first, self);
            self.stat_first = false;
            self.args.stat_file = Some(f);
        }
        self.write_counts(true);
        if let Some(f) = self.args.codes_file.as_mut() {
            // print_error_codes_file(): the time, then the codes, newest first.
            let now = SystemTime::now();
            let ms = now.duration_since(self.stats.start()).unwrap_or_default().as_millis() as u64;
            let d = &self.stats.delimiter;
            let codes: String = self.stats.error_codes.drain(..).rev().map(|c| format!("{c},")).collect();
            let _ = writeln!(f, "{}{d}{}{d}{codes}", stat::format_time(now, self.args.rfc3339), stat::hhmmss_us(ms));
        }
        self.last_stat = Instant::now();
        self.stats.new_period();
    }

    /// sipp_exit(): nothing else tells why the exit code is 253.
    fn rtp_check_warning(&mut self) {
        let c = &self.counters;
        if c.rtp_errors > 0 || c.echo_errors {
            let mut e = if c.rtp_errors > 0 { rtp_check_failed(c.rtp_errors) } else { String::new() };
            if c.echo_errors {
                e += if c.rtp_errors > 0 { " and rtp_echo" } else { "rtp_echo" };
            }
            self.args.log.warning(&format!("RTP check failed: {e}"));
        }
    }

    /// An ERROR() while SIPp sets up, before the traffic: sipp_exit()'s
    /// closing screens and statistics row.
    fn startup_failed(&mut self, msg: &str, code: u8) -> u8 {
        self.stats.fatal_error();
        self.args.log.error(msg);
        self.closing_screens();
        self.dump_stats();
        self.args.log.print_errors();
        code
    }

    fn run(&mut self) -> u8 {
        // A server without a watchdog: its clock starts with the loop.
        call::epoch();
        self.count_sockets();
        self.run_init();
        let mut buf = vec![0u8; 65536];
        let mut got = Vec::new();
        let mut last_report = self.start;
        let mut loops = 0u64;
        let mut last_key = self.start;
        self.open_counts();
        // SIPp connects its single TCP/TLS/SCTP socket at the start, not
        // with the first call, which the rate may hold back for seconds.
        if let Some(to) = self.args.given_remote.filter(|_| self.args.connects_at_start()) {
            if let Err(e) = self.net.connect(self.args.rsa.unwrap_or(to)) {
                self.net_warnings();
                if self.args.reconnect.left > 0 {
                    // open_connections(): with a reconnection left, only a
                    // warning, the socket staying invalid for the calls,
                    // and the main socket closed.
                    self.args.log.warning("Failed to reconnect");
                    self.args.reconnect.left -= 1;
                    self.net.invalidate_shared();
                    self.net.close_main();
                } else {
                    let n = net::handshake_failed(&e).or(e.raw_os_error()).unwrap_or(0);
                    let why = net::os_error(&std::io::Error::from_raw_os_error(n));
                    let text = if n == sys::EINVAL { "Unable to connect a TCP socket, remote peer error." } else { "Unable to connect a TCP socket." };
                    // Before the traffic starts, as SIPp's open_connections().
                    return self.startup_failed(&format!("{text}\nUse 'sipp -h' for details, errno = {n} ({why})"), EXIT_FATAL_ERROR);
                }
            }
        }
        // Once that connection took its port: SIPp's main socket listens
        // for connections to it in client mode too.
        if let Err(e) = self.net.listen() {
            let (text, code) = error_no("Unable to listen main socket", &e);
            return self.startup_failed(&text, code);
        }
        // SIPp writes one before any call too.
        self.dump_stats();
        // The rate, and its increase, start with the traffic: the setup
        // may be slow, and the calls the rate is behind on would all open.
        self.set_rate(self.rate);
        self.last_ramp = Instant::now();
        self.next_watchdog = (!self.args.watchdog.is_zero()).then(|| self.last_ramp + self.args.watchdog);
        self.generator = self.args.creates.then_some(None);
        while !self.done() {
            if SIGNAL_EXIT.load(Ordering::Relaxed) {
                break;
            }
            // As SIPp's traffic loop: the call limit reached, it quits.
            if self.args.max_calls.is_some_and(|m| self.counters.created >= m) {
                self.control.quitting = true;
            }
            if SIGNAL_DUMP.swap(false, Ordering::Relaxed) {
                self.signal_dump();
            }
            let now = Instant::now();
            // The pass's time, before its wait: SIPp's clock_tick for its
            // tasks, which the -timeout alarm comes before.
            let tick = now;
            if self.args.timeout.is_some_and(|t| now.duration_since(self.start) >= t) {
                if self.args.timeout_error {
                    let e = format!("{} timed out after '{:.3}' seconds", self.args.scenario_name, call::tick_ms(now) as f64 / 1000.0);
                    self.control.fatal = Some(e);
                    break;
                }
                self.timed_out = true;
                self.forcing = true;
                self.abort_all();
                break;
            }
            self.timer_cycle(tick);
            self.generate_calls(now);
            let mut inputs = Vec::new();
            if let Some(s) = &self.control_sock {
                let mut b = [0u8; 2048];
                while let Ok(n) = s.recv(&mut b) {
                    inputs.extend(control::datagram(&b[..n]));
                }
            }
            if let Some(k) = self.keyboard.as_mut().filter(|_| now.duration_since(last_key) >= Duration::from_millis(20)) {
                last_key = now;
                inputs.extend(k.read());
            }
            // SIGUSR1 is a 'q'.
            inputs.extend((0..SIGNAL_QUIT.swap(0, Ordering::Relaxed)).map(|_| control::Input::Key(b'q')));
            if inputs.into_iter().any(|i| self.control_input(i)) {
                // SIPp's 'Q', or a second 'q': quit now, ending the calls it has.
                self.forcing = true;
                self.abort_all();
                break;
            }
            // ponytail: Net::poll waits a millisecond when idle, which also
            // paces call generation and timers; wait for the next deadline
            // instead if idle CPU matters.
            // The calls queued so far run on after this read.
            std::mem::swap(&mut self.due, &mut self.turns);
            self.reading = true;
            self.poll_net(&mut buf, &mut got);
            for r in got.drain(..) {
                self.on_packet(&r.msg, r.from);
                self.check_ramp();
            }
            self.reading = false;
            self.net_warnings();
            for (conn, why) in std::mem::take(&mut self.net.resets) {
                self.connection_failed(Some(conn), &why);
            }
            for closed in std::mem::take(&mut self.net.closed) {
                // -reconnect_close false: the calls stay on a closed
                // connection, but not on one we accepted: nothing
                // reconnects that.
                if !self.args.reconnect.close && !closed.accepted {
                    continue;
                }
                let ids = self.call_ids(|c| c.peer.conn == Some(closed.conn));
                let mut failed = 0;
                for id in ids {
                    let (mut env, call) = self.env_of(&id);
                    let outcome = call.connection_closed(&mut env);
                    failed += usize::from(matches!(outcome, Outcome::Failed));
                    self.finish(&id, outcome);
                }
                if failed > 0 {
                    let how = if closed.reset { "reset" } else { "closed" };
                    self.args.log.warning(&format!("The remote peer {how} the {} connection, failing {failed} call(s)", self.net.transport.name()));
                }
            }
            self.poll_twin();
            self.rtp_played();
            self.reap_verify();
            let now = Instant::now();
            let was_done = self.done();
            self.run_turns();
            self.run_timers(now);
            self.ran = 0;
            self.pass = self.pass.wrapping_add(1);
            // SIPp's loop reads its sockets after running its calls and
            // timers, before it sees the run is over: what a call that just
            // ended so got back (a 200 to its abort's BYE, a twin's end)
            // still comes in.
            let ran = std::mem::take(&mut self.ended_running);
            if (ran || !was_done) && self.done() && !self.control.stop_now && self.control.fatal.is_none() {
                self.poll_net(&mut buf, &mut got);
                for r in got.drain(..) {
                    self.on_packet(&r.msg, r.from);
                }
                self.poll_twin();
            }
            self.args.log.flush_deferred();
            self.check_oversized();
            if let Some(e) = log::take_deferred_fatal() {
                self.control.fatal.get_or_insert(e);
            }
            loops += 1;
            self.write_rtts(true);
            // SIPp's watchdog task, which only counts here.
            while let Some(t) = self.next_watchdog.filter(|t| *t < tick) {
                self.woken += 1;
                self.next_watchdog = Some(t + self.args.watchdog);
            }
            if tick.duration_since(last_report) >= Duration::from_secs(1) {
                last_report = tick;
                // The screen task's wakeup.
                self.woken += 1;
                self.loops = loops;
                loops = 0;
                media::counters::take_rates(self.stats.display_period().1);
                self.draw_screen();
                self.stats.new_display_period();
            }
            if now.duration_since(self.last_stat) >= self.args.stat_period {
                // stattask, which SIPp has for these files only.
                if self.args.stat_path.is_some() || self.args.counts_file.is_some() || self.args.codes_file.is_some() {
                    self.woken += 1;
                }
                self.dump_stats();
            }
        }
        self.loops = self.loops.max(loops);
        let fatal = self.control.fatal.clone().map(|e| {
            self.stats.fatal_error();
            self.args.log.error(&e)
        });
        // The -trace_err file not created: the exit of the warning's.
        let fatal = fatal.or(self.args.log.dead.then_some(()));
        if SIGNAL_EXIT.load(Ordering::Relaxed) || self.control.stop_now || fatal.is_some() {
            // sipp_exit() at once, from a signal, stop_now or ERROR(): the
            // screen file, the closing screens and a stats row, and the
            // open calls count for nothing. A signal's exit still takes
            // the RTP checks, as rtpstream_shutdown(), of the open calls
            // too.
            if fatal.is_none() && !self.control.stop_now {
                self.counters.rtp_errors |= mediapool::finish();
                self.rtp_check_warning();
            }
            self.closing_screens();
            self.dump_stats();
            self.write_rtts(false);
            self.args.log.print_errors();
            let c = &self.counters;
            return if fatal.is_some() {
                self.control.fatal_code.unwrap_or(EXIT_FATAL_ERROR)
            } else if self.control.stop_now {
                EXIT_TEST_RES_INTERNAL
            } else if c.rtp_errors > 0 || c.echo_errors {
                EXIT_RTPCHECK_FAILED
            } else if c.failed > 0 {
                EXIT_TEST_FAILED
            } else if self.timed_out && c.successful < 1 {
                EXIT_TEST_RES_INTERNAL
            } else {
                EXIT_TEST_OK
            };
        }
        // The traffic loop quits: abort_all_tasks() for the -oocsf, -rxsf
        // and -aa calls still open, the sockets closed, then its last
        // screen report (a new display period) and a stats row;
        // sipp_exit() then writes the screen file, prints the screens and
        // a row.
        self.abort_all();
        self.net.close_all();
        self.sockets_closed = true;
        // Every way out of it has quitting set, if only by the call limit.
        self.control.quitting = true;
        media::counters::take_rates(self.stats.display_period().1);
        self.stats.new_display_period();
        self.loops = 0;
        self.dump_stats();
        // rtpstream_shutdown(): the RTP checks of the calls, as their
        // threads end. sipp_exit(): nothing else tells why the exit code
        // is 253. Its last stats row, and the screen file, count the
        // warning.
        self.counters.rtp_errors |= mediapool::finish();
        self.rtp_check_warning();
        self.closing_screens();
        self.dump_stats();
        self.write_rtts(false);
        self.args.log.print_errors();
        let c = &self.counters;
        if c.rtp_errors > 0 || c.echo_errors {
            EXIT_RTPCHECK_FAILED
        } else if c.failed > 0 {
            EXIT_TEST_FAILED
        } else if self.timed_out && c.successful < 1 {
            EXIT_TEST_RES_INTERNAL
        } else {
            EXIT_TEST_OK
        }
    }
}

/// The pattern ids whose bit (id - 1) is set in `mask`: "pattern 3",
/// "patterns 1, 3".
fn rtp_check_failed(mask: u64) -> String {
    let ids: Vec<String> = (1..=64).filter(|id| mask & (1 << (id - 1)) != 0).map(|id: u64| id.to_string()).collect();
    format!("{} {}", if ids.len() > 1 { "patterns" } else { "pattern" }, ids.join(", "))
}

/// rate_calls_to_open(): the calls due `since` the rate changed, whole
/// milliseconds as SIPp's clock.
fn calls_by_rate(since: Duration, rate: f64, period: Duration) -> u64 {
    (since.as_millis() as f64 * rate / period.as_millis().max(1) as f64) as u64
}

/// SIPp's exit() of a statistics file it can't open: its text, and
/// nothing else but the terminal restored.
fn exit_now(keyboard: &mut Option<control::Keyboard>, text: &str) -> ! {
    *keyboard = None;
    eprintln!("{text}");
    std::process::exit(EXIT_FATAL_ERROR.into());
}

/// SIPp's ERROR() before the run: the time and the message, also in the
/// -trace_err log, named after "sipp" since no scenario has named it yet.
fn fatal_before_run(argv: &[String], rfc3339: bool, msg: &str) {
    let mut line = format!("{}: {msg}", stat::format_time(SystemTime::now(), rfc3339));
    let (log, _) = error_log(argv);
    if log.trace {
        let path = log.file.unwrap_or_else(|| format!("sipp_{}_errors.log", std::process::id()));
        let overwrite = log.overwrite.unwrap_or(true);
        let mut errors = log::Sink::new(path, "errors", overwrite);
        match errors.rotate(&log::Limits::default()) {
            Ok(()) => {
                if let Some(f) = errors.file.as_mut() {
                    let _ = raw::write(f, &format!("The following events occurred:\n{line}\n"));
                }
            }
            // The reason joins the error.
            Err(e) => line += &format!("Unable to create '{}': {}.\n", errors.path, net::os_error(&e)),
        }
    }
    // ERROR() prints it without a -trace_err file, print_errors() with.
    raw::eprintln(&line);
}

/// What SIPp's open_connections(), setup_media_sockets() and
/// setup_ctrl_socket() make once the scenario is loaded.
struct Setup {
    net: Net,
    control_sock: Option<UdpSocket>,
    echo: Option<media::Echo>,
    twin: Option<Twin>,
    peers: Option<Peers>,
    /// Whether it got as far as creating the main socket.
    socket: bool,
}

/// ERROR_NO()'s text for `e`, and sipp_exit()'s code for it.
fn error_no(text: &str, e: &std::io::Error) -> (String, u8) {
    let code = if e.raw_os_error() == Some(sys::EADDRINUSE) { EXIT_BIND_ERROR } else { EXIT_FATAL_ERROR };
    (format!("{text}, errno = {} ({})", e.raw_os_error().unwrap_or(0), net::os_error(e)), code)
}

/// Whether the local IP has no address in the remote's family, as
/// getaddrinfo() of it with that family finds: an IPv4-mapped IPv6 one
/// is also an IPv4 one.
/// -i as SIPp's getaddrinfo() resolves it, in the family of the remote
/// host if there is one; else an address to go on with, and SIPp's
/// error (its EAI_ADDRFAMILY in another family).
fn local_address(text: &str, remote: Option<SocketAddr>) -> Result<IpAddr, (IpAddr, String)> {
    let all = dns::addresses(text).map_err(|ret| (IpAddr::from([0, 0, 0, 0]), format!("Can't get local IP address in getaddrinfo, local_ip='{text}', ret={ret}")))?;
    let Some(remote) = remote else { return Ok(all[0]) };
    all.iter().copied().find(|&ip| !family_mismatch(ip, remote.ip())).ok_or_else(|| {
        let family = if remote.is_ipv6() { sys::AF_INET6 } else { sys::AF_INET };
        (all[0], format!("Network family mismatch for local ({text}) and remote ({}, {family}) IP", remote.ip()))
    })
}

fn family_mismatch(local: IpAddr, remote: IpAddr) -> bool {
    match (local, remote) {
        (IpAddr::V6(v6), IpAddr::V4(_)) => v6.to_ipv4_mapped().is_none(),
        (IpAddr::V4(_), IpAddr::V6(_)) => true,
        _ => false,
    }
}

/// connect_local_twin_socket(): the -3pcc or -slave_cfg listener, on the
/// port of `addr` and any address of its family, as SIPp binds it.
fn twin_listener(addr: SocketAddr) -> Result<TcpListener, (String, u8)> {
    let any: IpAddr = if addr.is_ipv6() { std::net::Ipv6Addr::UNSPECIFIED.into() } else { std::net::Ipv4Addr::UNSPECIFIED.into() };
    let l = TcpListener::bind(SocketAddr::new(any, addr.port())).map_err(|e| error_no("Unable to bind twin sipp socket ", &e))?;
    let _ = l.set_nonblocking(true);
    Ok(l)
}

impl Setup {
    /// Each step in SIPp's order; a failure is an ERROR() with its words.
    fn run(&mut self, args: &mut Args, server: bool, first: Option<net::Tls>) -> Result<(), (String, u8)> {
        if let Some(e) = args.local_error.take() {
            // The screens' port is SIPp's local_port, 0 until bound.
            args.cfg.local.set_port(0);
            return Err((e, EXIT_FATAL_ERROR));
        }
        self.socket = true;
        // Without -p, SIPp tries 5060 to 5119, then leaves the port to the
        // system, which a failure is fatal for.
        let ports = match args.explicit_port {
            true => vec![args.cfg.local.port()],
            false => (5060..5120).chain([0]).collect(),
        };
        let mut bound = Err(std::io::Error::from(std::io::ErrorKind::AddrInUse));
        for port in ports {
            bound = Net::bind(args.transport, SocketAddr::new(args.cfg.local.ip(), port), server && !args.connects_at_start(), None, args.sctp);
            if bound.is_ok() {
                break;
            }
        }
        let mut n = bound.map_err(|e| {
            args.cfg.local.set_port(0);
            error_no("Unable to bind main socket", &e)
        })?;
        n.tls = first;
        args.cfg.local = n.local_addr().unwrap_or(args.cfg.local);
        if let Some(dev) = &args.bind_device {
            n.bind_device(dev).map_err(|e| error_no("setsockopt(SO_BINDTODEVICE) failed", &e))?;
        }
        n.max_sockets = args.max_socket;
        n.keep = !args.reconnect.close;
        n.recv_loops = args.recv_loops.max(1);
        n.ws_path = args.ws_path.clone();
        n.ws_timeout = args.ws_timeout;
        if let (false, Some(remote)) = (args.cfg.remote_host.is_empty(), args.remote) {
            let h = &args.cfg.remote_host;
            n.ws_host = Some(if h.contains(':') { format!("[{h}]:{}", remote.port()) } else { format!("{h}:{}", remote.port()) });
        }
        // A -t t1/l1/w1 client's connection goes out from -p, and an s1
        // one's from the main socket's port, -p or not.
        if args.transport.single() && (args.explicit_port || args.transport.sctp()) {
            n.bind_port = args.cfg.local.port();
        }
        let per_ip = server && args.transport == Transport::UdpPerIp;
        let listened = if per_ip { n.listen_on(&args.per_ip) } else { Ok(()) };
        self.net = n;
        listened.map_err(|e| error_no("Unable to bind server socket", &e))?;
        if let Some(e) = args.twin_mode_error {
            return Err((e.to_string(), EXIT_FATAL_ERROR));
        }
        // 3PCC: controller B (starting with <recvCmd>) listens, controller A connects.
        // connect_to_peer() and connect_local_twin_socket(), in SIPp's words.
        let twin_addr = match &args.twin {
            None => None,
            Some(v) => {
                let (what, unknown) = if args.twin_listens { ("listener", "twin") } else { ("peer", "peer") };
                println!("Resolving {what} address : {}...", host_part(v));
                match v.to_socket_addrs().ok().and_then(|mut a| a.next()) {
                    Some(a) => Some(a),
                    None => return Err((format!("Unknown {unknown} host '{}'.\nUse 'sipp -h' for details", host_part(v)), EXIT_FATAL_ERROR)),
                }
            }
        };
        match twin_addr {
            None => {}
            Some(addr) if args.twin_listens => {
                let l = twin_listener(addr)?;
                self.twin = Some(Twin { listener: Some(l), stream: None, to: None, buf: Vec::new(), out: TwinOut::default(), closed: false, error: None });
            }
            Some(addr) => {
                let s = Twin::connect(addr).map_err(|e| error_no("Unable to connect a twin sipp socket \nUse 'sipp -h' for details", &e))?;
                self.twin = Some(Twin { listener: None, stream: Some(s), to: Some(addr), buf: Vec::new(), out: TwinOut { connecting: true, ..TwinOut::default() }, closed: false, error: None });
            }
        }
        // 3PCC extended mode: listen on our -slave_cfg address; a master
        // connects to its peers now, a slave when first reached.
        if let Some((name, master, hosts)) = &args.extended {
            let host = hosts.get(name).ok_or_else(|| (format!("get_peer_addr: Peer {name} not found"), EXIT_FATAL_ERROR))?;
            // connect_local_twin_socket().
            println!("Resolving listener address : {}...", host_part(host));
            let own = resolve_logged(host, &mut args.log).ok_or_else(|| (format!("Unknown twin host '{}'.\nUse 'sipp -h' for details", host_part(host)), EXIT_FATAL_ERROR))?;
            let addrs = HashMap::from([(name.clone(), own)]);
            let listener = twin_listener(own)?;
            let mut dests: Vec<String> = Vec::new();
            for step in &args.scenario.steps {
                if let Op::SendCmd { dest: Some(d), .. } = &step.op {
                    if !dests.contains(d) {
                        dests.push(d.clone());
                    }
                }
            }
            let mut p = Peers { listener, incoming: Vec::new(), outgoing: HashMap::new(), out: HashMap::new(), hosts: hosts.clone(), addrs, dests, connected: false, closed: false, fatal: None, error: None };
            if *master {
                p.connect(&mut args.log);
                if let Some(e) = p.fatal.take() {
                    return Err((e, EXIT_FATAL_ERROR));
                }
            }
            self.peers = Some(p);
        }
        if args.rtp_echo {
            let (e, port) = media::Echo::bind(args.cfg.media_ip, args.cfg.media_port, args.rtp_ports.1).map_err(|(text, e)| error_no(&text, &e))?;
            args.cfg.media_port = port;
            e.start().map_err(|e| error_no("Unable to create RTP echo thread", &e))?;
            self.echo = Some(e);
        }
        // setup_ctrl_socket(): gai_getsockaddr()'s warning, then the error.
        let control_ip = match args.control_ip.as_deref().map(|host| (host, dns::addresses(host))) {
            None => None,
            Some((_, Ok(a))) => Some(a[0]),
            Some((host, Err(_))) => {
                if let Err(e) = (host, 0).to_socket_addrs() {
                    let e = e.to_string();
                    args.log.warning(&format!("getaddrinfo failed: {}", e.strip_prefix("failed to lookup address information: ").unwrap_or(&e)));
                }
                return Err((format!("Unknown control address '{host}'.\nUse 'sipp -h' for details"), EXIT_FATAL_ERROR));
            }
        };
        self.control_sock = match control::socket(control_ip, args.control_port) {
            Ok(s) => Some(s),
            Err((Some(port), e)) => return Err(error_no(&format!("Unable to bind remote control socket to UDP port {port}"), &e)),
            Err((None, e)) => {
                args.log.warning(&format!("Unable to bind remote control socket (tried UDP ports 8888-8947): {}", net::os_error(&e)));
                None
            }
        };
        Ok(())
    }
}

fn main() -> ExitCode {
    // glibc gives each thread that allocates its own arena, with 64 MB of
    // address space, up to 8 per CPU: hundreds for the media threads.
    // They allocate little, and glibc's per-thread cache serves most of it
    // without an arena's lock: two arenas do, unless MALLOC_ARENA_MAX says
    // otherwise.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    if std::env::var_os("MALLOC_ARENA_MAX").is_none() {
        // SAFETY: before any thread starts.
        unsafe { libc::mallopt(libc::M_ARENA_MAX, 2) };
    }
    sys::init();
    // Windows has neither: the control socket does what they do.
    #[cfg(unix)]
    {
        set_handler(libc::SIGUSR1, on_sigusr1);
        set_handler(libc::SIGUSR2, on_sigusr2);
    }
    let mut argv: Vec<String> = std::env::args_os().skip(1).map(raw::from_os).collect();
    // A bare launch at a terminal asks for its command line.
    if let (Some(program), true) = (std::env::args().next(), argv.is_empty() && wizard::wanted()) {
        let Some(args) = wizard::run(&program) else { return ExitCode::from(EXIT_OTHER) };
        argv = args[1..].to_vec();
    }
    let args = match parse_args(&argv) {
        Ok(a) => a,
        Err(ArgsError::Exit(code, msg)) => {
            if code == EXIT_OTHER {
                println!("{msg}");
            } else if code == EXIT_FATAL_ERROR {
                fatal_before_run(&argv, argv.iter().any(|a| a == "-rfc3339" || a == "--rfc3339"), &msg);
            } else {
                raw::eprintln(&msg);
            }
            return ExitCode::from(code);
        }
        Err(ArgsError::Quit(code)) => return ExitCode::from(code),
        Err(ArgsError::Logged(msg, mut log)) => {
            log.error(&msg);
            log.print_errors();
            return ExitCode::from(EXIT_FATAL_ERROR);
        }
    };
    let mut args = args;
    // A warning while the options are checked could not go to the
    // -trace_err file: SIPp exits before it has screens.
    if args.log.dead {
        args.log.print_errors();
        return ExitCode::from(EXIT_FATAL_ERROR);
    }
    media::srtp_debug::CLIENT.store(args.cfg.client, Ordering::Relaxed);
    #[cfg(windows)]
    if args.background && std::env::var_os(BACKGROUND_ENV).is_none() {
        return background(&argv);
    }
    #[cfg(unix)]
    if args.background {
        // SAFETY: no threads have been started yet.
        match unsafe { libc::fork() } {
            -1 => {
                eprintln!("Forking error");
                return ExitCode::from(EXIT_FATAL_ERROR);
            }
            0 => {
                // SAFETY: plain descriptor calls on our own stdio.
                unsafe {
                    let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
                    for fd in 0..3 {
                        libc::dup2(null, fd);
                    }
                    libc::close(null);
                }
            }
            pid => {
                println!("Background mode - PID=[{pid}]");
                return ExitCode::from(EXIT_OTHER);
            }
        }
    }
    std::thread::sleep(args.sleep);
    // SIPp's clock starts here, with its watchdog task (or the call rate
    // it sets), before it opens its sockets; a server without a watchdog
    // reads it first in its traffic loop (run()).
    if !args.watchdog.is_zero() || args.creates {
        call::epoch();
    }
    // SIPp raises the soft limit on open files to the hard limit, then
    // checks it against the call sockets, and the two media sockets of
    // each open call, after set_rate() has set the open calls.
    if !args.skip_rlimit {
        if let Some(open) = sys::raise_nofile_limit() {
            let sockets = if args.transport.per_call() { args.max_socket } else { 1 } as u64;
            if sockets > open {
                args.log.error(&format!("Maximum number of open sockets ({sockets}) should be less than the maximum number of open files ({open}). Tune this with the `ulimit` command or the -max_socket option"));
                args.log.print_errors();
                return ExitCode::from(EXIT_FATAL_ERROR);
            }
            if 2 * args.limit as u64 + sockets > open {
                args.log.warning(&format!("Maximum number of open sockets ({sockets}) plus two per open call ({}) should be less than the maximum number of open files ({open}) to allow for media support. Tune this with the `ulimit` command, the -l option or the -max_socket option", args.limit));
            }
        }
    }
    // open_connections().
    if args.given_remote.is_some() {
        eprintln!("Resolving remote host '{}'... {}Done.", args.cfg.remote_host, args.srv_note);
    } else if args.remote_unknown {
        eprint!("Resolving remote host '{}'... ", args.cfg.remote_host);
    }
    let server = !args.cfg.client;
    let tls = args.transport.tls();
    // TLS_init_context(): a client goes without a certificate when no
    // option names one and neither default file is there.
    if let (true, false, false, Some((cert, key))) = (tls, server, args.tls_named, args.tls_files.clone()) {
        if !std::path::Path::new(&cert).exists() && !std::path::Path::new(&key).exists() {
            args.log.warning(&format!("TLS: neither {cert} nor {key} found: connecting without a certificate; incoming TLS connections will fail"));
            args.tls_files = None;
        }
    }
    let first = match args.transport {
        t if t.tls() => net::Tls::new(args.tls_files.as_ref().map(|(c, k)| (c.as_str(), k.as_str())), server, &args.tls_options).map(Some),
        _ => Ok(None),
    };
    let (first, tls_failure) = match first {
        _ if args.setup_error.is_some() => (None, args.setup_error.take()),
        Ok(t) => (t, None),
        Err(e) => (None, Some(e)),
    };
    // SIPp's sighandle_set(), before open_connections(): a SIGINT or
    // SIGTERM from then on ends the run as the traffic loop starts.
    set_handler(libc::SIGINT, on_sigexit);
    set_handler(libc::SIGTERM, on_sigexit);
    #[cfg(unix)]
    set_handler(libc::SIGXFSZ, on_sigxfsz);
    let mut setup = Setup { net: Net::unbound(args.transport, args.cfg.local, args.sctp), control_sock: None, echo: None, twin: None, peers: None, socket: false };
    let failure = if tls_failure.is_some() { None } else { setup.run(&mut args, server, first).err() };
    let Setup { net, control_sock, echo, twin, peers, socket } = setup;
    // The keys, unless -nostdin or -bg.
    let keyboard = if args.nostdin || args.background || failure.is_some() || tls_failure.is_some() { None } else { control::Keyboard::open() };
    let live_screen = !args.background && std::io::stdout().is_terminal();
    let rate_scale = args.rate_scale;
    let rtp_ports = media::RtpPorts::new(args.rtp_ports.0, args.rtp_ports.1);
    mediapool::set_tolerance(args.cfg.audio_tolerance, args.cfg.video_tolerance);
    if let Some(dtmf_types) = args.counts_received {
        mediapool::count_received(dtmf_types);
    }
    // Clock and pid, as randomseed(): SIPps started at once differ.
    let seed = seed_now();
    // One table of <Global> (and of <User>) variables for all the run's scenarios.
    let (mut globals, mut users_vars) = (args.scenario.global_vars.clone(), args.scenario.user_vars.clone());
    for side in args.ooc.iter().chain(args.rx.iter()) {
        globals.extend(side.global_vars.iter().cloned());
        users_vars.extend(side.user_vars.iter().cloned());
    }
    let scopes = vars::Scopes::new(globals, users_vars);
    for (name, value) in &args.sets {
        scopes.global.borrow_mut().insert(name.clone(), vars::Value::Str(value.clone()));
    }
    let free_users = (1..=args.cfg.users.unwrap_or(0)).collect();
    let rate0 = args.rate;
    let users_ramp = args.cfg.users.is_some() && args.rate_set;
    let side_stats = [&args.ooc, &args.rx, &args.aa].map(|s| s.as_ref().map(|s| Stats::new(&s.layout)));
    let mut stats = Stats::new(&args.scenario.layout);
    stats.rfc3339 = args.rfc3339;
    stats.delimiter = args.stat_delimiter.clone();
    // The scenarios' <DefaultMessage>s, SIPp's for the whole run.
    let mut overrides = std::mem::take(&mut args.scenario.default_messages);
    for side in args.ooc.iter_mut().chain(args.rx.iter_mut()) {
        overrides.append(&mut side.default_messages);
    }
    let defaults = Defaults::with(overrides, args.twin.is_some());
    let mut engine = Engine {
        args,
        defaults,
        net,
        pid: std::process::id(),
        calls: Calls::default(),
        timers: BinaryHeap::new(),
        dead: BTreeMap::new(),
        dead_expiry: Fifo::new(),
        displaced: 0,
        aliases: HashMap::new(),
        new_dialog_calls: BTreeMap::new(),
        new_dialog_seq: 0,
        side_calls: 0,
        scopes,
        free_users,
        user_vars: HashMap::new(),
        rate: rate0,
        rate_since: (call::tick_ms(Instant::now()), 0),
        last_ramp: Instant::now(),
        ramping: users_ramp,
        loops: 0,
        side_stats,
        rtt_files: Default::default(),
        keyboard,
        live_screen,
        screen: 1,
        hide: true,
        rate_scale,
        traffic_paused: false,
        next_number: 1,
        next_remote: 0,
        ended_running: false,
        reading: false,
        counters: Counters::default(),
        stats,
        control: Control::default(),
        rng: Rng::new(seed),
        rtp_ports,
        echo,
        links: TwinLinks { twin, peers, failed: None, gone: false },
        start: Instant::now(),
        timed_out: false,
        forcing: false,
        stat_first: true,
        woken: 0,
        next_watchdog: None,
        generator: None,
        paused: 0,
        running: 0,
        pass: 0,
        ran: 0,
        last_cycle: 0,
        cycle: None,
        turns: Vec::new(),
        due: Vec::new(),
        last_stat: Instant::now(),
        control_sock,
        // None open when it failed before the main socket.
        sockets_closed: failure.is_some() && !socket,
        verify: Vec::new(),
        verify_started: Vec::new(),
        inits: Vec::new(),
    };
    if let Some((msg, code)) = failure {
        engine.open_counts();
        return ExitCode::from(engine.startup_failed(&msg, code));
    }
    // SIPp's TLS setup (or the check before it) fails before its screens
    // exist: only the error and a statistics row.
    if let Some(msg) = tls_failure {
        engine.open_counts();
        engine.stats.fatal_error();
        engine.args.log.error(&msg);
        engine.dump_stats();
        engine.args.log.print_errors();
        return ExitCode::from(EXIT_FATAL_ERROR);
    }
    let code = engine.run();
    engine.close_srtpctx();
    // What the playback threads logged, as SIPp's exit() writes it out.
    media::rtp_debug::close();
    ExitCode::from(code)
}

#[cfg(test)]
mod rate_tests {
    use super::*;

    #[test]
    fn fifo_keeps_order_across_blocks() {
        let mut q = Fifo::new();
        let n = Fifo::<usize>::BLOCK * 2 + 3;
        for i in 0..n {
            q.push(i);
        }
        assert_eq!(q.front(), Some(&0));
        assert_eq!(std::iter::from_fn(|| q.pop()).collect::<Vec<_>>(), (0..n).collect::<Vec<_>>());
        assert!(q.front().is_none() && q.blocks.is_empty());
        q.push(7);
        assert_eq!(q.pop(), Some(7));
    }

    #[test]
    fn first_call_after_one_interval() {
        let ms = Duration::from_millis;
        // -r 1 -rp 3000: none for the first 3 s.
        assert_eq!(calls_by_rate(ms(0), 1.0, ms(3000)), 0);
        assert_eq!(calls_by_rate(ms(2999), 1.0, ms(3000)), 0);
        assert_eq!(calls_by_rate(ms(3000), 1.0, ms(3000)), 1);
        // -r 10: one per 100 ms.
        assert_eq!(calls_by_rate(ms(99), 10.0, ms(1000)), 0);
        assert_eq!(calls_by_rate(ms(100), 10.0, ms(1000)), 1);
        assert_eq!(calls_by_rate(ms(1050), 10.0, ms(1000)), 10);
        assert_eq!(calls_by_rate(ms(5000), 0.0, ms(1000)), 0);
    }

    #[test]
    fn rtp_check_names_the_patterns() {
        assert_eq!(rtp_check_failed(1 << 2), "pattern 3");
        assert_eq!(rtp_check_failed(0b101), "patterns 1, 3");
    }

    #[test]
    fn timeout_to_the_millisecond() {
        let timeout = |t: &str| {
            let argv: Vec<String> = ["-sn", "uac", "-timeout", t, "127.0.0.1"].map(String::from).into();
            match parse_args(&argv) {
                Ok(args) => args.timeout,
                Err(ArgsError::Exit(code, e)) => panic!("{code}: {e}"),
                Err(ArgsError::Logged(e, _)) => panic!("{e}"),
                Err(ArgsError::Quit(code)) => panic!("{code}"),
            }
        };
        assert_eq!(timeout("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(timeout("1900ms"), Some(Duration::from_millis(1900)));
        assert_eq!(timeout("2"), Some(Duration::from_secs(2)));
        assert_eq!(timeout("0"), None);
    }

    #[test]
    fn cid_str_keeps_an_unknown_conversion() {
        let ids = CallIds { format: "a%xb%%c%u-%".into(), mode: CidMode::Format };
        assert_eq!(ids.make(77, 1, "127.0.0.1", &mut call::Rng::new(1)), "a%xb%c77-%");
    }
}

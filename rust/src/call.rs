//! One call walking through the scenario.

use crate::log::Log;
use std::borrow::Cow;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use crate::media::{self, RtpPorts, Stream};
use crate::mediapool;
use crate::pcap::{self, PcapMedia, Player};
use crate::scenario::StreamSource;
use crate::srtp::{self, MediaCrypto};
use crate::template::CryptoWhat;
use crate::stat::{Fail, Stats};
use crate::scenario::{Action, Arith, Check, Compare, Expect, Num, Op, Operand, PauseLen, Scenario, Source, Step, Stop, StrOp};
use crate::sip::{self, Kind};
use crate::infile::Injection;
use crate::template::{AuthCtx, Ctx, Kw, Template};
use crate::vars::Vars;
use std::collections::{BTreeMap, HashMap};
use crate::net::{Net, Peer, NO_REMOTE};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

pub struct Config {
    /// -sendbuffer_warn: a message of our own that fails to send is fatal.
    pub sendbuffer_warn: bool,
    pub local: SocketAddr,
    pub local_ip: String,
    pub media_ip: IpAddr,
    /// media_ip as [media_ip] shows it, made once.
    pub media_ip_text: String,
    pub service: String,
    pub media_port: u16,
    pub default_pause: Duration,
    pub recv_timeout: Option<Duration>,
    /// SIPp's default behaviours (-nd turns them off, -default_behaviors
    /// picks them): the BEHAVIOR_* bits.
    pub default_behaviors: u8,
    /// -au (default: -s), -ap and -auth_uri, for [authentication].
    pub auth_user: String,
    pub auth_pass: String,
    pub auth_uri: Option<String>,
    /// -aa: answer INFO, NOTIFY, OPTIONS and UPDATE nobody expected with a 200.
    pub auto_answer: bool,
    /// UDP retransmissions, ours and the peer's (-nr turns them off).
    pub retrans: bool,
    /// -users: that many calls at all times, each with its user.
    pub users: Option<u32>,
    /// -base_cseq less one, as SIPp keeps it.
    pub base_cseq: u32,
    /// Retransmissions before a UDP transaction times out.
    pub max_invite_retrans: u32,
    pub max_non_invite_retrans: u32,
    /// -T2: where non-INVITE retransmission intervals stop doubling.
    pub t2: Duration,
    /// -pause_msg_ign: drop what arrives while the call is in a <pause>.
    pub pause_msg_ign: bool,
    /// -lost: the percentage of messages to drop, sent or received.
    pub lost: f64,
    /// The remote host as given on the command line, for [remote_host].
    pub remote_host: String,
    pub rfc3339: bool,
    pub client: bool,
    /// The first call's audio SSRC: 0xCA110000, or random (-random_base_ssrc).
    pub ssrc_base: u32,
    /// -audiotolerance, -videotolerance: the share of failed echoes that
    /// fails a pattern check.
    pub audio_tolerance: f64,
    pub video_tolerance: f64,
    /// -rtcheck loose: a retransmission is the same To, From, Call-ID and
    /// CSeq (and a response's status line and body), not the same text.
    pub rtcheck_loose: bool,
    /// -sf's directory, where rtp_stream files are looked for first.
    pub scenario_dir: std::path::PathBuf,
    /// SIPp's hasMedia: a scenario plays or echoes media, so the peer's
    /// SDP is read for it.
    pub has_media: bool,
    /// -rsa: every message goes to its address, responses included.
    pub rsa: bool,
    /// -callid_slash_ign: '///' in a Call-ID is part of it.
    pub callid_slash_ign: bool,
}

/// Send a BYE or CANCEL for an aborted call (and a 200 to an unexpected
/// BYE or CANCEL).
pub const BEHAVIOR_BYE: u8 = 1;
/// Abort a call on an unexpected message, rather than carry on.
pub const BEHAVIOR_ABORTUNEXP: u8 = 2;
/// Answer an unexpected PING with a 200 and end the call.
pub const BEHAVIOR_PINGREPLY: u8 = 4;
/// Abort a call whose ACK has another CSeq than the INVITE's.
pub const BEHAVIOR_BADCSEQ: u8 = 8;
pub const BEHAVIOR_ALL: u8 = 15;

/// -default_behaviors: "all", "none", or names, "-" before one clearing it.
pub fn parse_behaviors(spec: &str) -> Result<u8, String> {
    let mut bits = 0;
    for token in spec.split(',').filter(|t| !t.is_empty()) {
        if token == "none" {
            bits = 0;
            continue;
        }
        let (off, name) = match token.strip_prefix('-') {
            Some(n) => (true, n),
            None => (false, token.strip_prefix('+').unwrap_or(token)),
        };
        let mask = match name {
            "all" => BEHAVIOR_ALL,
            "bye" => BEHAVIOR_BYE,
            "abortunexp" => BEHAVIOR_ABORTUNEXP,
            "pingreply" => BEHAVIOR_PINGREPLY,
            "cseq" => BEHAVIOR_BADCSEQ,
            _ => return Err(format!("Unknown default behavior: '{token}'")),
        };
        if off { bits &= !mask } else { bits |= mask }
    }
    Ok(bits)
}

/// checkInternalCmd(): the word after "internal-cmd:", if one ends there.
fn internal_cmd(cmd: &str) -> Option<&str> {
    let rest = cmd[cmd.find("internal-cmd:")? + 13..].trim_start_matches([' ', '\t']);
    let end = rest.find([' ', '\t', '\r', '\n'])?;
    Some(&rest[..end]).filter(|w| !w.is_empty())
}

/// SIPp's built-in messages for aborting a call.
pub struct Defaults {
    ack: Template,
    bye: Template,
    cancel: Template,
    ok: Template,
    /// -3pcc: the command that aborts the twin's call too.
    abort_3pcc: Option<Template>,
}

impl Defaults {
    /// The ids <DefaultMessage> may replace (SIPp's ack2 is never sent).
    pub const NAMES: [&'static str; 6] = ["3pcc_abort", "ack", "ack2", "bye", "cancel", "200"];

    /// With the scenarios' <DefaultMessage>s, a later one winning; `twin`
    /// in -3pcc mode.
    pub fn with(overrides: Vec<(String, Template)>, twin: bool) -> Defaults {
        let mut d = Defaults::builtin(twin);
        for (id, t) in overrides {
            match id.as_str() {
                "ack" => d.ack = t,
                "bye" => d.bye = t,
                "cancel" => d.cancel = t,
                "200" => d.ok = t,
                "3pcc_abort" if twin => d.abort_3pcc = Some(t),
                _ => {}
            }
        }
        d
    }

    fn builtin(twin: bool) -> Defaults {
        let t = |s: &str| Template::parse(s, &HashMap::new()).expect("built-in message");
        let contact = "Contact: <sip:sipp@[local_ip]:[local_port];transport=[transport]>\n";
        Defaults {
            abort_3pcc: twin.then(|| t("call-id: [call_id]\ninternal-cmd: abort_call\n\n")),
            ack: t(&format!("ACK [last_Request_URI] SIP/2.0\n[last_Via]\n[last_From]\n[last_To]\nCall-ID: [call_id]\nCSeq: [last_cseq_number] ACK\n{contact}Max-Forwards: 70\nSubject: Performance Test\nContent-Length: 0\n\n")),
            bye: t(&format!("BYE [next_url] SIP/2.0\nVia: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\n[routes]\n[last_From]\n[last_To]\nCall-ID: [call_id]\nCSeq: [last_cseq_number+1] BYE\nMax-Forwards: 70\n{contact}Content-Length: 0\n\n")),
            cancel: t(&format!("CANCEL [last_Request_URI] SIP/2.0\n[last_Via]\n[last_From]\n[last_To]\nCall-ID: [call_id]\nCSeq: [last_cseq_number] CANCEL\nMax-Forwards: 70\n{contact}Content-Length: 0\n\n")),
            ok: t("SIP/2.0 200 OK\n[last_Via:]\n[last_From:]\n[last_To:]\n[last_Call-ID:]\n[last_CSeq:]\nContact: <sip:[local_ip]:[local_port];transport=[transport]>\nContent-Length: 0\n\n"),
        }
    }
}

/// Requests from actions to the engine.
#[derive(Default)]
pub struct Control {
    pub stop_now: bool,
    pub quitting: bool,
    /// SIPp's run-time ERROR(): the run ends with 255, or fatal_code.
    pub fatal: Option<String>,
    /// ERROR_NO()'s code for its errno, EXIT_BIND_ERROR for EADDRINUSE.
    pub fatal_code: Option<u8>,
    /// Calls woken without a timer here: a <pause> of 0 SIPp still pauses
    /// until its next timer cycle.
    pub woken: u64,
}

/// 3PCC: the connections to the twin SIPp or the extended mode peers,
/// which a command is written to at once, as SIPp's sendCmdMessage()
/// and sendCmdBuffer() do.
pub trait Commands {
    /// The command to `dest` (None: the twin), traced as SIPp's write()
    /// traces it; an error if it could not go. `abort`: the 3pcc_abort
    /// of a call aborted, which only a twin connection gets.
    fn send_cmd(&mut self, dest: Option<&str>, cmd: &str, abort: bool, log: &mut Log) -> std::io::Result<()>;
}

/// What the unit tests keep of the commands.
impl Commands for Vec<(Option<String>, String)> {
    fn send_cmd(&mut self, dest: Option<&str>, cmd: &str, _abort: bool, _log: &mut Log) -> std::io::Result<()> {
        self.push((dest.map(String::from), cmd.to_string()));
        Ok(())
    }
}

/// What a call needs from the engine to make progress.
pub struct Env<'a> {
    pub scenario: &'a Scenario,
    pub defaults: &'a Defaults,
    pub cfg: &'a Config,
    pub net: &'a mut Net,
    pub pid: u32,
    pub stats: &'a mut Stats,
    pub log: &'a mut Log,
    pub control: &'a mut Control,
    pub rng: &'a mut Rng,
    pub rtp_ports: &'a mut RtpPorts,
    /// 3PCC: where the commands go.
    pub twin: &'a mut dyn Commands,
    pub inject: &'a mut Injection,
    /// The <exec verify> commands the call started, for the engine to
    /// wait for.
    pub verify: &'a mut Vec<(std::process::Child, String)>,
}

impl Env<'_> {
    /// `keep`: a scenario message, which a connection that failed keeps
    /// for its reconnection (SIPp's WS_KEEP).
    fn send(&mut self, msg: &str, to: &Peer, keep: bool) -> Result<(), String> {
        let r = self.net.send(msg, to, keep);
        for t in std::mem::take(&mut self.net.traces) {
            self.log.trace_msg(&t);
        }
        // Those it buffered first, as SIPp's flush() before the write.
        for m in std::mem::take(&mut self.net.written) {
            self.log.sent(self.net.transport.name(), &m);
        }
        match r {
            Ok(true) => self.log.sent(self.net.transport.name(), msg),
            Ok(false) => {}
            Err(_) if std::mem::take(&mut self.net.held_back) => {}
            Err(_) => self.log.send_error(self.net.transport.name(), msg),
        }
        // keep(): it goes on the reconnection, as sent; a WebSocket's
        // frame is traced now, any other message once it is written.
        match self.net.kept.take() {
            Some(traced) => {
                if traced {
                    self.log.sent(self.net.transport.name(), msg);
                }
                Ok(())
            }
            None => r.map(|_| ()),
        }
    }

    /// sendBuffer()'s report of a message of SIPp's own that failed.
    fn own_send(&mut self, r: Result<(), String>) {
        if let Err(e) = r {
            let line = format!("Error sending raw message, {e}");
            if self.cfg.sendbuffer_warn {
                self.control.fatal = Some(line);
            } else {
                self.log.warning(&line);
            }
        }
    }
}

/// xorshift64*: `chance=` needs coin flips, not cryptography.
pub struct Rng(u64);

impl crate::dist::Unit for Rng {
    fn unit(&mut self) -> f64 {
        Rng::unit(self)
    }
}

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed | 1)
    }
    pub fn next_u32(&mut self) -> u32 {
        self.u32()
    }
    fn u32(&mut self) -> u32 {
        (self.unit() * u32::MAX as f64) as u32
    }
    fn unit(&mut self) -> f64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        (self.0.wrapping_mul(0x2545F4914F6CDD1D) >> 11) as f64 / (1u64 << 53) as f64
    }
}

struct Retrans {
    next: Instant,
    interval: Duration,
    count: u32,
}

#[derive(Debug, PartialEq)]
pub enum Outcome {
    Running,
    Success,
    Failed,
    /// <exec int_cmd="stop_now">: the whole run ends.
    StopNow,
    /// Ended without counting as a success or a failure (a PING answered).
    Discarded,
}

/// What running a message's actions asks for.
enum ActionResult {
    Ok,
    /// A check_it failed: the call carries on but ends as failed.
    Failed(Fail),
    StopCall,
    /// rtp_echo stop of an echo that failed to receive: the call ends
    /// as failed, at once in a <nop>.
    RtpEchoError,
}

/// The transactions a call's scenario names (start_txn=, response_txn=,
/// ack_txn=), by name.
#[derive(Default)]
struct Txns {
    /// The top Via branch of the request that started each.
    branches: HashMap<String, String>,
    /// Each transaction's ACK step once sent, and the hash of the final
    /// response it got: SIPp's ackIndex and txnResp.
    ack: HashMap<String, usize>,
    resp: HashMap<String, u64>,
    server: HashMap<String, ServerTxn>,
    /// The dialog each transaction started in, with dialog="N" messages.
    dialog: HashMap<String, usize>,
}

/// A transaction a received request started (start_txn=): the request,
/// its step, and the last response sent in it with its step.
struct ServerTxn {
    request: Arc<str>,
    step: usize,
    response: Option<(Arc<str>, usize)>,
}

/// A dialog of a call whose scenario has dialog="N" messages. The state
/// of the current one is in the call's fields, the others' here.
#[derive(Default)]
struct Dialog {
    /// Empty for dialog 1, whose Call-ID is the call's, and until known.
    call_id: String,
    cseq: u32,
    invite_cseq: u32,
    peer_tag: Option<String>,
    last_recv: Option<Arc<str>>,
    route_set: Option<String>,
    next_url: String,
}

struct Dialogs {
    map: BTreeMap<usize, Dialog>,
    current: usize,
    /// The dialog of the message being taken.
    incoming: usize,
    /// Call-IDs known since the engine last looked, which it routes to
    /// the call.
    new_ids: Vec<String>,
}

/// A <recv request>'s method matches the request's.
fn expects_request(expect: &Expect, method: &str) -> bool {
    match expect {
        Expect::Request(m) => m == method,
        Expect::RequestRe(re) => re.is_match(method),
        _ => false,
    }
}

/// Does a call of these steps send the request that creates its dialog
/// (its first SIP message)? Only then does an abort end the dialog: it is
/// the call's role, not the run's (a 3PCC controller B sends the INVITE).
fn creates_dialog(steps: &[Step]) -> bool {
    steps.iter().find_map(|s| match &s.op {
        Op::Recv { .. } => Some(false),
        Op::Send { msg, .. } => Some(msg.method().is_some()),
        _ => None,
    }) == Some(true)
}

/// Is there a <recvCmd> in these steps, before the call sends another
/// command?
fn recv_cmd_follows(steps: &[Step]) -> bool {
    steps.iter().find_map(|s| match s.op {
        Op::RecvCmd { .. } => Some(true),
        Op::SendCmd { .. } => Some(false),
        _ => None,
    }) == Some(true)
}

/// Which of the run's scenarios a call plays.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Sc {
    Main,
    /// -oocsf: a request outside any call.
    Ooc,
    /// -rxsf: an incoming call while the main scenario makes calls.
    Rx,
    /// -aa: a request outside any call, answered, and kept until the end
    /// of the run as SIPp keeps its ooc_dummy call.
    Aa,
}

pub struct Call {
    pub number: u64,
    /// -trace_calldebug: what happened to the call so far. Boxed, as the
    /// srtpctxdebugfile: a Call of at most 1032 bytes is in glibc's
    /// tcache, at a fraction of the cost of a larger one.
    #[allow(clippy::box_collection)]
    debug: Option<Box<String>>,
    /// -tdmmap: the call's circuit (from 1) and its [tdmmap] name.
    circuit: usize,
    circuit_name: Option<String>,
    pub sc: Sc,
    /// The -users user making the call, 0 for none.
    pub user_id: u32,
    pub id: String,
    pub peer: Peer,
    /// The requests that came from elsewhere than `peer` (from another
    /// address over UDP, on another connection otherwise), by their top
    /// Via branch: the responses to them go back there. The last few; a
    /// -t tn call connection among them is held open for them, as SIPp's
    /// ss_count keeps it (Net::hold()).
    request_sources: Vec<(String, Peer, bool)>,
    peer_ip: Rc<str>,
    idx: usize,
    last_recv: Option<Arc<str>>,
    pub last_send: Option<Arc<str>>,
    /// last_send_unanswered: the scenario's last message, a request that
    /// a connection took, with no response yet.
    unanswered: Option<Arc<str>>,
    last_code: Option<u16>,
    peer_tag: Option<String>,
    retrans: Option<Retrans>,
    /// The wakeup the engine's timer queue holds for this call.
    pub scheduled: Option<Instant>,
    /// It runs a step a turn, as SIPp's call runs one message each time
    /// its loop comes to it (an <init> call runs through): `turn` once it
    /// ran one, until the engine runs it on at the loop's next pass; the
    /// engine has it `turn_queued` for that.
    pub turns: bool,
    pub turn: bool,
    pub turn_queued: bool,
    /// The engine's pass it last ran a step in.
    pub ran_in: u32,
    pause_until: Option<Instant>,
    /// rtp_stream="wait": the step whose actions wait for the playback,
    /// and when the wait gives up.
    rtp_wait: Option<(usize, Option<Instant>)>,
    /// Where a <jump> action sends the call once its step is done.
    jump: Option<usize>,
    /// The CSeq of the last INVITE received, which its ACK must repeat.
    invite_cseq: u32,
    /// -rsa: the remote host's port for [remote_port].
    remote_port_kw: Option<u16>,
    /// When the call began, for its length and its response times.
    pub created: Instant,
    /// The <pause> the call is in.
    pub paused_at: Option<usize>,
    /// Its <timewait> has begun.
    in_timewait: bool,
    /// Each RTD's start, and whether it is done.
    rtds: Vec<(Instant, bool)>,
    /// The steps of the last message sent and received, for lost=.
    last_send_idx: usize,
    last_recv_idx: usize,
    /// A <pauserestore>'d pause, which outlives the step it is done in.
    restored_pause: Option<Instant>,
    /// The unexpected message _unexp.main's handler gets at its <recv>.
    queued: Option<Arc<str>>,
    /// Whether its SDP was taken already, not to take it twice.
    queued_sdp: bool,
    /// A command that came while the call waited for a SIP message, kept
    /// for the <recvCmd> that follows.
    queued_cmd: Option<String>,
    recv_deadline: Option<Instant>,
    vars: Vars,
    cseq: u32,
    /// Boxed, made when the scenario first names a transaction.
    txns: Option<Box<Txns>>,
    /// The call's dialogs, with dialog="N" messages; boxed, as few have.
    dialogs: Option<Box<Dialogs>>,
    /// Its place among the calls a request of a Call-ID no call has may
    /// start a dialog of.
    pub wait_seq: Option<u64>,
    /// Another call took its Call-ID: it isn't the call's any more.
    pub displaced: bool,
    /// SIPp's retransmission detection: the last message received until a
    /// send follows it (last_recv_hash), and the message a send answered,
    /// with the steps of both and the answer as it was sent
    /// (recv_retrans_*).
    pending_recv: Option<Arc<str>>,
    answered: Option<(Arc<str>, usize, usize, Arc<str>)>,
    route_set: Option<String>,
    next_url: String,
    /// An ACK went either way: aborting now means BYE, not CANCEL.
    established: bool,
    /// Aborting after a request from the peer: the BYE has our From, To
    /// and CSeq, not that request's.
    bye_after_peer_request: bool,
    /// abortCall() left the dialog with a BYE or a CANCEL, whose answers
    /// its dead call expects.
    pub aborted_with: Option<&'static str>,
    /// The reason its dead call gives, as SIPp's terminate() and
    /// abortCall() word it; none for the ends that keep no dead call.
    pub dead: Option<Cow<'static, str>>,
    failure: Option<Failure>,
    /// How many <exec verify> commands the call waits for before its next
    /// message.
    pub verify_pending: usize,
    /// Why the call failed, for the statistics.
    pub fail: Option<Fail>,
    /// Audio and video.
    media: [Media; 2],
    /// Where the SDP offer/answer stands, which picks the SRTP lines.
    sdp: SdpState,
    /// Each -inf file's line for this call.
    pub lines: HashMap<String, usize>,
    /// The last 401/407 challenge, and the credentials sent for it.
    /// Boxed: most calls have no challenge.
    auth: Option<Box<AuthCtx>>,
    /// Where a playback goes to and comes from; boxed, made once either
    /// is known and not the default.
    pcap: Option<Box<PcapAddrs>>,
    /// The next play_dtmf's first RTP sequence number.
    dtmf_seq: u16,
    /// The call's place in SIPp's RTP playback threads, which run its
    /// media, from its first RTP socket or play.
    stream_task: Option<mediapool::Task>,
    /// rtp_echo started before the call had a task, for its thread.
    pending_echo: Vec<mediapool::Cmd>,
    /// -srtpcheck_debug's srtpctxdebugfile, the call's own.
    pub srtpctx: Option<Box<media::srtpctx_debug::File>>,
}

/// A line of the call's srtpctxdebugfile, formatted only if it has one.
macro_rules! srtpctx {
    ($file:expr, $($arg:tt)*) => {
        if let Some(f) = $file.as_deref_mut() {
            f.line(format_args!($($arg)*));
        }
    };
}

/// call::init()'s srtpctxdebugfile, for SIPp's sendMode, client or
/// server (with neither, none): the header size of its SRTP contexts,
/// which srtp::Context has fixed.
pub fn srtpctx_open(mode: Option<bool>, log: &mut Log) -> Option<Box<media::srtpctx_debug::File>> {
    let Some(mut f) = mode.and_then(|client| media::srtpctx_debug::File::create(client).ok()) else {
        log.warning("Error encountered opening srtp ctx debug file");
        return None;
    };
    let contexts = if f.client { [f.tx(), f.rx()] } else { [f.rx(), f.tx()] };
    for ctx in contexts {
        for media in ["AUDIO", "VIDEO"] {
            f.line(format_args!("call::srtpctx_open():  {ctx}-{media} SRTP context - {} setting SRTP header size to 12\n", f.mode()));
        }
    }
    Some(Box::new(f))
}

fn pcap_index(kind: PcapMedia) -> usize {
    match kind {
        PcapMedia::Audio => 0,
        PcapMedia::Image => 1,
        PcapMedia::Video => 2,
        PcapMedia::Text => 3,
    }
}

const PCAP_MEDIA: [&str; 4] = ["audio", "image", "video", "text"];

/// Without [media_port] in our SDP, SIPp sends from -mp, +2 for video, +4
/// for text.
const PCAP_PORT_OFFSET: [u16; 4] = [0, 0, 2, 4];

/// For audio, image, video and text: the peer's SDP address, and the port
/// our last [media_port] gave (0 for -mp's).
#[derive(Default)]
struct PcapAddrs {
    to: [Option<SocketAddr>; 4],
    from: [u16; 4],
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
enum SdpState {
    #[default]
    None,
    OfferSent,
    OfferReceived,
    Completed,
}

/// One media type's RTP: its port (its socket and what plays on it are in
/// the call's playback thread), where the peer wants it, and its SRTP.
#[derive(Default)]
struct Media {
    /// Our RTP port, 0 until bound.
    port: u16,
    /// Where the peer's SDP says this media goes.
    remote: Option<SocketAddr>,
    /// The peer's SDP holds it: no address of the media's IP version, or
    /// a null one (c=0.0.0.0).
    held: bool,
    /// Made when a message first has its crypto keywords or the peer's
    /// crypto lines: most calls have none.
    crypto: Option<Box<MediaCrypto>>,
}

impl Media {
    fn crypto_mut(&mut self) -> &mut MediaCrypto {
        self.crypto.get_or_insert_with(Default::default)
    }

    /// The SRTP of this media, none if the call has made none.
    fn crypto(&self) -> &MediaCrypto {
        static NONE: MediaCrypto = MediaCrypto::NONE;
        self.crypto.as_deref().unwrap_or(&NONE)
    }
}

/// What fails the call at its end: SIPp's last_action_result.
#[derive(Clone, Copy)]
enum Failure {
    /// A failed check, or setdest's connection, each with its counter.
    Action(Fail),
    /// An <exec verify> command that failed, which has no counter.
    Verify,
    /// An rtp_echo that failed to receive, which has none either but
    /// fails the RTP check.
    RtpEcho,
}

enum SetDestError {
    Fatal(String),
    Connect(String),
}

/// system()'s shell: sh -c, or on Windows cmd /C, given the command as
/// it is, not quoted as an argument, for its redirections.
fn shell(cmd: &str) -> std::process::Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let mut c = std::process::Command::new("cmd");
        c.raw_arg("/C").raw_arg(cmd);
        c
    }
    #[cfg(not(windows))]
    {
        let mut c = std::process::Command::new("sh");
        c.arg("-c").arg(crate::raw::os(cmd));
        c
    }
}

/// is_auto_answered(): a request -aa answers outside of any call.
pub fn auto_answered(cfg: &Config, raw: &str) -> bool {
    cfg.auto_answer && matches!(sip::kind(raw), Some(Kind::Request("INFO" | "NOTIFY" | "OPTIONS" | "UPDATE")))
}

/// C's strcmp() as glibc's returns it: the difference of the first bytes
/// that differ.
fn c_strcmp(a: &str, b: &str) -> i32 {
    let (a, b) = (crate::raw::bytes(a), crate::raw::bytes(b));
    let i = a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count();
    i32::from(a.get(i).copied().unwrap_or(0)) - i32::from(b.get(i).copied().unwrap_or(0))
}

/// process_unexpected()'s words for the step a call is at.
fn while_at(op: Option<&Op>) -> String {
    match op {
        Some(Op::Recv { expect, .. }) => match expect {
            Expect::Response(c) => format!("while expecting '{c}' "),
            Expect::Request(m) => format!("while expecting '{m}' "),
            Expect::ResponseRe(re) | Expect::RequestRe(re) => format!("while expecting '{}' ", re.as_str()),
            Expect::Nothing => "while expecting '' ".into(),
        },
        Some(Op::Send { .. }) => "while sending ".into(),
        Some(Op::Pause(_) | Op::Timewait { .. }) => "while pausing ".into(),
        Some(Op::SendCmd { .. }) => "while sending command ".into(),
        Some(Op::RecvCmd { .. }) => "while expecting command ".into(),
        // MSG_TYPE_NOP.
        Some(Op::Nop) | None => "while in message type 5 ".into(),
    }
}

/// SIPp's clock, which its first read starts, after -sleep: its
/// clock_tick, the RTP timestamps, -trace_rtt's dates and
/// $_unexp.pausedaddr count from there.
pub fn epoch() -> Instant {
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

/// SIPp's clock_tick at `t`: its whole milliseconds.
pub fn tick_ms(t: Instant) -> u64 {
    t.saturating_duration_since(epoch()).as_millis() as u64
}

fn epoch_ms(t: Instant) -> f64 {
    tick_ms(t) as f64
}

/// SIPp's url_encode(): unreserved characters as they are, the rest %XX.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in crate::raw::bytes(s).iter() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out += &format!("%{b:02X}");
        }
    }
    out
}

/// url_decode(): %XX and '+' for a space; a '%' without two hex digits
/// stays as it is.
fn url_decode(s: &str) -> String {
    let b = crate::raw::bytes(s);
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = b.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok()).and_then(|h| u8::from_str_radix(h, 16).ok());
        match (b[i], hex) {
            (b'%', Some(v)) => {
                out.push(v);
                i += 3;
                continue;
            }
            (b'+', _) => out.push(b' '),
            (c, _) => out.push(c),
        }
        i += 1;
    }
    crate::raw::text_owned(out)
}

/// Where a header search lands, as SIPp's extractSubMessage(): the value
/// is the rest of that line. A header name (an RFC 3261 token, with or
/// without its colon) starts a line and ends at the colon: "To" is neither
/// "Topic:" nor "X-Forward-To:". Any other text ("tag=") is looked for
/// anywhere, or at the start of a line with start_line.
fn header_text<'a>(msg: &'a str, header: &str, start_line: bool, occurrence: usize, case_indep: bool) -> Option<&'a str> {
    let toklen = header.bytes().take_while(|c| c.is_ascii_alphanumeric() || b"-.!%*_+`'~".contains(c)).count();
    let name = toklen > 0 && matches!(&header[toklen..], "" | ":");
    let need_colon = name && toklen == header.len();
    let start_line = start_line || name;
    let (hay, needle) = if case_indep {
        (msg.to_ascii_lowercase(), header.to_ascii_lowercase())
    } else {
        (msg.to_string(), header.to_string())
    };
    let step = needle.chars().next().map_or(1, char::len_utf8);
    let mut seen = 0;
    let mut from = 0;
    while let Some(pos) = hay[from..].find(&needle).map(|p| p + from) {
        from = pos + step;
        if start_line && pos > 0 && !hay[..pos].ends_with('\n') {
            continue;
        }
        if need_colon && !hay[pos + needle.len()..].trim_start_matches([' ', '\t']).starts_with(':') {
            continue;
        }
        seen += 1;
        if seen >= occurrence {
            let rest = &msg[pos + needle.len()..];
            return Some(&rest[..rest.find(['\r', '\n']).unwrap_or(rest.len())]);
        }
    }
    None
}

/// A line of a call's -trace_calldebug history, if it keeps one.
#[allow(clippy::box_collection)]
fn note(history: &mut Option<Box<String>>, log: &Log, text: &str) {
    if let Some(h) = history.as_mut() {
        h.push_str(&log.stamp());
        h.push(' ');
        h.push_str(text);
    }
}

/// An address's text, shared by the calls with the same one.
fn ip_text(ip: IpAddr) -> Rc<str> {
    thread_local! {
        static LAST: RefCell<Option<(IpAddr, Rc<str>)>> = const { RefCell::new(None) };
    }
    LAST.with_borrow_mut(|last| match last {
        Some((known, text)) if *known == ip => text.clone(),
        _ => last.insert((ip, ip.to_string().into())).1.clone(),
    })
}

/// Content-Type application/sdp, as SIPp's strcmp() wants it, but for
/// parameters, blanks and case, which RFC 3261 allows and it refuses.
fn is_sdp_type(content_type: &str) -> bool {
    content_type.split(';').next().unwrap_or("").trim_matches([' ', '\t']).eq_ignore_ascii_case("application/sdp")
}

/// atoll(v) > 0.
fn positive(v: &str) -> bool {
    let v = v.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
    v.strip_prefix('+').unwrap_or(v).bytes().take_while(u8::is_ascii_digit).any(|d| d != b'0')
}

/// Two messages call::hash() takes for the same: all of them with -rtcheck
/// full, their To, From, Call-ID and CSeq (and a response's status line
/// and body) with loose.
fn same_message(a: &str, b: &str, loose: bool) -> bool {
    if !loose {
        return a == b;
    }
    fn key(m: &str) -> Vec<std::borrow::Cow<'_, str>> {
        let mut k: Vec<_> = ["To", "From", "Call-ID", "CSeq"].iter().map(|h| sip::header_content(m, h)).collect();
        if let Some(rest) = m.strip_prefix("SIP/2.0") {
            k.push(rest.split('\r').next().unwrap_or("").into());
            k.push(m.find("\r\n\r\n").map_or("", |e| &m[e + 4..]).into());
        }
        k
    }
    key(a) == key(b)
}

/// call::hash(): sdbm over the message's (signed) chars, or with -rtcheck
/// loose over the parts same_message() compares.
fn hash(msg: &str, loose: bool) -> u64 {
    let sdbm = |h: u64, s: &str| crate::raw::bytes(s).iter().fold(h, |h, c| (*c as i8 as i64 as u64).wrapping_add(h << 6).wrapping_add(h << 16).wrapping_sub(h));
    if !loose {
        return sdbm(0, msg);
    }
    let mut h = ["To", "From", "Call-ID", "CSeq"].iter().fold(0, |h, name| sdbm(h, &sip::header_content(msg, name)));
    if let Some(rest) = msg.strip_prefix("SIP/2.0") {
        h = sdbm(h, rest.split('\r').next().unwrap_or(""));
        h = sdbm(h, msg.find("\r\n\r\n").map_or("", |e| &msg[e + 4..]));
    }
    h
}

impl Call {
    pub fn new(number: u64, id: String, peer: Peer) -> Call {
        Call {
            number,
            debug: None,
            circuit: 0,
            circuit_name: None,
            sc: Sc::Main,
            user_id: 0,
            id,
            peer,
            request_sources: Vec::new(),
            peer_ip: ip_text(peer.addr.ip()),
            idx: 0,
            last_recv: None,
            last_send: None,
            unanswered: None,
            last_code: None,
            peer_tag: None,
            retrans: None,
            scheduled: None,
            turns: false,
            turn: false,
            turn_queued: false,
            ran_in: u32::MAX,
            pause_until: None,
            rtp_wait: None,
            jump: None,
            invite_cseq: 0,
            remote_port_kw: None,
            created: Instant::now(),
            paused_at: None,
            in_timewait: false,
            rtds: Vec::new(),
            last_send_idx: 0,
            last_recv_idx: 0,
            restored_pause: None,
            queued: None,
            queued_sdp: false,
            queued_cmd: None,
            recv_deadline: None,
            vars: Vars::default(),
            cseq: 0,
            txns: None,
            dialogs: None,
            wait_seq: None,
            displaced: false,
            pending_recv: None,
            answered: None,
            route_set: None,
            next_url: String::new(),
            established: false,
            bye_after_peer_request: false,
            aborted_with: None,
            dead: None,
            failure: None,
            verify_pending: 0,
            fail: None,
            media: Default::default(),
            sdp: SdpState::None,
            lines: HashMap::new(),
            auth: None,
            pcap: None,
            // SIPp's play_args_a.last_seq_no.
            dtmf_seq: 1200,
            stream_task: None,
            pending_echo: Vec::new(),
            srtpctx: None,
        }
    }

    /// SIPp's SSRCs: from the base up, audio then video, by call.
    fn ssrc(cfg: &Config, number: u64, video: bool) -> u32 {
        cfg.ssrc_base.wrapping_add((2 * number as u32).wrapping_sub(2) + video as u32)
    }

    /// The call's audio (or video) RTP port, bound on first use: its
    /// socket goes to the call's playback thread.
    fn media_port(&mut self, env: &mut Env, video: bool) -> u16 {
        if self.media[video as usize].port == 0 {
            match env.rtp_ports.bind(env.cfg.media_ip) {
                Ok((rtp, rtcp)) => {
                    self.media[video as usize].port = rtp.local_addr().map_or(0, |a| a.port());
                    self.media_cmd(mediapool::Cmd::Sockets { video, rtp, rtcp });
                }
                Err(e) => env.log.warning(&e),
            }
        }
        self.media[video as usize].port
    }

    /// rtpstream_start_task(): the call joins a playback thread, if it
    /// hasn't, which gets the command.
    fn media_cmd(&mut self, cmd: mediapool::Cmd) {
        let task = self.stream_task.get_or_insert_with(|| {
            let task = mediapool::Task::start();
            for c in self.pending_echo.drain(..) {
                task.send(c);
            }
            task
        });
        task.send(cmd);
    }

    /// A command for the call's playback thread, if it has one.
    fn media_update(&self, cmd: mediapool::Cmd) {
        if let Some(task) = &self.stream_task {
            task.send(cmd);
        }
    }

    /// -base_cseq, and -rsa's [remote_ip] and [remote_port]: the remote host,
    /// not where messages go.
    pub fn set_origin(&mut self, base_cseq: u32, remote: Option<SocketAddr>) {
        self.cseq = base_cseq;
        if let Some(r) = remote {
            self.peer_ip = ip_text(r.ip());
            self.remote_port_kw = Some(r.port());
        }
    }

    /// tcpClose(): the call's connection is gone. A call in, or at, its
    /// <timewait> is done; any other has failed.
    pub fn connection_closed(&mut self, env: &mut Env) -> Outcome {
        self.peer.conn = None;
        let at_timewait = matches!(env.scenario.steps.get(self.idx).map(|s| &s.op), Some(Op::Timewait { .. }));
        if self.in_timewait || at_timewait {
            return self.end();
        }
        self.dead = Some(self.failure_reason().unwrap_or_else(|| format!("failed at index {}", self.idx)).into());
        self.failed(Fail::TcpClosed)
    }

    /// sendCmdMessage(): a command the call could not send deletes it,
    /// failed, a dead call only for a failed action's reason.
    pub fn cmd_not_sent(&mut self) -> Outcome {
        self.dead = self.failure_reason().map(Cow::Owned);
        self.failed(Fail::CmdNotSent)
    }

    /// The step the call is at.
    pub fn index(&self) -> usize {
        self.idx
    }

    /// The call's variables: the scenario's shared ones, and its user's.
    pub fn set_vars(&mut self, vars: Vars) {
        self.vars = vars;
    }

    /// rtpstream_play_pcap(): starts a playback, replacing the one in
    /// progress on its stream. Audio and image end each other too, as a
    /// switch to T.38 often keeps the remote port: no RTP and UDPTL mixed.
    fn play(&mut self, env: &mut Env, kind: PcapMedia, pcap: std::sync::Arc<pcap::Pcap>) {
        let i = pcap_index(kind);
        let (to, port) = self.pcap.as_ref().map_or((None, 0), |p| (p.to[i], p.from[i]));
        let port = match port {
            0 => env.cfg.media_port.wrapping_add(PCAP_PORT_OFFSET[i]),
            port => port,
        };
        let from = SocketAddr::new(env.cfg.media_ip, port);
        // The raw socket first: SIPp exits if it cannot open one.
        let player = match Player::new(pcap, from, to.unwrap_or(from)) {
            Ok(p) => p,
            Err(e) => {
                env.control.fatal = Some(e);
                return;
            }
        };
        // No address for it yet, or none of the media's IP version: SIPp
        // plays to nowhere, without a word.
        if to.is_none() {
            return;
        }
        // It replaces the one in progress, and ends the other of audio
        // and image, in the call's playback thread.
        self.media_cmd(mediapool::Cmd::Play { index: i, player });
    }

    /// Crypto keywords set the SRTP state before a message is rendered, as
    /// SIPp's createSendingMessage() does while rendering; the warnings of
    /// an answer that takes none of the peer's lines.
    fn apply_crypto(&mut self, cfg: &Config, template: &Template) -> Vec<String> {
        let mut warnings = Vec::new();
        if !template.has_srtp_keywords() {
            return warnings;
        }
        // Per media, whether the message has its keywords, and of each
        // line position, a tag and the suite.
        let mut lines = [(false, [(false, None); 2]); 2];
        // -srtpcheck_debug: SIPp's SrtpInfoParams of the message.
        let mut debug: [media::srtp_debug::Params; 2] = Default::default();
        for (kw, offset) in template.srtp_keywords() {
            let k = match kw {
                Kw::Crypto(k) => *k,
                // [rtpstream_audio_port] and [rtpstream_video_port], bound
                // by now: for the log.
                _ => {
                    let video = *kw == Kw::RtpstreamVideoPort;
                    srtpctx!(self.srtpctx, "Call::apply_crypto():  Kw::{kw:?}: {}\n", i64::from(self.media[video as usize].port) + offset);
                    continue;
                }
            };
            let m = self.media[k.video as usize].crypto_mut();
            let sent = &mut lines[k.video as usize];
            let p = &mut debug[k.video as usize];
            sent.0 = true;
            let which = if k.slot == 0 { "PRIMARY" } else { "SECONDARY" };
            match k.what {
                CryptoWhat::Tag => {
                    m.slot(k.slot).tag = k.slot as u32 + 1;
                    sent.1[k.slot].0 = true;
                    p.tags[k.slot] = k.slot as i32 + 1;
                    srtpctx!(self.srtpctx, "Call::apply_crypto():  {which} crypto tag: {}\n", k.slot + 1);
                }
                CryptoWhat::Suite(s) => {
                    let slot = m.slot(k.slot);
                    slot.suite = s;
                    slot.ue = false;
                    sent.1[k.slot].1 = Some(s);
                    p.suites[k.slot] = s.name().to_string();
                    srtpctx!(self.srtpctx, "Call::apply_crypto():  {} {which} cryptosuite {}\n", ["AUDIO", "VIDEO"][k.video as usize], s.name());
                    if k.slot == 0 {
                        match self.sdp {
                            SdpState::None | SdpState::Completed => srtpctx!(self.srtpctx, "Call::apply_crypto():  Marking preferred OFFER cryptosuite...\n"),
                            // Answering: take the peer's line that has our suite.
                            SdpState::OfferReceived => {
                                if m.answer_with(s, &mut warnings) {
                                    srtpctx!(self.srtpctx, "Call::apply_crypto():  Preferred ANSWER cryptosuite mismatch -- SWAPPING...\n");
                                }
                            }
                            SdpState::OfferSent => {}
                        }
                    }
                }
                // A negative offset reuses the key, as in [cryptokeyparams1audio-9].
                // As long as the suite before it on the line takes.
                CryptoWhat::Key => {
                    let slot = m.slot(k.slot);
                    if offset >= 0 {
                        slot.key = srtp::new_master(slot.suite.key_len());
                    }
                    p.keys[k.slot] = srtp::base64(&slot.key);
                    let how = if offset >= 0 { "generating new" } else { "reusing old" };
                    srtpctx!(self.srtpctx, "Call::apply_crypto():  {which} {how} master key/salt: {}\n", p.keys[k.slot]);
                }
                // The NULL cipher and the suite's hash, under the suite's name.
                CryptoWhat::Unencrypted(s) => {
                    let slot = m.slot(k.slot);
                    slot.suite = s;
                    slot.ue = true;
                    sent.1[k.slot].1 = Some(s);
                    p.suites[k.slot] = s.name().to_string();
                    p.unencrypted[k.slot] = true;
                    srtpctx!(self.srtpctx, "Call::apply_crypto():  {} {which} cryptosuite {}\n", ["AUDIO", "VIDEO"][k.video as usize], s.name());
                }
            }
        }
        for (video, (m, (keywords, sent))) in self.media.iter_mut().zip(lines).enumerate() {
            if keywords {
                m.crypto_mut().sent(sent);
                if debug[video].tags[0] != 0 {
                    media::srtp_debug::dump(false, video == 1, &debug[video]);
                    // Where the peer's SRTP comes to, for a client.
                    if let Some(f) = self.srtpctx.as_deref_mut().filter(|f| f.client) {
                        let ssrc = Call::ssrc(cfg, self.number, video == 1);
                        let media = ["AUDIO", "VIDEO"][video];
                        f.line(format_args!("Call::apply_crypto():  RX-UAC-{media} SRTP context - ssrc:0x{ssrc:08x} address:{} port:{}\n", cfg.media_ip_text, m.port));
                    }
                }
            }
        }
        warnings
    }

    /// The peer's SDP: where its media go, its crypto lines, and the answer
    /// picking which of ours is in use; the warnings about its keys and
    /// media, or SIPp's fatal error.
    fn received_sdp(&mut self, env: &Env, kind: &Kind, raw: &str) -> Result<Vec<String>, String> {
        // As SIPp: an SDP body, or a multipart one with an SDP part, of a
        // Content-Length above 0, from all their values joined. Most
        // messages have none: their length first.
        let is_sdp = positive(&sip::header_content(raw, "Content-Length")) && {
            let content_type = sip::header_content(raw, "Content-Type");
            is_sdp_type(&content_type) || (content_type.contains("multipart/") && raw.contains("application/sdp"))
        };
        let (has_media, v6) = (env.cfg.has_media, env.cfg.media_ip.is_ipv6());
        // Most messages have no SDP, nor a scenario with media to look for
        // a body for.
        let body = if is_sdp || has_media { sip::body(raw) } else { "" };
        let mut warnings = Vec::new();
        if is_sdp {
            if let Some(f) = self.srtpctx.as_deref_mut() {
                let switch = "Call::received_sdp():  Switching session state: ";
                match self.sdp {
                    SdpState::None | SdpState::Completed => f.line(format_args!("{switch} SdpState::{:?} --> SdpState::OfferReceived\n", self.sdp)),
                    SdpState::OfferSent => {
                        f.line(format_args!("{switch} SdpState::OfferSent --> eAnswerReceived\n"));
                        f.line(format_args!("Call::received_sdp();  Switching session state:  eAnswerReceived --> SdpState::Completed\n"));
                    }
                    SdpState::OfferReceived => {}
                }
                media::srtpctx_debug::remote_info(f, raw);
            }
            // Where the peer's audio and video go, for the log.
            let mut remotes = [None, None];
            if has_media {
                // extract_rtp_remote_addr(): each stream to the c= line of
                // its own media section, else the session one.
                let audio = media::sdp::stream_remote(raw, "audio")?;
                let video = media::sdp::stream_remote(raw, "video")?;
                if self.srtpctx.is_some() {
                    remotes = [audio.clone(), video.clone()];
                }
                if audio.is_none() && video.is_none() {
                    warnings.push("extract_rtp_remote_addr: no m=audio or m=video or m=image line found in SDP message body".to_string());
                } else {
                    for (video, remote) in [(false, audio), (true, video)] {
                        // rtpstream_set_remote(): a stream without an
                        // address of the media's IP version, or with a
                        // null one, is held until one comes.
                        let ip = |host: &str| match v6 {
                            true => host.parse::<std::net::Ipv6Addr>().ok().map(IpAddr::from),
                            false => host.parse::<std::net::Ipv4Addr>().ok().map(IpAddr::from),
                        };
                        let addr = remote.and_then(|(host, port)| ip(&host).filter(|ip| !ip.is_unspecified()).map(|ip| SocketAddr::new(ip, port)));
                        let m = &mut self.media[video as usize];
                        m.held = addr.is_none();
                        if addr.is_some() {
                            m.remote = addr;
                        }
                        // A stream goes on to the new address, or holds.
                        self.media_update(mediapool::Cmd::Remote { video, addr });
                    }
                }
            }
            // Without its crypto lines, nothing to make SRTP for: most
            // SDPs have none, which one search tells.
            let crypto = if body.contains("a=crypto:") { [(false, "audio"), (true, "video")].as_slice() } else { &[] };
            for &(video, kind) in crypto {
                let lines = srtp::sdp_crypto(raw, kind);
                if lines[0].tag != 0 {
                    let p = media::srtp_debug::Params {
                        tags: lines.clone().map(|l| l.tag as i32),
                        suites: lines.clone().map(|l| l.suite),
                        keys: lines.clone().map(|l| l.key),
                        unencrypted: lines.clone().map(|l| l.unencrypted),
                    };
                    media::srtp_debug::dump(true, video, &p);
                    let answer = self.sdp == SdpState::OfferSent;
                    let name = ["AUDIO", "VIDEO"][video as usize];
                    if let Some(f) = self.srtpctx.as_deref_mut() {
                        let (host, port) = remotes[video as usize].as_ref().map_or(("", 0), |(h, p)| (h.as_str(), *p));
                        let ssrc = Call::ssrc(env.cfg, self.number, video);
                        f.line(format_args!("Call::received_sdp():  TX-{}-{name} SRTP context - ssrc:0x{ssrc:08x} address:{host} port:{port}\n", f.role()));
                        if answer {
                            f.line(format_args!("Call::received_sdp():  TX-{}-{name} SRTP context -- CIPHERSUITE CHOICE...\n", f.role()));
                        }
                    }
                    let m = self.media[video as usize].crypto_mut();
                    m.received(&lines, answer, kind, &mut warnings);
                    if let Some(f) = self.srtpctx.as_deref_mut() {
                        // The lines whose keys it took, which set their
                        // slot's suite.
                        for (n, (line, _)) in lines.iter().zip(&m.rx).enumerate().filter(|(_, (_, slot))| !slot.offered.is_empty()) {
                            let which = ["primary", "secondary"][n];
                            let ue = if line.unencrypted { " UNENCRYPTED_SRTP" } else { "" };
                            f.line(format_args!("Call::received_sdp():  RX-{}-{name} SRTP context -- {which} master key/salt: {}, crypto tag: {}, cryptosuite: [{}]{ue}\n", f.role(), line.key, line.tag as i32, line.suite));
                        }
                    }
                }
            }
            self.sdp = match self.sdp {
                SdpState::None | SdpState::Completed => SdpState::OfferReceived,
                SdpState::OfferSent => SdpState::Completed,
                s => s,
            };
        }
        // get_remote_media_addr(): where pcap plays go, from a response
        // with a body, or from an INVITE, ACK or PRACK.
        let pcap = match kind {
            Kind::Response(_) => !body.is_empty(),
            Kind::Request(m) => ["INVITE", "ACK", "PRACK"].iter().any(|r| m.starts_with(r)),
        };
        if has_media && pcap && media::sdp::has_connection(raw, v6) {
            for (index, kind) in PCAP_MEDIA.into_iter().enumerate() {
                // None to play to on an address of the other IP version.
                let Some((host, _, port)) = media::sdp::pcap_remote(raw, kind).filter(|r| r.1 == v6) else { continue };
                if let (Ok(ip), Ok(port)) = (host.parse::<IpAddr>(), port.parse::<u16>()) {
                    let addr = SocketAddr::new(ip, port);
                    self.pcap.get_or_insert_default().to[index] = Some(addr);
                    // rtpstream_update_pcap(): a play goes on to the new address.
                    self.media_update(mediapool::Cmd::PcapAddr { index, from: None, to: Some(addr) });
                }
            }
        }
        Ok(warnings)
    }

    fn sent_sdp(&mut self, text: &str) {
        // Most messages have no body, which is quicker to see than their
        // Content-Type.
        if !sip::body(text).trim().is_empty() && is_sdp_type(&sip::header_content(text, "Content-Type")) {
            let switch = "Call::sent_sdp():  Switching session state: ";
            match self.sdp {
                SdpState::None | SdpState::Completed => srtpctx!(self.srtpctx, "{switch} SdpState::{:?} --> SdpState::OfferSent\n", self.sdp),
                SdpState::OfferReceived => {
                    srtpctx!(self.srtpctx, "{switch} SdpState::OfferReceived --> eAnswerSent\n");
                    srtpctx!(self.srtpctx, "{switch} eAnswerSent --> SdpState::Completed\n");
                }
                SdpState::OfferSent => {}
            }
            self.sdp = match self.sdp {
                SdpState::None | SdpState::Completed => SdpState::OfferSent,
                SdpState::OfferReceived => SdpState::Completed,
                s => s,
            };
        }
    }

    pub fn next_wakeup(&self) -> Option<Instant> {
        [self.retrans.as_ref().map(|r| r.next), self.pause_until, self.recv_deadline, self.rtp_wait.and_then(|(_, until)| until)]
            .into_iter()
            .flatten()
            .min()
    }

    fn txns_mut(&mut self) -> &mut Txns {
        self.txns.get_or_insert_default()
    }

    fn render(&mut self, env: &Env, t: &Template, msg_index: usize) -> String {
        self.claim_dialog_id(t);
        t.render(&self.ctx(env, msg_index))
    }

    /// dialogCallId(): [call_id] in a dialog whose Call-ID isn't known
    /// yet makes it N-, then the call's.
    fn claim_dialog_id(&mut self, t: &Template) {
        let dialog = self.current_dialog();
        if !self.dialog_known(dialog) && t.uses_call_id() {
            self.set_dialog_call_id(dialog, &format!("{dialog}-{}", self.id));
        }
    }

    fn render_shared(&mut self, env: &Env, t: &Template, msg_index: usize) -> Arc<str> {
        self.claim_dialog_id(t);
        t.render_shared(&self.ctx(env, msg_index))
    }

    fn ctx<'a>(&'a self, env: &'a Env, msg_index: usize) -> Ctx<'a> {
        Ctx {
            service: &env.cfg.service,
            remote_ip: &self.peer_ip,
            remote_port: self.remote_port_kw.unwrap_or(self.peer.addr.port()),
            local_ip: &env.cfg.local_ip,
            local_port: env.net.local_port(&self.peer, env.cfg.local.port()),
            media_ip: env.cfg.media_ip,
            media_ip_text: &env.cfg.media_ip_text,
            media_port: env.cfg.media_port,
            rtp_port: self.media[0].port,
            rtp_video_port: self.media[1].port,
            crypto: Some([self.media[0].crypto(), self.media[1].crypto()]),
            ipv6: env.cfg.local_ip.starts_with('['),
            transport: env.net.transport.name(),
            pid: env.pid,
            call_number: self.number,
            users: env.cfg.users,
            user_id: self.user_id,
            call_id: self.dialog_call_id(),
            msg_index,
            cseq: self.cseq,
            last_recv: self.last_recv.as_deref(),
            remote_host: &env.cfg.remote_host,
            server_ip: env.net.local_ip(&self.peer),
            rfc3339: env.cfg.rfc3339,
            peer_tag: self.peer_tag.as_deref(),
            routes: self.route_set.as_deref(),
            next_url: &self.next_url,
            vars: &self.vars,
            inject: Some((&*env.inject, &self.lines)),
            auth: self.auth.as_deref(),
            tdmmap: self.circuit_name.as_deref(),
            bye_after_peer_request: self.bye_after_peer_request,
        }
    }

    /// [call_id]: the Call-ID of the current dialog.
    fn dialog_call_id(&self) -> &str {
        match self.dialogs.as_deref() {
            Some(ds) if ds.current != 1 => ds.map.get(&ds.current).map_or(&self.id, |d| if d.call_id.is_empty() { &self.id } else { &d.call_id }),
            _ => &self.id,
        }
    }

    /// switchDialog(): the dialog `n`'s state becomes the call's, the
    /// current one's is kept.
    fn switch_dialog(&mut self, env: &Env, n: usize) {
        if !env.scenario.dialogs {
            return;
        }
        let mut ds = self.dialogs.take().unwrap_or_else(|| {
            Box::new(Dialogs { map: BTreeMap::from([(1, Dialog::default())]), current: 1, incoming: 1, new_ids: Vec::new() })
        });
        if ds.current != n {
            self.swap_dialog_state(ds.map.get_mut(&ds.current).unwrap());
            let base_cseq = env.cfg.base_cseq;
            self.swap_dialog_state(ds.map.entry(n).or_insert_with(|| Dialog { cseq: base_cseq, ..Dialog::default() }));
            ds.current = n;
        }
        self.dialogs = Some(ds);
    }

    fn swap_dialog_state(&mut self, d: &mut Dialog) {
        std::mem::swap(&mut self.cseq, &mut d.cseq);
        std::mem::swap(&mut self.invite_cseq, &mut d.invite_cseq);
        std::mem::swap(&mut self.peer_tag, &mut d.peer_tag);
        std::mem::swap(&mut self.last_recv, &mut d.last_recv);
        std::mem::swap(&mut self.route_set, &mut d.route_set);
        std::mem::swap(&mut self.next_url, &mut d.next_url);
    }

    /// msgDialog(): a message's dialog="N", else that of its transaction,
    /// else 1.
    fn msg_dialog(&self, op: &Op) -> usize {
        let (dialog, txn) = match op {
            Op::Send { dialog, response_txn, ack_txn, .. } => (*dialog, response_txn.as_ref().or(ack_txn.as_ref())),
            Op::Recv { dialog, response_txn, .. } => (*dialog, response_txn.as_ref()),
            _ => (0, None),
        };
        match dialog {
            0 => txn.and_then(|t| self.txns.as_ref()?.dialog.get(t)).copied().unwrap_or(1),
            n => n,
        }
    }

    fn current_dialog(&self) -> usize {
        self.dialogs.as_ref().map_or(1, |ds| ds.current)
    }

    fn dialog_known(&self, n: usize) -> bool {
        n == 1 || self.dialogs.as_ref().and_then(|ds| ds.map.get(&n)).is_some_and(|d| !d.call_id.is_empty())
    }

    /// dialogOf(): the dialog of a message's Call-ID, 1 if none. The peer
    /// echoes a "///" prefix written before [call_id]: the dialog's
    /// Call-ID is what follows it, as for the call's.
    fn dialog_of(&self, env: &Env, raw: &str) -> usize {
        let Some(ds) = self.dialogs.as_ref() else { return 1 };
        let full = sip::call_id(raw).unwrap_or("");
        let id = match env.cfg.callid_slash_ign {
            true => full,
            false => full.split_once("///").map_or(full, |(_, rest)| rest),
        };
        ds.map.iter().find(|(_, d)| !d.call_id.is_empty() && (d.call_id == full || d.call_id == id)).map_or(1, |(n, _)| *n)
    }

    /// setDialogCallId(): the engine routes its messages to the call.
    fn set_dialog_call_id(&mut self, n: usize, id: &str) {
        let Some(ds) = self.dialogs.as_mut() else { return };
        // A Call-ID of this call already, such as its own.
        if (id == self.id && !self.displaced) || ds.map.values().any(|d| d.call_id == id) {
            return;
        }
        ds.map.entry(n).or_default().call_id = id.to_string();
        ds.new_ids.push(id.to_string());
    }

    /// The Call-IDs of its dialogs known since the last time.
    pub fn has_dialog_ids(&self) -> bool {
        self.dialogs.as_ref().is_some_and(|ds| !ds.new_ids.is_empty())
    }

    pub fn take_dialog_ids(&mut self) -> Vec<String> {
        self.dialogs.as_mut().map(|ds| std::mem::take(&mut ds.new_ids)).unwrap_or_default()
    }

    /// The Call-IDs of its dialogs but 1.
    pub fn dialog_ids(&self) -> impl Iterator<Item = &str> {
        self.dialogs.iter().flat_map(|ds| ds.map.values()).map(|d| d.call_id.as_str()).filter(|id| !id.is_empty())
    }

    /// newDialogFor() and take_new_dialog(): a request of a Call-ID no
    /// call has starts a dialog of this call if the next message it waits
    /// for is a <recv> of it, in a dialog whose Call-ID it doesn't know.
    pub fn take_new_dialog(&mut self, sc: &Scenario, raw: &str) -> bool {
        let Some(sip::Kind::Request(method)) = sip::kind(raw) else { return false };
        if method.len() >= 65 {
            return false;
        }
        for step in sc.steps.iter().skip(self.idx) {
            let optional = match &step.op {
                Op::Recv { expect, optional, .. } => {
                    let n = self.msg_dialog(&step.op);
                    if !self.dialog_known(n) && expects_request(expect, method) {
                        self.set_dialog_call_id(n, sip::call_id(raw).unwrap_or(""));
                        return true;
                    }
                    *optional
                }
                Op::RecvCmd { optional, .. } => *optional,
                _ => false,
            };
            if !optional {
                break;
            }
        }
        false
    }

    /// remember_request_source(): where a request that did not come from
    /// the call's destination came from, for its responses: RFC 3261
    /// 18.2.2 sends a response back to the source of its request, as
    /// rport (RFC 3581) does in practice. It is found by the request's
    /// top Via branch, which the response copies; a CANCEL has its
    /// INVITE's, and comes from the same hop. -rsa sends every message to
    /// its address.
    pub fn request_came(&mut self, env: &mut Env, raw: &str, src: Peer) {
        const MAX_REQUEST_SOURCES: usize = 4;
        if env.cfg.rsa || raw.starts_with("SIP/2.0 ") || raw.starts_with("ACK ") {
            return;
        }
        let elsewhere = match env.net.transport.udp() {
            true => (src.addr.ip(), src.addr.port()) != (self.peer.addr.ip(), self.peer.addr.port()),
            false => src.conn.is_some() && src.conn != self.peer.conn,
        };
        if !elsewhere && self.request_sources.is_empty() {
            return;
        }
        let Some(branch) = sip::top_via_branch(raw).filter(|b| !b.is_empty()) else { return };
        // A request of this transaction again: it is answered where the
        // last one came from.
        if let Some(i) = self.request_sources.iter().position(|(b, ..)| b == branch) {
            let (_, old, held) = self.request_sources.remove(i);
            self.release(env.net, old, held);
        }
        if !elsewhere {
            return;
        }
        if self.request_sources.len() == MAX_REQUEST_SOURCES {
            let (_, old, held) = self.request_sources.remove(0);
            self.release(env.net, old, held);
        }
        let held = !env.net.transport.udp() && src.conn.is_some_and(|c| env.net.hold(c));
        self.request_sources.push((branch.to_string(), src, held));
    }

    fn release(&self, net: &mut Net, src: Peer, held: bool) {
        if let (true, Some(conn)) = (held, src.conn) {
            net.close(conn);
        }
    }

    /// The call ends: the connections it held for its responses go, unless
    /// others use them.
    pub fn release_request_sources(&mut self, net: &mut Net) {
        for (_, src, held) in std::mem::take(&mut self.request_sources) {
            self.release(net, src, held);
        }
    }

    /// Where send_raw() sends `msg`: a response to a request that came
    /// from elsewhere goes back there, over UDP from the call's socket,
    /// else on that connection while it is open; anything else to the
    /// call's destination.
    fn dest(&self, env: &Env, msg: &str) -> Peer {
        if self.request_sources.is_empty() || !msg.starts_with("SIP/2.0 ") {
            return self.peer;
        }
        let branch = sip::top_via_branch(msg).unwrap_or("");
        match self.request_sources.iter().find(|(b, ..)| b == branch) {
            Some((_, src, _)) if env.net.transport.udp() => Peer { addr: src.addr, conn: self.peer.conn },
            Some((_, src, _)) if src.conn.is_some_and(|c| env.net.is_open(c)) => Peer { conn: src.conn, ..self.peer },
            _ => self.peer,
        }
    }

    /// tcpReconnected(): its connection failed and was made again, with
    /// the calls kept: a request that the old one took, with no response
    /// yet, may have been lost with it, and goes on the new one (see
    /// Net::requeue()).
    pub fn reconnected(&mut self, env: &mut Env) {
        if let Some(text) = self.unanswered.clone() {
            self.debug(env.log, "Sending the unanswered request again on a new connection\n");
            let _ = self.send_at(env, text, self.last_send_idx as i64);
        }
    }

    /// A message of SIPp's own: the call carries on if it fails.
    fn send(&mut self, env: &mut Env, text: String) {
        let r = self.send_at(env, text.into(), -1);
        env.own_send(r);
    }

    /// send_raw(): `index` is the scenario message's, -1 for SIPp's own.
    fn send_at(&mut self, env: &mut Env, text: Arc<str>, index: i64) -> Result<(), String> {
        // Rendering it was fatal: SIPp's ERROR() never sends it.
        if let Some(e) = crate::log::take_deferred_fatal() {
            env.control.fatal = Some(e);
            return Ok(());
        }
        self.debug_sending(env, &text, index);
        let r = env.send(&text, &self.dest(env, &text), index != -1);
        self.note_sent(text);
        r
    }

    pub fn set_circuit(&mut self, n: usize, name: String) {
        self.circuit = n;
        self.circuit_name = Some(name);
    }

    pub fn circuit(&self) -> usize {
        self.circuit
    }

    /// -trace_calldebug: from now on, record the call's history.
    pub fn start_debug(&mut self, log: &Log) {
        self.debug = Some(Box::default());
        let line = format!("Starting call {}\n", self.id);
        self.debug(log, &line);
    }

    fn debugging(&self) -> bool {
        self.debug.is_some()
    }

    fn debug(&mut self, log: &Log, text: &str) {
        note(&mut self.debug, log, text);
    }

    fn debug_sending(&mut self, env: &Env, text: &str, index: i64) {
        if self.debugging() {
            let line = format!(
                "Sending {} message for call {} (index {index}, hash {}):\n{text}\n\n",
                env.net.transport.name(),
                self.id,
                hash(text, env.cfg.rtcheck_loose)
            );
            self.debug(env.log, &line);
        }
    }

    /// abortCall(true): the history goes to the calldebug file.
    fn dump_debug(&mut self, env: &mut Env) {
        if let Some(history) = self.debug.take() {
            env.log.call_debug(&self.id, &history);
        }
    }

    fn note_sent(&mut self, text: Arc<str>) {
        if let Some(Kind::Request(m)) = sip::kind(&text) {
            self.established |= m == "ACK";
        }
        self.last_send = Some(text);
    }

    /// call::next(): the step after this one, or its `next` label when the
    /// test passes and the chance allows.
    fn goto_next(&mut self, env: &mut Env) {
        let sc = env.scenario;
        let step = &sc.steps[self.idx];
        let jump = step.next.filter(|_| {
            step.test.as_ref().is_none_or(|v| self.vars.is_set(v)) && (step.chance >= 1.0 || env.rng.unit() < step.chance)
        });
        self.paused_at = None;
        self.idx = self.jump.take().or(jump).unwrap_or(self.idx + 1);
        self.recv_deadline = None;
        self.pause_until = self.restored_pause.take();
    }

    fn failed(&mut self, why: Fail) -> Outcome {
        self.fail = Some(why);
        Outcome::Failed
    }

    /// terminate()'s dead call reason for a check that failed.
    fn failure_reason(&self) -> Option<String> {
        let i = self.idx;
        let why = match self.failure? {
            Failure::Action(why) => why,
            Failure::Verify => return Some(format!("exec verify failure at index {i}")),
            Failure::RtpEcho => return Some(format!("rtp echo error {i}")),
        };
        Some(match why {
            Fail::RegexpDoesntMatch => format!("regexp match failure at index {i}"),
            Fail::RegexpShouldntMatch => format!("regexp matched, but shouldn't at index {i}"),
            Fail::RegexpHdrNotFound => format!("regexp header not found at index {i}"),
            Fail::TcpConnect => format!("connection failed {i}"),
            Fail::TestDoesntMatch | Fail::StrcmpDoesntMatch => format!("test failure at index {i}"),
            Fail::TestShouldntMatch | Fail::StrcmpShouldntMatch => format!("test succeeded, but shouldn't at index {i}"),
            _ => return None,
        })
    }

    fn end(&mut self) -> Outcome {
        self.dead = Some(self.failure_reason().map_or(Cow::Borrowed("successful"), Cow::Owned));
        if let Some(Failure::Action(why)) = self.failure {
            self.fail = self.fail.or(Some(why));
        }
        if self.failure.is_some() {
            Outcome::Failed
        } else {
            Outcome::Success
        }
    }

    /// Runs the steps that don't wait for the peer: sends, pauses and nops,
    /// one a turn when the call takes turns.
    pub fn advance(&mut self, env: &mut Env) -> Outcome {
        // Not before its turn.
        if self.turn {
            return Outcome::Running;
        }
        let sc = env.scenario;
        let mut ran = false;
        loop {
            let Some(step) = sc.steps.get(self.idx) else {
                // Past its last message, the call waits for its <exec
                // verify> commands alone, as SIPp's next(): verify_done()
                // ends it.
                if self.verify_pending > 0 {
                    self.retrans = None;
                    self.end_rtp_wait();
                    return Outcome::Running;
                }
                return self.end();
            };
            // SIPp's call::run() is over with the message it ran: the
            // next one runs in the loop's next pass, a millisecond later
            // when there is nothing to read. A <recv> that only waits,
            // with no timeout to start, waits from now just as well.
            let waits = || {
                matches!(step.op, Op::Recv { timeout_ms: None, timeout_var: None, .. })
                    && env.cfg.recv_timeout.is_none()
                    && step.condexec.is_none()
                    && self.rtp_wait.is_none()
                    && self.verify_pending == 0
                    && self.queued.is_none()
            };
            if ran && self.turns && !waits() {
                self.turn = true;
                return Outcome::Running;
            }
            // The step waits while the rtp_stream plays.
            if let Some((_, until)) = self.rtp_wait {
                if !self.rtp_playing() {
                    note(&mut self.debug, env.log, "rtp_stream playback over, waking up.\n");
                    self.end_rtp_wait();
                } else if until.is_some_and(|u| Instant::now() >= u) {
                    return self.rtp_wait_timed_out(env);
                } else {
                    return Outcome::Running;
                }
            }
            if let Some((var, inverse)) = &step.condexec {
                if self.vars.is_set(var) == *inverse {
                    self.goto_next(env);
                    ran = true;
                    continue;
                }
            }
            // The step waits for the call's <exec verify> commands, as in
            // SIPp's run(), unless it is a pause under way.
            if self.verify_pending > 0 && self.pause_until.is_none() {
                note(&mut self.debug, env.log, &format!("Waiting for {} exec verify commands.\n", self.verify_pending));
                return Outcome::Running;
            }
            match &step.op {
                Op::Send { msg, retrans_ms, start_txn, ack_txn, response_txn, .. } => {
                    // Nothing new goes out while the last message is still
                    // being retransmitted, as in SIPp.
                    if self.retrans.is_some() {
                        return Outcome::Running;
                    }
                    // A call a 3PCC command started, with no remote host.
                    if env.net.transport.reliable() && self.peer.conn.is_none() && self.peer.addr == NO_REMOTE {
                        env.control.fatal = Some(match env.net.transport.single() {
                            true => format!(
                                "Call '{}' has no socket to send on: a call that a 3PCC command creates in a scenario starting with a <recv> needs a remote host",
                                self.id
                            ),
                            false => format!("Call '{}' has no remote host to connect to", self.id),
                        });
                        return Outcome::Running;
                    }
                    self.switch_dialog(env, self.msg_dialog(&step.op));
                    self.bookkeeping(env, self.idx);
                    if msg.uses_rtp_port() {
                        self.media_port(env, false);
                    }
                    if msg.uses_rtp_video_port() {
                        self.media_port(env, true);
                    }
                    for w in self.apply_crypto(env.cfg, msg) {
                        env.log.warning(&w);
                    }
                    if msg.uses_auth() {
                        if let Some(a) = self.auth.as_mut() {
                            a.nonce_count += 1;
                            // As SIPp: 64 unpredictable bits, against a
                            // server choosing what the digest hashes.
                            let mut r = [0u8; 8];
                            if !crate::sys::random_bytes(&mut r) {
                                r = (u64::from(env.rng.u32()) << 32 | u64::from(env.rng.u32())).to_be_bytes();
                            }
                            a.cnonce = format!("{:016x}", u64::from_be_bytes(r));
                        }
                    }
                    if msg.method().is_some_and(|m| m != "ACK" && m != "CANCEL") {
                        self.cseq = self.cseq.wrapping_add(1);
                    }
                    let dialog = self.current_dialog();
                    // A response in a transaction a received request
                    // started: the [last_*] keywords are of that request.
                    let answered = response_txn.as_ref().filter(|t| self.txns.as_ref().is_some_and(|x| x.server.contains_key(*t)));
                    let text = match answered {
                        Some(t) => {
                            let request = self.txns_mut().server[t].request.clone();
                            let last = self.last_recv.replace(request);
                            let text = self.render_shared(env, msg, self.idx);
                            self.last_recv = last;
                            text
                        }
                        None => self.render_shared(env, msg, self.idx),
                    };
                    if let Some(txn) = start_txn {
                        self.txns_mut().branches.insert(txn.clone(), sip::top_via_branch(&text).unwrap_or("").to_string());
                        if env.scenario.dialogs {
                            self.txns_mut().dialog.insert(txn.clone(), dialog);
                        }
                    }
                    // A Call-ID written without [call_id].
                    if !self.dialog_known(dialog) {
                        if let Some(id) = sip::call_id(&text).ok().filter(|id| !id.is_empty()) {
                            self.set_dialog_call_id(dialog, id);
                        }
                    }
                    // A retransmission of the request gets it again.
                    let idx = self.idx;
                    let answered = answered.map(|t| {
                        let txn = self.txns_mut().server.get_mut(t).unwrap();
                        txn.response = Some((text.clone(), idx));
                        txn.request.clone()
                    });
                    if let Some(txn) = ack_txn {
                        self.txns_mut().ack.insert(txn.clone(), idx);
                    }
                    // Sent just after a message came: a retransmission of
                    // that message gets this one again. A later response
                    // to the same request (a 200 after a 180) takes over;
                    // one to another request (the 200 of an INVITE after
                    // that of a PRACK) doesn't. Only UDP retransmissions of
                    // the request get it again: no copy kept otherwise.
                    let resend = env.cfg.retrans && env.net.transport.udp();
                    // Not a response to an earlier request than the last
                    // received.
                    let loose = env.cfg.rtcheck_loose;
                    if let Some(recv) = self.pending_recv.take_if(|recv| answered.as_ref().is_none_or(|req| same_message(req, recv, loose))) {
                        self.answered = Some((recv, self.last_recv_idx, self.idx, if resend { text.clone() } else { "".into() }));
                    } else if let Some((_, ri, si, sent)) = self.answered.as_mut() {
                        let request = matches!(&env.scenario.steps[*ri].op, Op::Recv { expect: Expect::Request(_) | Expect::RequestRe(_), .. });
                        let same_cseq = || self.last_recv.as_deref().is_some_and(|m| sip::header_content(&text, "CSeq") == sip::header_content(m, "CSeq"));
                        if *ri == self.last_recv_idx && request && msg.response_code().is_some() && same_cseq() {
                            *si = self.idx;
                            if resend {
                                sent.clone_from(&text);
                            }
                        }
                    }
                    if msg.uses_media_port() {
                        for (kind, port) in msg.media_ports(&self.ctx(env, self.idx)) {
                            let i = PCAP_MEDIA.iter().position(|&k| k == kind).unwrap();
                            // -mp's port, as a play takes by default, needs no room.
                            if self.pcap.is_some() || port != env.cfg.media_port.wrapping_add(PCAP_PORT_OFFSET[i]) {
                                self.pcap.get_or_insert_default().from[i] = port;
                            }
                            self.media_update(mediapool::Cmd::PcapAddr { index: i, from: Some(port), to: None });
                        }
                    }
                    self.sent_sdp(&text);
                    self.last_send_idx = self.idx;
                    env.stats.steps[self.idx].sent += 1;
                    let request = (msg.response_code().is_none() && msg.method() != Some("ACK")).then(|| text.clone());
                    // Its actions look in the message sent, as SIPp's.
                    let sent = text.clone();
                    if self.lost(env, self.idx) {
                        // Voluntarily lost: as if sent, retransmissions and all.
                        env.stats.steps[self.idx].lost += 1;
                        self.debug_sending(env, &text, self.idx as i64);
                        env.log.trace_msg(&format!("{} message voluntary lost (while sending).", env.net.transport.name()));
                        if self.debugging() {
                            let line = format!(
                                "{} message voluntary lost (while sending) (index {}, hash {}).\n",
                                env.net.transport.name(),
                                self.idx,
                                hash(&text, env.cfg.rtcheck_loose)
                            );
                            self.debug(env.log, &line);
                        }
                        self.note_sent(text);
                    } else if self.send_at(env, text, self.idx as i64).is_err() {
                        return self.failed(Fail::CannotSendMessage);
                    }
                    // Not one that waits for the connection to be made
                    // again: that sends it (see Net::send()). Only a
                    // connection made again with its calls kept resends
                    // it: other runs keep none, and look for no response.
                    self.unanswered = request.filter(|_| env.net.keep && env.net.all_written(self.peer.conn));
                    // Retransmissions are for UDP only, as in SIPp.
                    self.retrans = retrans_ms.filter(|_| env.cfg.retrans && !env.net.transport.reliable()).map(|ms| Retrans {
                        next: Instant::now() + Duration::from_millis(ms),
                        interval: Duration::from_millis(ms),
                        count: 0,
                    });
                    if let Some(out) = self.action_outcome(env, step, Some(&sent)) {
                        return out;
                    }
                }
                Op::SendCmd { msg, dest } => {
                    let text = self.render(env, msg, self.idx);
                    // A command not sent deletes the call, failed, which
                    // the engine does, as it stops here.
                    if env.twin.send_cmd(dest.as_deref(), &text, false, env.log).is_err() {
                        return Outcome::Running;
                    }
                    env.stats.steps[self.idx].cmds += 1;
                    self.bookkeeping(env, self.idx);
                    if let Some(out) = self.action_outcome(env, step, None) {
                        return out;
                    }
                }
                Op::RecvCmd { .. } => {
                    return match self.queued_cmd.take() {
                        Some(cmd) => {
                            self.turn = self.turns;
                            self.on_command(env, &cmd)
                        }
                        None => Outcome::Running,
                    };
                }
                Op::Recv { timeout_ms, timeout_var, .. } => {
                    if let Some(msg) = self.queued.take() {
                        let sdp_done = std::mem::take(&mut self.queued_sdp);
                        // In its turn: the step after it waits for the next.
                        self.turn = self.turns;
                        return self.take_message(env, &msg, sdp_done);
                    }
                    if self.recv_deadline.is_none() {
                        // recvTimeout(): a variable's number of ms, none
                        // below 1; 0 is no timeout of its own.
                        let ms = match timeout_var {
                            Some(v) => Some(self.var_double(env, v)).filter(|t| *t >= 1.0).map_or(0, |t| t.min(i32::MAX as f64) as u64),
                            None => timeout_ms.unwrap_or(0),
                        };
                        let t = Some(ms).filter(|&ms| ms > 0).map(Duration::from_millis).or(env.cfg.recv_timeout);
                        self.recv_deadline = t.map(|t| Instant::now() + t);
                    }
                    return Outcome::Running;
                }
                Op::Pause(len) => {
                    let now = Instant::now();
                    match self.pause_until {
                        None => {
                            self.bookkeeping(env, self.idx);
                            env.stats.steps[self.idx].sessions += 1;
                            if let Some(out) = self.action_outcome(env, step, None) {
                                return out;
                            }
                            self.paused_at = Some(self.idx);
                            let d = self.pause_len(env, len);
                            self.pause_until = Some(now + d);
                            if !d.is_zero() {
                                return Outcome::Running;
                            }
                            env.control.woken += 1;
                        }
                        Some(until) if now < until => return Outcome::Running,
                        Some(_) => {}
                    }
                }
                Op::Nop => {
                    self.bookkeeping(env, self.idx);
                    if let Some(out) = self.action_outcome(env, step, None) {
                        return out;
                    }
                }
                // A <pause> at whose end the call is over, as in SIPp: it
                // stays to answer retransmissions, and a connection closing
                // in the meantime doesn't fail it.
                Op::Timewait(len) => {
                    let now = Instant::now();
                    match self.pause_until {
                        None => {
                            self.bookkeeping(env, self.idx);
                            env.stats.steps[self.idx].sessions += 1;
                            if let Some(out) = self.action_outcome(env, step, None) {
                                return out;
                            }
                            self.paused_at = Some(self.idx);
                            self.in_timewait = true;
                            let d = self.pause_len(env, len);
                            self.pause_until = Some(now + d);
                            if !d.is_zero() {
                                return Outcome::Running;
                            }
                        }
                        Some(until) if now < until => return Outcome::Running,
                        Some(_) => {}
                    }
                }
            }
            if env.control.stop_now {
                return Outcome::StopNow;
            }
            if self.pause_until.is_some_and(|until| Instant::now() < until) {
                return Outcome::Running;
            }
            self.goto_next(env);
            ran = true;
        }
    }

    fn matches(&self, env: &Env, j: usize, kind: &Kind, raw: &str) -> bool {
        let op = &env.scenario.steps[j].op;
        let Op::Recv { expect, response_txn, methods, .. } = op else {
            return false;
        };
        if env.scenario.dialogs && self.msg_dialog(op) != self.dialogs.as_ref().map_or(1, |ds| ds.incoming) {
            return false;
        }
        match (expect, kind) {
            (Expect::Request(_) | Expect::RequestRe(_), Kind::Request(k)) => return expects_request(expect, k),
            // A code of 0 (none) is no response that a step expects.
            (Expect::Response(c), Kind::Response(k)) if c == k && *k != 0 => {}
            (Expect::ResponseRe(re), Kind::Response(k)) if *k != 0 && re.is_match(&k.to_string()) => {}
            _ => return false,
        }
        // A response must belong to one of this call's requests.
        if let Some(txn) = response_txn {
            return self.txns.as_ref().and_then(|x| x.branches.get(txn)).map(String::as_str) == sip::top_via_branch(raw);
        }
        j == 0 || sip::cseq_method(raw).is_none_or(|m| m.is_empty() || methods.contains(m))
    }

    pub fn on_message(&mut self, env: &mut Env, raw: impl Into<Arc<str>>) -> Outcome {
        self.take_message(env, &raw.into(), false)
    }

    /// A message, `sdp_done` when its SDP was taken already.
    fn take_message(&mut self, env: &mut Env, raw: &Arc<str>, mut sdp_done: bool) -> Outcome {
        // checkAckCSeq(): what it can't take for a request ends the run,
        // once get_cseq_value() has looked at it.
        let fatal = |env: &mut Env, text: String| {
            if let Err(w) = sip::cseq_value(raw) {
                env.log.warning(&w);
            }
            env.control.fatal = Some(text);
            Outcome::Running
        };
        let kind = match sip::kind(raw) {
            Some(Kind::Request(m)) if m.len() >= 64 => return fatal(env, format!("SIP method too long in received message '{raw}'")),
            None if !raw.starts_with("SIP/2.0") && !raw.contains(' ') => return fatal(env, format!("Invalid SIP message received '{raw}'")),
            Some(kind) => kind,
            None => return Outcome::Running,
        };
        if self.debugging() {
            let line = format!("Processing {} byte incoming message for call-ID {} (hash {}):\n{raw}\n\n", crate::raw::len(raw), self.id, hash(raw, env.cfg.rtcheck_loose));
            self.debug(env.log, &line);
        }
        if matches!(kind, Kind::Response(_)) && self.unanswered.as_deref().is_some_and(|req| sip::header_content(req, "CSeq") == sip::header_content(raw, "CSeq")) {
            self.unanswered = None;
        }
        // Over but for its <exec verify> commands, the call takes no more
        // messages.
        if self.idx >= env.scenario.steps.len() {
            return Outcome::Running;
        }
        if env.cfg.pause_msg_ign && matches!(env.scenario.steps.get(self.idx).map(|s| &s.op), Some(Op::Pause(_))) {
            return Outcome::Running;
        }
        // Over UDP, the same message again: the peer missed the answer to
        // it, which goes again; or nothing answered it yet, and it goes.
        if env.cfg.retrans && env.net.transport.udp() {
            let loose = env.cfg.rtcheck_loose;
            if let Some((ri, si, sent)) = self.answered.as_ref().filter(|(recv, ..)| same_message(recv, raw, loose)).map(|(_, ri, si, sent)| (*ri, *si, sent.clone())) {
                if self.lost(env, ri) {
                    env.stats.steps[ri].lost += 1;
                    let t = env.net.transport.name();
                    env.log.trace_msg(&format!("{t} message (retrans) lost (recv)."));
                    if self.debugging() {
                        let line = format!("{t} message (retrans) lost (recv) (hash {})\n", hash(raw, loose));
                        self.debug(env.log, &line);
                    }
                    return Outcome::Running;
                }
                env.stats.steps[ri].recv_retrans += 1;
                // Sent again as it was sent: rendering it again would give
                // new values to keywords such as the SRTP keys.
                self.debug_sending(env, &sent, si as i64);
                let _ = env.send(&sent, &self.dest(env, &sent), true);
                env.stats.steps[si].sent_retrans += 1;
                env.stats.retransmission();
                return Outcome::Running;
            }
            if self.pending_recv.as_deref().is_some_and(|last| same_message(last, raw, loose)) {
                env.stats.steps[self.last_recv_idx].recv_retrans += 1;
                return Outcome::Running;
            }
            // A request of a transaction started before the last message:
            // the last response sent in it, if any, goes again.
            if let Some(txn) = self.txns.as_ref().and_then(|x| x.server.values().find(|t| same_message(&t.request, raw, loose))) {
                env.stats.steps[txn.step].recv_retrans += 1;
                if let Some((sent, si)) = txn.response.clone() {
                    self.debug_sending(env, &sent, si as i64);
                    let _ = env.send(&sent, &self.dest(env, &sent), true);
                    env.stats.steps[si].sent_retrans += 1;
                    env.stats.retransmission();
                }
                return Outcome::Running;
            }
        }

        if env.scenario.dialogs {
            let n = self.dialog_of(env, raw);
            self.switch_dialog(env, n);
            if let Some(ds) = self.dialogs.as_mut() {
                ds.incoming = n;
            }
        }
        // checkAckCSeq(): an ACK must carry the CSeq of the INVITE we got.
        let cseq = sip::cseq_value(raw).unwrap_or_else(|w| {
            env.log.warning(&w);
            0
        });
        if let Kind::Request(m) = kind {
            // Kept in 32 bits: a Call fits the tcache.
            if m.starts_with("ACK") && env.cfg.default_behaviors & BEHAVIOR_BADCSEQ != 0 && cseq as u32 != self.invite_cseq {
                env.log.warning("ACK CSeq value does NOT match value of related INVITE CSeq -- aborting call");
                return Outcome::Failed;
            }
        }
        let sc = env.scenario;
        let steps = &sc.steps;
        // A <nop> or <sendCmd> the call hasn't run yet (the first step of a
        // server call, or the one after a send) runs first; the message
        // waits for the <recv> after it.
        if self.rtp_wait.is_none() && matches!(steps.get(self.idx).map(|s| &s.op), Some(Op::Nop | Op::SendCmd { .. })) {
            self.queued = Some(raw.clone());
            self.queued_sdp = sdp_done;
            // Now, before its turn, as SIPp's process_incoming() runs it.
            self.turn = false;
            return self.advance(env);
        }
        // SIPp takes a message without a To header as unexpected, whatever it is.
        if sip::header(raw, "To").is_some() {
            // Its SDP first, as SIPp takes it before looking for the step
            // it matches, if any: an unexpected message's too.
            // ignoresdp= of the step the call is at, SIPp's curmsg. Once
            // only: SIPp takes that of a message _unexp.main gets again at
            // its <recv>, an answer then being a new offer.
            if !sdp_done && !steps.get(self.idx).is_some_and(|s| s.ignoresdp) {
                sdp_done = true;
                match self.received_sdp(env, &kind, raw) {
                    Ok(warnings) => {
                        for w in warnings {
                            env.log.warning(&w);
                        }
                    }
                    Err(e) => {
                        env.control.fatal = Some(e);
                        return Outcome::Running;
                    }
                }
            }
            // Then an INVITE's CSeq, or a response's To tag, whatever step
            // it matches: one without keeps the tag before.
            if let Kind::Request(m) = kind {
                if m.starts_with("INVITE") {
                    self.invite_cseq = sip::cseq_value(raw).unwrap_or_else(|w| {
                        env.log.warning(&w);
                        0
                    }) as u32;
                }
            }
            if let Kind::Response(_) = kind {
                match sip::peer_tag(raw) {
                    Ok(Some(tag)) => {
                        if let Some(tag) = tag.filter(|&tag| self.peer_tag.as_deref() != Some(tag)) {
                            self.peer_tag = Some(tag.to_string());
                        }
                    }
                    found => {
                        if let Err(pos) = found {
                            env.log.warning(&format!("Missing CR during header scan at pos {pos}"));
                        }
                        env.log.warning("No valid To: header in reply");
                    }
                }
            }
            let mut j = self.idx;
            loop {
                match steps.get(j).map(|s| &s.op) {
                    Some(Op::Recv { optional, .. }) => {
                        if self.matches(env, j, &kind, raw) {
                            return self.received(env, j, &kind, raw);
                        }
                        if !optional {
                            break;
                        }
                    }
                    // An optional <recvCmd> is passed over too.
                    Some(Op::RecvCmd { optional: true, .. }) => {}
                    _ => break,
                }
                j += 1;
            }
            // Back through what the call has passed, as SIPp: an optional
            // <recv> is taken again while only optional ones lie between, a
            // global one from anywhere. A late copy matching further back is
            // absorbed only as SIPp absorbs it; anything else is unexpected.
            let mut contiguous = true;
            for j in (0..self.idx).rev() {
                let (optional, global, txn) = match &steps[j].op {
                    Op::Recv { optional, global, response_txn, .. } => (*optional, *global, response_txn.as_deref()),
                    Op::RecvCmd { optional, .. } => (*optional, false, None),
                    _ => (false, false, None),
                };
                contiguous &= optional;
                if !self.matches(env, j, &kind, raw) {
                    continue;
                }
                if contiguous || global {
                    return self.received(env, j, &kind, raw);
                }
                if self.late_copy(env, j, txn, &kind, raw) {
                    return Outcome::Running;
                }
            }
        }
        // A _unexp.main label takes the message instead, once at a time
        // when $_unexp.retaddr says where the call was.
        if let Some(target) = sc.unexpected_jump {
            if !(sc.uses_retaddr && self.vars.double("_unexp.retaddr") != 0.0) {
                if sc.uses_retaddr {
                    self.vars.set_double("_unexp.retaddr", self.idx as f64);
                }
                if sc.uses_pausedaddr {
                    self.vars.set_double("_unexp.pausedaddr", self.pause_until.map_or(0.0, epoch_ms));
                }
                self.idx = target;
                self.queued = Some(raw.clone());
                self.queued_sdp = sdp_done;
                self.pause_until = None;
                self.end_rtp_wait();
                self.recv_deadline = None;
                return self.advance(env);
            }
        }
        let behaviors = env.cfg.default_behaviors;
        let aborts = behaviors & BEHAVIOR_ABORTUNEXP != 0;
        // checkAutomaticResponseMode(): BYE, CANCEL, PING and -aa's methods.
        match kind {
            Kind::Request(m @ ("BYE" | "CANCEL")) => {
                env.stats.unexpected += 1;
                self.count_unexpected(env, &kind);
                self.last_recv = Some(raw.clone());
                if !aborts {
                    env.log.warning(&format!("Continuing call on an unexpected {m} for call: {}", self.id));
                    return Outcome::Running;
                }
                env.log.warning(&format!("Aborting call on an unexpected {m} for call: {}", self.id));
                self.abort(env, &kind);
                self.abort_twin(env);
                return self.failed(Fail::UnexpectedMessage);
            }
            Kind::Request("PING") => {
                self.last_recv = Some(raw.clone());
                if behaviors & BEHAVIOR_PINGREPLY == 0 {
                    env.log.warning(&format!("Do not answer on an unexpected PING for call: {}", self.id));
                    return Outcome::Running;
                }
                env.log.warning(&format!("Automatic response mode for an unexpected PING for call: {}", self.id));
                let ok = self.render(env, &env.defaults.ok, self.idx);
                self.send(env, ok);
                self.abort_twin(env);
                env.stats.auto_answered();
                return Outcome::Discarded;
            }
            _ => {}
        }
        if self.auto_answer(env, raw) {
            return Outcome::Running;
        }
        if self.debugging() {
            let line = format!(
                "Unexpected {} message received (index {}, hash {}):\n\n{raw}\n",
                env.net.transport.name(),
                self.idx,
                hash(raw, env.cfg.rtcheck_loose)
            );
            self.debug(env.log, &line);
        }
        env.stats.unexpected += 1;
        self.count_unexpected(env, &kind);
        env.log.warning(&format!(
            "{} call on unexpected message for Call-Id '{}': {}(index {}), received '{raw}'",
            if aborts { "Aborting" } else { "Continuing" },
            self.id,
            while_at(steps.get(self.idx).map(|s| &s.op)),
            self.idx,
        ));
        env.log.trace_msg(&format!("-----------------------------------------------\nUnexpected {} message received:\n\n{raw}\n", env.net.transport.name()));
        if !aborts {
            return Outcome::Running;
        }
        self.abort_twin(env);
        self.last_recv = Some(raw.clone());
        self.abort(env, &kind);
        self.failed(Fail::UnexpectedMessage)
    }

    /// A message matching step `j`, which the call is past: absorbed as
    /// SIPp absorbs it, or false to go on looking.
    fn late_copy(&mut self, env: &mut Env, j: usize, txn: Option<&str>, kind: &Kind, raw: &str) -> bool {
        let provisional = matches!(kind, Kind::Response(c) if (100..200).contains(c));
        let t = env.net.transport.name();
        if let Some(txn) = txn {
            if provisional {
                env.log.trace_msg(&format!("-----------------------------------------------\nIgnoring provisional {t} message for transaction {txn}:\n\n{raw}\n"));
                if self.debugging() {
                    let line = format!("Ignoring provisional {t} message for transaction {txn} (hash {}):\n\n{raw}\n", hash(raw, env.cfg.rtcheck_loose));
                    self.debug(env.log, &line);
                }
                return true;
            }
            if let Some(&ack) = self.txns.as_ref().and_then(|x| x.ack.get(txn)) {
                // A final response again: its ACK again.
                self.send_step_again(env, ack, -1);
                return true;
            }
            if self.txns.as_ref().and_then(|x| x.resp.get(txn)) == Some(&hash(raw, env.cfg.rtcheck_loose)) {
                let h = hash(raw, env.cfg.rtcheck_loose);
                env.log.trace_msg(&format!("-----------------------------------------------\nIgnoring final {t} message for transaction {txn}:\n\n{raw}\n"));
                if self.debugging() {
                    let line = format!("Ignoring final {t} message for transaction {txn} (hash {h}):\n\n{raw}\n");
                    self.debug(env.log, &line);
                }
                env.log.warning(&format!("Ignoring final {t} message for transaction {txn} (hash {h}):\n\n{raw}"));
                return true;
            }
            return false;
        }
        if provisional {
            env.log.trace_msg(&format!("-----------------------------------------------\nIgnoring late provisional {t} message:\n\n{raw}\n"));
            if self.debugging() {
                let line = format!("Ignoring late provisional {t} message (hash {}):\n\n{raw}\n", hash(raw, env.cfg.rtcheck_loose));
                self.debug(env.log, &line);
            }
            return true;
        }
        // A response to the INVITE again, when an ACK followed it: that ACK
        // again, to quench the retransmissions.
        let acked = matches!(env.scenario.steps.get(j + 1).map(|s| &s.op), Some(Op::Send { msg, .. }) if msg.method() == Some("ACK"));
        if matches!(kind, Kind::Response(_)) && sip::cseq_method(raw) == Some("INVITE") && acked {
            self.send_step_again(env, j + 1, -1);
            return true;
        }
        // The peer ACKs each 200 we retransmit, so an ACK can come again.
        if matches!(kind, Kind::Request("ACK")) {
            env.log.trace_msg(&format!("-----------------------------------------------\nIgnoring repeated {t} ACK:\n\n{raw}\n"));
            if self.debugging() {
                let line = format!("Ignoring repeated {t} ACK (hash {}):\n\n{raw}\n", hash(raw, env.cfg.rtcheck_loose));
                self.debug(env.log, &line);
            }
            return true;
        }
        false
    }

    /// A <send> the call already passed, rendered and sent once more, as
    /// SIPp's send_scene() (`index` its send_raw() index).
    fn send_step_again(&mut self, env: &mut Env, i: usize, index: i64) {
        if let Some(Step { op: Op::Send { msg, .. }, .. }) = env.scenario.steps.get(i) {
            let text = self.render(env, msg, i);
            self.debug_sending(env, &text, index);
            let r = env.send(&text, &self.dest(env, &text), index != -1);
            // A scenario message is only sent again over UDP, which doesn't fail here.
            if index == -1 {
                env.own_send(r);
            }
        }
    }

    fn received(&mut self, env: &mut Env, j: usize, kind: &Kind, raw: &Arc<str>) -> Outcome {
        if self.lost(env, j) {
            env.stats.steps[j].lost += 1;
            let t = env.net.transport.name();
            env.log.trace_msg(&format!("{t} message lost (recv)."));
            if self.debugging() {
                let line = format!("{t} message lost (recv) (hash {}).\n", hash(raw, env.cfg.rtcheck_loose));
                self.debug(env.log, &line);
            }
            return Outcome::Running;
        }
        // Part of a transaction: its final response, as SIPp marks it.
        if let Op::Recv { response_txn: Some(txn), .. } = &env.scenario.steps[j].op {
            self.txns_mut().resp.insert(txn.clone(), hash(raw, env.cfg.rtcheck_loose));
        }
        // A request that starts a transaction: kept for its responses.
        if let Op::Recv { start_txn: Some(txn), .. } = &env.scenario.steps[j].op {
            self.txns_mut().server.insert(txn.clone(), ServerTxn { request: raw.clone(), step: j, response: None });
            if env.scenario.dialogs {
                let dialog = self.current_dialog();
                self.txns_mut().dialog.insert(txn.clone(), dialog);
            }
        }
        env.stats.steps[j].recv += 1;
        self.bookkeeping(env, j);
        // advance_state="false": nothing of the call's state moves.
        let advance = !matches!(env.scenario.steps[j].op, Op::Recv { advance_state: false, .. });
        // One copy of it for both, which a call keeps.
        let msg: Option<Arc<str>> = advance.then(|| raw.clone());
        if advance {
            self.last_recv_idx = j;
            self.pending_recv = msg.clone();
        }
        match kind {
            Kind::Response(code) => self.last_code = Some(*code),
            Kind::Request(m) => self.established |= *m == "ACK",
        }
        // As SIPp: a response, or an ACK, CANCEL, BYE or PRACK, past the
        // message being retransmitted stops that; a provisional response to
        // a non-INVITE request only slows it to T2.
        let answers = matches!(kind, Kind::Response(_) | Kind::Request("ACK" | "CANCEL" | "BYE" | "PRACK"));
        if answers && j > self.last_send_idx {
            let slows = matches!(kind, Kind::Response(c) if *c < 200) && sip::cseq_method(raw).is_some_and(|m| m != "INVITE");
            match self.retrans.as_mut() {
                Some(r) if slows => {
                    r.interval = env.cfg.t2;
                    r.next = Instant::now() + env.cfg.t2;
                }
                _ => self.retrans = None,
            }
        }
        let at = self.idx;
        self.idx = j;
        let sc = env.scenario;
        let step = &sc.steps[j];
        if let Some(out) = self.action_outcome(env, step, Some(raw)) {
            return out;
        }
        if env.control.stop_now {
            return Outcome::StopNow;
        }
        if let Op::Recv { rrs: true, .. } = step.op {
            self.record_route(env, raw, matches!(kind, Kind::Request(_)));
        }
        // [cseq] follows a request's, in SIPp's unsigned int.
        if matches!(kind, Kind::Request(m) if !m.is_empty()) {
            let n = sip::cseq_value(raw).unwrap_or_else(|w| {
                env.log.warning(&w);
                0
            });
            if n > u64::from(self.cseq) {
                self.cseq = n as u32;
            }
        }
        if let (Op::Recv { auth: true, .. }, Kind::Response(code @ (401 | 407))) = (&env.scenario.steps[j].op, kind) {
            // All the challenges, of which the first SIPp can answer.
            let joined = [sip::header_content(raw, "Proxy-Authenticate"), sip::header_content(raw, "WWW-Authenticate")];
            match joined.iter().find(|ch| !ch.is_empty()) {
                Some(ch) => {
                    self.auth = Some(Box::new(AuthCtx {
                        challenge: crate::auth::select_challenge(ch).to_string(),
                        code: *code,
                        nonce_count: 0,
                        cnonce: String::new(),
                        uri: format!("sip:{}", env.cfg.auth_uri.clone().unwrap_or_else(|| format!("{}:{}", self.peer_ip, self.remote_port_kw.unwrap_or(self.peer.addr.port())))),
                        user: env.cfg.auth_user.clone(),
                        pass: env.cfg.auth_pass.clone(),
                    }));
                }
                None => {
                    env.control.fatal = Some("Couldn't find 'Proxy-Authenticate' or 'WWW-Authenticate' in 401 or 407!".into());
                    return Outcome::Running;
                }
            }
        }
        if !advance {
            self.idx = at;
            self.jump = None;
            return Outcome::Running;
        }
        // Only now, as SIPp: in the message's own actions, [last_*] is the
        // message received before it.
        self.last_recv = msg;
        // A message the scenario expects ends a wait, as it ends a pause,
        // unless its own actions set it; one it may take does not.
        let optional = matches!(step.op, Op::Recv { optional: true, .. });
        let moves = !optional || step.next.is_some() && step.test.as_ref().is_none_or(|v| self.vars.is_set(v));
        if moves && self.rtp_wait.is_some_and(|(w, _)| w != j) {
            self.end_rtp_wait();
        }
        self.goto_next(env);
        self.advance(env)
    }

    /// Whether the call's rtp_stream still plays, even paused.
    fn rtp_playing(&self) -> bool {
        self.stream_task.as_ref().is_some_and(mediapool::Task::playing)
    }

    fn end_rtp_wait(&mut self) {
        if self.rtp_wait.take().is_some() {
            if let Some(t) = &self.stream_task {
                t.wait(false);
            }
        }
    }

    /// The media task whose streams the call waits for, once they have
    /// played: take_ended() names it.
    pub fn rtp_waiting_task(&self) -> Option<u64> {
        self.stream_task.as_ref().filter(|_| self.rtp_wait.is_some()).map(mediapool::Task::id)
    }

    /// rtpstreamWaitTimeout(): the playback outlasted the wait. The call
    /// goes to the ontimeout label of the step that waits, or fails
    /// without one.
    fn rtp_wait_timed_out(&mut self, env: &mut Env) -> Outcome {
        let Some((w, _)) = self.rtp_wait else { return Outcome::Running };
        self.end_rtp_wait();
        let sc = env.scenario;
        env.stats.steps[w].timeouts += 1;
        match sc.steps[w].ontimeout {
            None => env.log.warning(&format!(
                "Call-Id: {}, rtp_stream wait timeout on message {}:{w} without label to jump to (ontimeout attribute): aborting call",
                self.id, sc.name
            )),
            Some(label) => {
                env.log.warning(&format!("Call-Id: {}, rtp_stream wait timeout on message {}:{w}, jumping to label {label}", self.id, sc.name));
                self.idx = label;
                self.pause_until = None;
                self.recv_deadline = None;
                if label < sc.steps.len() {
                    return self.advance(env);
                }
            }
        }
        self.abort(env, &Kind::Response(0));
        Outcome::Failed
    }

    /// Waiting in a <recvCmd>, which a command without a Call-ID goes to.
    pub fn waits_for_command(&self, env: &Env) -> bool {
        matches!(env.scenario.steps.get(self.idx).map(|s| &s.op), Some(Op::RecvCmd { .. }))
    }

    /// process_twinSippCom(): a command from the twin SIPp, for the next
    /// <recvCmd>, its actions run against the command text.
    pub fn on_command(&mut self, env: &mut Env, cmd: &str) -> Outcome {
        let sc = env.scenario;
        if self.debugging() {
            let line = format!("Processing incoming command for call-ID {}:\n{cmd}\n\n", self.id);
            self.debug(env.log, &line);
        }
        // checkInternalCmd(): the twin aborted its call.
        if internal_cmd(cmd) == Some("abort_call") {
            self.dead = Some(format!("aborted at index {}", self.idx).into());
            self.leave_dialog(env, &Kind::Response(0));
            self.dump_debug(env);
            return Outcome::Failed;
        }
        // check_peer_src(): in extended mode, what follows "From:".
        let from = cmd.find("From:").map(|i| cmd[i + 5..].trim_start_matches([' ', '\t'])).map(|f| f.split([' ', '\t', '\r', '\n']).next().unwrap_or(""));
        let mut j = self.idx;
        loop {
            match sc.steps.get(j).map(|s| &s.op) {
                Some(Op::RecvCmd { src, .. }) if src.is_none() || src.as_deref() == from => break,
                Some(Op::RecvCmd { .. }) => {
                    env.log.warning(&format!("Unexpected sender for the received peer message\n{cmd}"));
                    return self.failed(Fail::CallRejected);
                }
                Some(Op::Nop) | Some(Op::Recv { optional: true, .. }) => j += 1,
                // The twin can answer a <sendCmd> before the SIP message
                // the call waits for comes, or before the call has sent
                // the one after the <sendCmd>: keep the command for the
                // <recvCmd> that follows, as a message that comes before a
                // <sendCmd> has run is kept for its <recv>.
                Some(Op::Recv { .. } | Op::Send { .. }) if self.queued_cmd.is_none() && recv_cmd_follows(&sc.steps[j + 1..]) => {
                    if self.debugging() {
                        let line = format!("Keeping the command for the <recvCmd> after index {j}.\n");
                        self.debug(env.log, &line);
                    }
                    self.queued_cmd = Some(cmd.to_string());
                    return Outcome::Running;
                }
                op => {
                    let why = if op.is_some() { "I was expecting a different type of message" } else { "no such message found" };
                    env.log.trace_msg(&format!("Unexpected control message received ({why}):\n{cmd}\n"));
                    if self.debugging() {
                        let line = format!("Unexpected control message received ({why}):\n{cmd}\n\n");
                        self.debug(env.log, &line);
                    }
                    return self.failed(Fail::CallRejected);
                }
            }
        }
        self.idx = j;
        env.stats.steps[j].cmds += 1;
        self.bookkeeping(env, j);
        // Only the blank line that ends a command, not a body's last CRLF.
        let cmd = cmd.strip_suffix("\r\n\r\n").unwrap_or(cmd);
        if let Some(out) = self.action_outcome(env, &sc.steps[j], Some(cmd)) {
            return out;
        }
        self.goto_next(env);
        self.advance(env)
    }

    /// computeRouteSetAndRemoteTargetUri(): the dialog's Route set and the
    /// target for [next_url], from Record-Route and Contact.
    fn record_route(&mut self, env: &mut Env, raw: &str, is_request: bool) {
        if self.route_set.is_some() {
            return;
        }
        self.next_url.clear();
        // All the Contact and Record-Route values, joined.
        let contact = sip::header_content(raw, "Contact");
        if contact.is_empty() {
            env.log.warning("Cannot record route set if there is no Contact");
            return;
        }
        let rr = sip::header_content(raw, "Record-Route");
        let mut target = String::new();
        if !rr.is_empty() {
            // getline()'s: no empty last one after a final comma.
            let mut headers: Vec<&str> = rr.strip_suffix(',').unwrap_or(&rr).split(',').collect();
            if !is_request {
                headers.reverse();
            }
            let mut routes = Vec::new();
            let mut first = true;
            for h in headers {
                if first && !h.contains(";lr") {
                    // A strict router: it becomes the target.
                    target = h.to_string();
                } else {
                    first = false;
                    routes.push(h.trim_matches(' ').to_string());
                }
            }
            if target.is_empty() {
                target = contact.to_string();
            } else {
                routes.push(contact.trim_matches(' ').to_string());
            }
            if !routes.is_empty() {
                self.route_set = Some(routes.join(", "));
            }
        } else {
            target = contact.to_string();
        }
        let t = target.trim_start_matches([' ', '\t']);
        self.next_url = match (t.find('<'), t.find('>')) {
            (Some(b), Some(e)) if b < e => t[b + 1..e].to_string(),
            _ => t.to_string(),
        };
    }

    /// -3pcc: the twin's call is aborted too, once this one got anywhere.
    fn abort_twin(&mut self, env: &mut Env) {
        if let Some(t) = env.defaults.abort_3pcc.as_ref().filter(|_| self.idx > 0) {
            let text = self.render(env, t, self.idx);
            let _ = env.twin.send_cmd(None, &text, true, env.log);
        }
    }

    /// abortCall(true): leave the dialog, and write the call's history.
    fn abort(&mut self, env: &mut Env, unexpected: &Kind) {
        if env.cfg.default_behaviors & BEHAVIOR_BYE == 0 {
            return;
        }
        // An unexpected BYE or CANCEL is answered, and the call deleted.
        if !matches!(unexpected, Kind::Request("BYE" | "CANCEL")) {
            self.dead = Some(format!("aborted at index {}", self.idx).into());
        }
        self.leave_dialog(env, unexpected);
        self.dump_debug(env);
    }

    /// abortCall(): leave the dialog as SIPp does before dropping the call.
    fn leave_dialog(&mut self, env: &mut Env, unexpected: &Kind) {
        if self.debugging() {
            let line = format!("Aborting call {} (index {}).\n", self.id, self.idx);
            self.debug(env.log, &line);
        }
        let d = env.defaults;
        if let Kind::Request("BYE" | "CANCEL") = unexpected {
            let ok = self.render(env, &d.ok, self.idx);
            self.send(env, ok);
            return;
        }
        if !creates_dialog(&env.scenario.steps) || self.idx == 0 {
            return;
        }
        let invite_pending = self.last_send.as_deref().is_some_and(|m| m.starts_with("INVITE")) && !self.established;
        let mut out = Vec::new();
        if invite_pending {
            // What came last, the unexpected message included, as abortCall().
            let last = self.last_recv.as_deref().map(|m| match sip::kind(m) {
                Some(Kind::Response(c)) => c,
                _ => 0,
            });
            match last {
                Some(c) if c >= 400 => out.push(&d.ack),
                Some(_) if self.last_code.is_some_and(|c| (200..300).contains(&c)) => {
                    out.extend([&d.ack, &d.bye]);
                    self.aborted_with = Some("BYE");
                }
                Some(_) => {
                    out.push(&d.cancel);
                    self.aborted_with = Some("CANCEL");
                }
                // No answer at all: nothing to cancel yet.
                None => {}
            }
        } else if let Some(last) = self.last_recv.as_deref() {
            self.bye_after_peer_request = !matches!(sip::kind(last), Some(Kind::Response(_)));
            out.push(&d.bye);
            self.aborted_with = Some("BYE");
        }
        // A default message's [branch] is of the step before the call's,
        // but the BYE starts a transaction of its own: its branch is of an
        // index past the last step, which no message of the call has.
        for t in out {
            let index = if std::ptr::eq(t, &d.bye) { env.scenario.steps.len() } else { self.idx.saturating_sub(1) };
            let text = self.render(env, t, index);
            self.send(env, text);
        }
    }

    /// -aa: a 200 for an INFO, NOTIFY, OPTIONS or UPDATE nobody expected.
    pub fn auto_answer(&mut self, env: &mut Env, raw: &str) -> bool {
        if !auto_answered(env.cfg, raw) {
            return false;
        }
        // The 200's [last_*] are of the request; the call's last message
        // is then the one before, as SIPp restores it, if there was one.
        let before = self.last_recv.replace(raw.into());
        let d = env.defaults;
        let ok = self.render(env, &d.ok, self.idx);
        self.send(env, ok);
        if before.is_some() {
            self.last_recv = before;
        }
        env.stats.auto_answered();
        true
    }

    /// The run is ending (global -timeout): count the call failed and leave
    /// its dialog as SIPp's abort does.
    pub fn abort_now(&mut self, env: &mut Env) {
        env.log.warning(&format!("Aborted call with Call-ID '{}'", self.id));
        self.dead = Some(format!("aborted at index {}", self.idx).into());
        if env.cfg.default_behaviors & BEHAVIOR_BYE != 0 {
            self.leave_dialog(env, &Kind::Response(0));
        }
    }

    /// -3pcc: the twin connection is gone while the call waits for its
    /// command, which never comes: tcpClose(), it fails as a call on a
    /// closed connection does.
    pub fn twin_lost(&mut self) -> Outcome {
        self.dead = Some(self.failure_reason().unwrap_or_else(|| format!("failed at index {}", self.idx)).into());
        self.failed(Fail::TcpClosed)
    }

    /// How long a <pause> or <timewait> lasts this time.
    fn pause_len(&self, env: &mut Env, len: &PauseLen) -> Duration {
        match len {
            PauseLen::Default => env.cfg.default_pause,
            // Negative samples would pause for ever.
            PauseLen::Dist(dist) => Duration::from_millis(dist.sample(env.rng).max(0.0) as u64),
            PauseLen::Var(v) => Duration::from_millis(self.var_double(env, v).max(0.0) as u64),
        }
    }

    /// For the timers: a receive timeout ends the call, or jumps to ontimeout.
    fn recv_timed_out(&mut self, env: &mut Env) -> Outcome {
        self.recv_deadline = None;
        env.stats.timeouts += 1;
        if let Some(c) = env.stats.steps.get_mut(self.idx) {
            c.timeouts += 1;
        }
        let sc = env.scenario;
        if let Some(Step { op: Op::Recv { ontimeout: Some(label), .. }, .. }) = sc.steps.get(self.idx) {
            env.log.warning(&format!("Call-Id: {}, receive timeout on message {}:{}, jumping to label {label}", self.id, sc.name, self.idx));
            self.idx = *label;
            if *label < sc.steps.len() {
                return self.advance(env);
            }
            // A label at the end fails the call, as SIPp's special case.
            self.abort(env, &Kind::Response(0));
            return self.failed(Fail::TimeoutOnRecv);
        }
        env.log.warning(&format!(
            "Call-Id: {}, receive timeout on message {}:{} without label to jump to (ontimeout attribute): aborting call",
            self.id, sc.name, self.idx
        ));
        self.abort(env, &Kind::Response(0));
        self.failed(Fail::TimeoutOnRecv)
    }

    pub fn on_timer(&mut self, env: &mut Env, now: Instant) -> Outcome {
        if let Some(r) = self.retrans.as_mut().filter(|r| now >= r.next) {
            let invite = self.last_send.as_deref().is_some_and(|m| m.starts_with("INVITE "));
            r.count += 1;
            let max = if invite { env.cfg.max_invite_retrans } else { env.cfg.max_non_invite_retrans };
            note(&mut self.debug, env.log, &format!("Retransmission required ({} retransmissions, max {max})\n", r.count));
            if r.count > max {
                env.stats.timeouts += 1;
                env.stats.steps[self.last_send_idx].timeouts += 1;
                // The send's ontimeout label, as SIPp's: the call goes on
                // there, or fails at the end.
                if let Some(Step { op: Op::Send { ontimeout: Some(label), .. }, .. }) = env.scenario.steps.get(self.last_send_idx) {
                    let label = *label;
                    env.log.warning(&format!("Call-Id: {}, timeout on max UDP retrans for message {}, jumping to label {label} ", self.id, self.idx));
                    self.retrans = None;
                    self.recv_deadline = None;
                    self.idx = label;
                    if label < env.scenario.steps.len() {
                        return self.advance(env);
                    }
                    if env.cfg.default_behaviors & BEHAVIOR_BYE != 0 {
                        self.abort(env, &Kind::Response(0));
                    }
                    return self.failed(Fail::MaxUdpRetrans);
                }
                if env.cfg.default_behaviors & BEHAVIOR_BYE != 0 {
                    env.log.warning(&format!("Aborting call on UDP retransmission timeout for Call-ID '{}'", self.id));
                    self.abort(env, &Kind::Response(0));
                }
                return self.failed(Fail::MaxUdpRetrans);
            }
            r.interval = if invite { r.interval * 2 } else { (r.interval * 2).min(env.cfg.t2) };
            r.next = now + r.interval;
            env.stats.retransmission();
            let last = self.last_send.clone().expect("retransmitting without a message");
            env.stats.steps[self.last_send_idx].sent_retrans += 1;
            if self.lost(env, self.last_send_idx) {
                env.stats.steps[self.last_send_idx].lost += 1;
                // SIPp's sendBuffer(), as for the first send.
                self.debug_sending(env, &last, self.last_send_idx as i64);
                let t = env.net.transport.name();
                env.log.trace_msg(&format!("{t} message voluntary lost (while sending)."));
                if self.debugging() {
                    let line = format!("{t} message voluntary lost (while sending) (index {}, hash {}).\n", self.last_send_idx, hash(&last, env.cfg.rtcheck_loose));
                    self.debug(env.log, &line);
                }
            } else {
                self.debug_sending(env, &last, self.last_send_idx as i64);
                if env.send(&last, &self.dest(env, &last), true).is_err() {
                    return self.failed(Fail::CannotSendMessage);
                }
            }
        }
        if self.recv_deadline.is_some_and(|t| now >= t) {
            return self.recv_timed_out(env);
        }
        if self.pause_until.is_some_and(|until| now >= until) || self.rtp_wait.is_some_and(|(_, until)| until.is_some_and(|u| now >= u)) {
            return self.advance(env);
        }
        Outcome::Running
    }

    /// take_ended(): the call's streams have played, ending its wait.
    pub fn rtp_played(&mut self, env: &mut Env) -> Outcome {
        match self.rtp_wait.is_some() && !self.rtp_playing() {
            true => self.advance(env),
            false => Outcome::Running,
        }
    }

    /// startVerify(): runs an <exec verify> command, as system() runs it
    /// but without waiting: the call waits for it before its next message.
    fn start_verify(&mut self, env: &mut Env, cmd: String) {
        env.log.trace_msg(&format!("Executing '{cmd}'\n"));
        match shell(&cmd).spawn() {
            Ok(child) => {
                env.verify.push((child, cmd));
                self.verify_pending += 1;
            }
            Err(e) => {
                let why = crate::net::os_error(&e);
                env.control.fatal = Some(format!("Forking error main, errno = {} ({why})", e.raw_os_error().unwrap_or(0)));
            }
        }
    }

    /// verifyDone(): an <exec verify> command ended, and a non-zero exit
    /// or a signal fails the call. The last one to end lets the call go
    /// on, or ends it past its last message.
    pub fn verify_done(&mut self, env: &mut Env, cmd: &str, status: std::process::ExitStatus) -> Outcome {
        match status.code() {
            Some(code) => {
                env.log.trace_msg(&format!("'{cmd}' returned {code}\n"));
                if code != 0 {
                    env.log.warning(&format!("Call-Id: {}, '{cmd}' returned {code}", self.id));
                    self.failure = Some(Failure::Verify);
                }
            }
            None => {
                let signal = crate::sys::exit_signal(&status);
                env.log.trace_msg(&format!("'{cmd}' was killed by signal {signal}\n"));
                env.log.warning(&format!("Call-Id: {}, '{cmd}' was killed by signal {signal}", self.id));
                self.failure = Some(Failure::Verify);
            }
        }
        self.verify_pending -= 1;
        if self.verify_pending > 0 {
            return Outcome::Running;
        }
        self.advance(env)
    }

    /// The <setdest> checks and change of SIPp.
    fn set_dest(&mut self, env: &mut Env, host: &str, port: &str, protocol: &str) -> Result<(), SetDestError> {
        use crate::net::Transport;
        let fatal = |m: String| SetDestError::Fatal(m);
        let port: u16 = port.trim().parse().map_err(|_| fatal(format!("Invalid port for setdest: {port}")))?;
        let wanted = match protocol {
            "udp" | "UDP" => "udp",
            "tcp" | "TCP" => "tcp",
            "tls" | "TLS" => "tls",
            "sctp" | "SCTP" => "sctp",
            "ws" | "WS" => "ws",
            "wss" | "WSS" => "wss",
            other => return Err(fatal(format!("Unknown transport for setdest: '{other}'"))),
        };
        let transport = env.net.transport;
        let ours = match transport {
            Transport::Udp | Transport::UdpMulti | Transport::UdpPerIp => "udp",
            Transport::TcpSingle | Transport::TcpMulti => "tcp",
            Transport::TlsSingle | Transport::TlsMulti => "tls",
            Transport::SctpSingle | Transport::SctpMulti => "sctp",
            Transport::WsSingle | Transport::WsMulti => "ws",
            Transport::WssSingle | Transport::WssMulti => "wss",
        };
        if wanted != ours {
            return Err(fatal("Can not switch protocols during setdest.".into()));
        }
        match transport {
            t if t.tls() => return Err(fatal("Changing destinations is not supported for TLS.".into())),
            Transport::TcpSingle | Transport::SctpSingle | Transport::WsSingle => {
                return Err(fatal("Changing destinations for TCP or SCTP requires multisocket mode.".into()))
            }
            // Past -max_socket, calls share a connection.
            _ if !transport.udp() && self.peer.conn.is_some_and(|c| env.net.users(c) > 1) => {
                return Err(fatal("Can not change destinations for a TCP/SCTP socket that has more than one user.".into()))
            }
            _ => {}
        }
        // An address in the family of the call's socket, if the name has one.
        let prefer_v6 = env.net.local_ip(&self.peer).map(|ip| ip.is_ipv6());
        let addr = crate::net::resolve((host, port), prefer_v6)
            .ok()
            .flatten()
            .ok_or_else(|| fatal(format!("Unknown host '{host}' for setdest")))?;
        // A UDP call socket is bound, not connected: it stays the call's.
        if !transport.udp() {
            if let Some(conn) = self.peer.conn.take() {
                env.net.close(conn);
            }
        }
        self.peer.addr = addr;
        if matches!(transport, Transport::TcpMulti | Transport::SctpMulti | Transport::WsMulti) {
            self.peer.conn = env.net.connect_elsewhere(addr).map_err(|_| SetDestError::Connect("Unable to connect a TCP/SCTP/TLS socket".into()))?;
        }
        Ok(())
    }

    /// call::lost(): drop step `j`'s message, at its lost= or -lost rate?
    fn lost(&self, env: &mut Env, j: usize) -> bool {
        let percent = env.scenario.steps.get(j).and_then(|s| s.lost).unwrap_or(env.cfg.lost);
        percent > 0.0 && env.rng.unit() < percent / 100.0
    }

    /// process_unexpected()'s counts: the step's, and the response's code.
    fn count_unexpected(&self, env: &mut Env, kind: &Kind) {
        if let Some(c) = env.stats.steps.get_mut(self.idx) {
            c.unexpected += 1;
        }
        if let Kind::Response(code @ 1..) = kind {
            env.stats.error_codes.push(*code);
        }
    }

    /// do_bookkeeping(): step `j`'s counter= and response times.
    fn bookkeeping(&mut self, env: &mut Env, j: usize) {
        let step = &env.scenario.steps[j];
        if let Some(c) = step.counter {
            env.stats.counter(c);
        }
        let n = env.scenario.layout.rtds.len();
        if self.rtds.len() < n {
            // Until a start_rtd, an RTD counts from the call's start.
            self.rtds.resize(n, (self.created, false));
        }
        // One time for all the step's timers.
        let now = Instant::now();
        for &r in &step.start_rtd {
            self.rtds[r].0 = now;
        }
        for &r in &step.stop_rtd {
            if !self.rtds[r].1 {
                env.stats.rtd(r, now.duration_since(self.rtds[r].0), now.duration_since(epoch()));
                self.rtds[r].1 = !step.repeat_rtd;
            }
        }
    }

    /// get_rhs(): a value, or a variable's number.
    fn num(&self, env: &mut Env, n: &Num) -> f64 {
        match n {
            Num::Value(v) => *v,
            Num::Var(v) => self.var_double(env, v),
        }
    }

    /// get_var_double(): a variable's number, a string or a match converted
    /// as <todouble> does; 0 otherwise, with a warning if it has a value.
    fn var_double(&self, env: &mut Env, name: &str) -> f64 {
        self.vars.to_double(name).unwrap_or_else(|| {
            if self.vars.is_set(name) {
                env.log.warning(&format!("Invalid double conversion of ${name}"));
            }
            0.0
        })
    }

    /// An action's text, or None when rendering it was fatal (a [fieldN
    /// line=] that is no number), which ends the run before the action.
    fn action_text(&mut self, env: &mut Env, t: &Template) -> Option<String> {
        self.claim_dialog_id(t);
        let text = t.render_line(&self.ctx(env, self.idx));
        match crate::log::take_deferred_fatal() {
            Some(e) => {
                env.control.fatal = Some(e);
                None
            }
            None => Some(text),
        }
    }

    /// Runs a step's actions, and what they ask for, the same for every
    /// step (SIPp's handleActionResult()): a failed check fails the call
    /// at its end, stop_call and a failed setdest end it now.
    fn action_outcome(&mut self, env: &mut Env, step: &Step, msg: Option<&str>) -> Option<Outcome> {
        match self.run_actions(env, step, msg) {
            ActionResult::Ok => None,
            ActionResult::StopCall => Some(self.failed(Fail::CallRejected)),
            ActionResult::Failed(Fail::TcpConnect) => {
                self.failure = Some(Failure::Action(Fail::TcpConnect));
                Some(self.end())
            }
            ActionResult::Failed(why) => {
                self.failure = Some(Failure::Action(why));
                None
            }
            ActionResult::RtpEchoError => {
                self.failure = Some(Failure::RtpEcho);
                matches!(step.op, Op::Nop).then(|| self.end())
            }
        }
    }

    /// The call failed an rtp_echo: SIPp's setRtpEchoErrors(1).
    pub fn echo_failed(&self) -> bool {
        matches!(self.failure, Some(Failure::RtpEcho))
    }

    fn run_actions(&mut self, env: &mut Env, step: &Step, msg: Option<&str>) -> ActionResult {
        for action in &step.actions {
            match self.action(env, action, msg) {
                ActionResult::Ok => {}
                other => return other,
            }
            // A fatal error ends the run at once, as SIPp's ERROR() exits.
            if env.control.stop_now || env.control.fatal.is_some() {
                break;
            }
        }
        ActionResult::Ok
    }

    /// check_it fails when `ok` isn't, check_it_inverse when it is.
    fn check(check: &Check, ok: bool, doesnt: Fail, shouldnt: Fail) -> Result<(), ActionResult> {
        if check.check_it && !ok {
            Err(ActionResult::Failed(doesnt))
        } else if check.inverse && ok {
            Err(ActionResult::Failed(shouldnt))
        } else {
            Ok(())
        }
    }

    fn action(&mut self, env: &mut Env, action: &Action, msg: Option<&str>) -> ActionResult {
        let result = (|| -> Result<(), ActionResult> {
            match action {
                Action::Ereg { re, source, check, assign_to } => {
                    let owned;
                    let msg = msg.or(self.last_recv.as_deref()).unwrap_or("");
                    // As SIPp: a header or body not there fails check_it,
                    // else the regexp looks in "".
                    let text = match source {
                        Source::Msg => msg,
                        Source::Body => match msg.find("\r\n\r\n") {
                            Some(e) => &msg[e + 4..],
                            None if check.check_it => {
                                env.log.warning(&format!("Failed regexp match: body not found in message\n{msg}"));
                                return Err(ActionResult::Failed(Fail::RegexpHdrNotFound));
                            }
                            None => "",
                        },
                        Source::Hdr { header, start_line, occurrence, case_indep } => match header_text(msg, header, *start_line, *occurrence, *case_indep) {
                            Some(v) if !v.is_empty() => v,
                            _ if check.check_it => {
                                env.log.warning(&format!("Failed regexp match: header {header} not found in message\n{msg}"));
                                return Err(ActionResult::Failed(Fail::RegexpHdrNotFound));
                            }
                            _ => "",
                        },
                        Source::Var(v) => {
                            owned = self.vars.string(v).to_string();
                            owned.as_str()
                        }
                    };
                    let caps = re.captures(text);
                    if caps.is_none() && check.check_it {
                        env.log.warning(&format!("Failed regexp match: looking in '{text}', with regexp '{}'", re.as_str()));
                    } else if caps.is_some() && check.inverse {
                        env.log.warning(&format!("Regexp matched but should not: looking in '{text}', with regexp '{}'", re.as_str()));
                    }
                    Self::check(check, caps.is_some(), Fail::RegexpDoesntMatch, Fail::RegexpShouldntMatch)?;
                    if let Some(caps) = caps {
                        for (i, var) in assign_to.iter().enumerate() {
                            if let Some(Some(m)) = caps.get(i) {
                                self.vars.set_regexp(var, m);
                            }
                        }
                    }
                }
                Action::Strcmp { assign_to, var, rhs: operand, check } => {
                    let (rhs, rhs_name) = match operand {
                        Operand::Value(v) => (v.clone(), ""),
                        Operand::Var(v) => (self.vars.string(v).to_string(), v.as_str()),
                    };
                    let lhs = self.vars.string(var).to_string();
                    let value = c_strcmp(&lhs, &rhs);
                    if (check.check_it && value != 0) || (check.inverse && value == 0) {
                        let inv = if check.check_it { "" } else { "_inverse" };
                        env.log.warning(&format!("strcmp {var}:\"{lhs}\" and {rhs_name}:\"{rhs}\" with check_it{inv} returned {value}"));
                    }
                    Self::check(check, value == 0, Fail::StrcmpDoesntMatch, Fail::StrcmpShouldntMatch)?;
                    if let Some(to) = assign_to {
                        self.vars.set_double(to, f64::from(value));
                    }
                }
                Action::Test { assign_to, var, compare, rhs: operand, check } => {
                    let lhs = self.vars.double(var);
                    let (rhs, rhs_name) = match operand {
                        Operand::Value(v) => (v.trim().parse().unwrap_or(0.0), ""),
                        Operand::Var(v) => (self.vars.double(v), v.as_str()),
                    };
                    let (ok, op) = match compare {
                        Compare::Equal => (lhs == rhs, "=="),
                        Compare::NotEqual => (lhs != rhs, "!="),
                        Compare::Greater => (lhs > rhs, ">"),
                        Compare::Less => (lhs < rhs, "<"),
                        Compare::GreaterEqual => (lhs >= rhs, ">="),
                        Compare::LessEqual => (lhs <= rhs, "<="),
                    };
                    if (check.check_it && !ok) || (check.inverse && ok) {
                        let inv = if check.check_it { "" } else { "_inverse" };
                        env.log.warning(&format!("test \"{var}:{lhs:.6} {op} {rhs_name}:{rhs:.6}\" with check_it{inv} failed"));
                    }
                    Self::check(check, ok, Fail::TestDoesntMatch, Fail::TestShouldntMatch)?;
                    if let Some(to) = assign_to {
                        self.vars.set_bool(to, ok);
                    }
                }
                Action::Assign { var, value } => {
                    let v = self.num(env, value);
                    self.vars.set_double(var, v);
                }
                Action::Arith { op, var, rhs: operand } => {
                    let (lhs, rhs) = (self.var_double(env, var), self.num(env, operand));
                    let v = match op {
                        Arith::Add => lhs + rhs,
                        Arith::Subtract => lhs - rhs,
                        Arith::Multiply => lhs * rhs,
                        // Only a variable can be zero: a value of zero doesn't load.
                        Arith::Divide if rhs == 0.0 => {
                            let by = match operand {
                                Num::Var(v) => v.as_str(),
                                Num::Value(_) => "",
                            };
                            env.log.warning(&format!("Action failure: Can not divide by zero (${var}/${by})!"));
                            lhs
                        }
                        Arith::Divide => lhs / rhs,
                    };
                    self.vars.set_double(var, v);
                }
                Action::Index(var) => self.vars.set_double(var, self.idx as f64),
                Action::GetTimeOfDay { sec, usec } => {
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
                    self.vars.set_double(sec, now.as_secs() as f64);
                    self.vars.set_double(usec, now.subsec_micros() as f64);
                }
                Action::Jump(to) => {
                    let to = self.num(env, to);
                    let steps = env.scenario.steps.len();
                    if to as usize == self.idx {
                        env.control.fatal = Some(format!("Jump statement at index {} jumps to itself and causes an infinite loop", self.idx));
                    } else if to < 0.0 || to as usize > steps {
                        env.control.fatal = Some(format!("Jump statement out of range (not 0 <= {} <= {steps})", to as i64));
                    } else {
                        self.jump = Some(to as usize);
                    }
                }
                Action::Sample { var, dist } => {
                    let v = dist.sample(env.rng);
                    self.vars.set_double(var, v);
                }
                Action::ToDouble { to, from } => match self.vars.to_double(from) {
                    Some(v) => self.vars.set_double(to, v),
                    None => env.log.warning(&format!("Invalid double conversion from ${from} to ${to}")),
                },
                Action::Str { op, var } => {
                    let v = self.vars.string(var);
                    let out = match op {
                        // isspace(), \v included.
                        StrOp::Trim => v.trim_matches(|c: char| c.is_ascii_whitespace() || c == '\x0b').to_string(),
                        StrOp::UrlEncode => url_encode(&v),
                        StrOp::UrlDecode => url_decode(&v),
                    };
                    self.vars.set_string(var, &out);
                }
                Action::Lookup { var, file, key } => {
                    let ctx = self.ctx(env, self.idx);
                    let (file, key) = (file.render_line(&ctx), key.render_line(&ctx));
                    match env.inject.get(&file).map(|f| f.lookup(&file, &key)) {
                        Some(Ok(line)) => self.vars.set_double(var, line),
                        Some(Err(e)) => env.control.fatal = Some(e),
                        None => env.control.fatal = Some(format!("Invalid injection file for lookup: {file}")),
                    }
                }
                Action::Insert { file, value } => {
                    let ctx = self.ctx(env, self.idx);
                    let (file, value) = (file.render_line(&ctx), value.render_line(&ctx));
                    match env.inject.get_mut(&file).map(|f| f.insert(&file, &value)) {
                        Some(Ok(())) => {}
                        Some(Err(e)) => env.control.fatal = Some(e),
                        None => env.control.fatal = Some(format!("Invalid injection file for insert: {file}")),
                    }
                }
                Action::Replace { file, line, value } => {
                    let ctx = self.ctx(env, self.idx);
                    let (file, line, value) = (file.render_line(&ctx), line.render_line(&ctx), value.render_line(&ctx));
                    let result = match (env.inject.get_mut(&file), line.trim().parse::<f64>()) {
                        (None, _) => Err(format!("Invalid injection file for replace: {file}")),
                        (_, Err(_)) => Err(format!("Invalid line number for replace: {line}")),
                        (Some(f), Ok(n)) => f.replace(&file, n as i64, &value),
                    };
                    if let Err(e) = result {
                        env.control.fatal = Some(e);
                    }
                }
                Action::SetDest { host, port, protocol } => {
                    let ctx = self.ctx(env, self.idx);
                    let (host, port, protocol) = (host.render_line(&ctx), port.render_line(&ctx), protocol.render_line(&ctx));
                    if let Err(e) = self.set_dest(env, &host, &port, &protocol) {
                        match e {
                            SetDestError::Fatal(e) => env.control.fatal = Some(e),
                            SetDestError::Connect(e) => {
                                env.log.warning(&e);
                                return Err(ActionResult::Failed(Fail::TcpConnect));
                            }
                        }
                    }
                }
                Action::CloseCon => {
                    if let Some(conn) = self.peer.conn.take() {
                        env.net.close(conn);
                    }
                }
                Action::PauseRestore(n) => {
                    let ms = self.num(env, n);
                    self.restored_pause = (ms > 0.0).then(|| epoch() + Duration::from_millis(ms as u64));
                }
                Action::Error(t) => {
                    let text = t.render_line(&self.ctx(env, self.idx));
                    env.control.fatal = Some(text);
                }
                Action::AssignStr { var, value } => {
                    let Some(text) = self.action_text(env, value) else { return Ok(()) };
                    self.vars.set_string(var, &text);
                }
                Action::Warning(t) => {
                    let Some(text) = self.action_text(env, t) else { return Ok(()) };
                    env.log.warning(&text);
                }
                Action::Log(t) => {
                    let Some(text) = self.action_text(env, t) else { return Ok(()) };
                    env.log.log(&text);
                }
                Action::Exec(t) => {
                    let Some(cmd) = self.action_text(env, t) else { return Ok(()) };
                    // Fire and forget, like SIPp's double fork.
                    if let Ok(mut child) = shell(&cmd).spawn() {
                        std::thread::spawn(move || child.wait());
                    }
                }
                Action::Lua(t) => {
                    let Some(cmd) = self.action_text(env, t) else { return Ok(()) };
                    let names = &env.scenario.var_names;
                    let log = &mut *env.log;
                    if let Err(e) = crate::lua::exec(&cmd, &mut self.vars, names, &mut |m| log.log(m)) {
                        env.control.fatal = Some(e);
                    }
                }
                Action::Verify(t) => {
                    let Some(cmd) = self.action_text(env, t) else { return Ok(()) };
                    self.start_verify(env, cmd);
                }
                Action::Stop(Stop::Now) => env.control.stop_now = true,
                Action::Stop(Stop::Gracefully) => env.control.quitting = true,
                Action::Stop(Stop::Call) => return Err(ActionResult::StopCall),
                Action::RtpEcho(on) => media::ECHO_ON.store(*on, std::sync::atomic::Ordering::Relaxed),
                Action::Unknown => env.control.fatal = Some("call::executeAction unknown action".into()),
                Action::VerifyAuth { assign_to, user, pass } => {
                    let msg = msg.or(self.last_recv.as_deref()).unwrap_or("");
                    let ctx = self.ctx(env, self.idx);
                    let (user, pass) = (user.render_line(&ctx), pass.render_line(&ctx));
                    // SIPp's: the Authorization headers, joined, and the
                    // method a space before the first line's end
                    let ok = match (msg.find('\n'), msg.find(' ')) {
                        (Some(lf), Some(end)) if end < lf => {
                            let creds = sip::header_content(msg, "Authorization");
                            let body = msg.find("\r\n\r\n").map_or("", |e| &msg[e + 4..]);
                            crate::auth::verify(&user, &pass, &msg[..end], &creds, body).unwrap_or_else(|w| {
                                env.log.warning(&w);
                                false
                            })
                        }
                        _ => false,
                    };
                    self.vars.set_bool(assign_to, ok);
                }
                Action::RtpWait { timeout_ms } => {
                    // The next step waits while the playback lasts.
                    if let Some(t) = &self.stream_task {
                        t.wait(true);
                        if t.playing() {
                            let until = (*timeout_ms > 0).then(|| Instant::now() + Duration::from_millis(*timeout_ms));
                            self.rtp_wait = Some((self.idx, until));
                        } else if self.rtp_wait.is_none() {
                            t.wait(false);
                        }
                    }
                }
                Action::RtpPause { video } | Action::RtpResume { video } => {
                    let paused = matches!(action, Action::RtpPause { .. });
                    self.media_update(mediapool::Cmd::Pause { video: *video, paused });
                }
                Action::MediaEcho { video, on, update, bytes } => {
                    let name = ["AUDIO", "VIDEO"][*video as usize];
                    let what = match (on, update) {
                        (true, false) => "START",
                        (true, true) => "UPDATE",
                        (false, _) => "STOP",
                    };
                    // A server's contexts, with the keys of its answer.
                    if let Some(f) = self.srtpctx.as_deref_mut().filter(|f| *on && !f.client) {
                        let ssrc = Call::ssrc(env.cfg, self.number, *video);
                        let port = self.media[*video as usize].port;
                        let at = "Call::action():  ";
                        f.line(format_args!("{at}RX-UAS-{name} SRTP context - ssrc:0x{ssrc:08x} address:{} port:{port}\n", env.cfg.media_ip_text));
                        f.line(format_args!("{at}TX/RX-UAS-{name} SRTP contexts - setting SRTP payload size to {bytes}, deriving session encryption/salting/authentication keys\n"));
                    }
                    let m = &self.media[*video as usize];
                    let cmd = mediapool::Cmd::Echo { video: *video, srtp: on.then(|| (m.crypto().rx_context(), m.crypto().tx_context())), failed: None };
                    let srtp = if *on { "Some(..)" } else { "None" };
                    srtpctx!(self.srtpctx, "Call::action() [{what}{name}]:  mediapool::Cmd::Echo {{ video: {video}, srtp: {srtp} }}\n");
                    match self.stream_task {
                        Some(_) => self.media_update(cmd),
                        None => self.pending_echo.push(cmd),
                    }
                    match (on, update) {
                        (true, false) => media::echo_debug::start(*video),
                        (true, true) => media::echo_debug::update(*video),
                        (false, _) => media::echo_debug::stop(*video),
                    }
                    let task = self.stream_task.as_ref();
                    if *on && !*update {
                        if let Some(t) = task {
                            t.echo_started(*video);
                        }
                    } else if !*on && task.is_some_and(|t| t.echo_failed(*video)) {
                        srtpctx!(self.srtpctx, "Call::action() [{what}{name}]:  mediapool::Task::echo_failed({video}) rc==-1\n");
                        return Err(ActionResult::RtpEchoError);
                    }
                }
                Action::RtpStats { video, vars } => {
                    let received = self.stream_task.as_ref().and_then(|t| t.received(*video));
                    let none = mediapool::Received::default();
                    let r = received.as_deref().unwrap_or(&none);
                    self.vars.set_double(&vars[0], r.packets as f64);
                    if let Some(pt) = vars.get(1) {
                        self.vars.set_double(pt, r.first_pt.map_or(-1.0, f64::from));
                    }
                    if let Some(payload) = vars.get(2) {
                        // The payload in hex.
                        const DIGITS: &[u8; 16] = b"0123456789abcdef";
                        let hex: String = r.first_payload.iter().flat_map(|&b| [DIGITS[(b >> 4) as usize] as char, DIGITS[(b & 15) as usize] as char]).collect();
                        self.vars.set_string(payload, &hex);
                    }
                }
                Action::RtpDtmf { var, payload_type } => {
                    let received = self.stream_task.as_ref().and_then(|t| t.received(false));
                    let digits: String = received.iter().flat_map(|r| &r.dtmf).filter(|(pt, _)| pt == payload_type).map(|&(_, d)| d as char).collect();
                    self.vars.set_string(var, &digits);
                }
                Action::PlayPcap { kind, pcap, .. } => {
                    if let Some(pcap) = pcap.clone() {
                        self.play(env, *kind, pcap);
                    }
                }
                Action::PlayDtmf(digits) => {
                    let spec = digits.render_line(&self.ctx(env, self.idx));
                    let ssrc = env.rng.next_u32();
                    let (events, tone, pt, error) = pcap::parse_dtmf(&spec);
                    if let Some(e) = error {
                        env.log.warning(&format!("Invalid play_dtmf \"{spec}\": {e}"));
                    }
                    let pcap = pcap::dtmf(&events, tone, pt, &mut self.dtmf_seq, ssrc);
                    self.play(env, PcapMedia::Audio, std::sync::Arc::new(pcap));
                }
                Action::RtpStream { source, video, loops, codec } => {
                    // -rtpcheck_debug's file, as SIPp caches what it plays.
                    if let Some(w) = media::rtp_debug::open(codec.video) {
                        env.log.warning(&w);
                    }
                    // Without an address, held from the start, as SIPp: it
                    // plays once the peer's SDP gives one.
                    let remote = self.media[*video as usize].remote;
                    let held = self.media[*video as usize].held || remote.is_none();
                    let unspecified = if env.cfg.media_ip.is_ipv6() { IpAddr::from([0u16; 8]) } else { IpAddr::from([0u8; 4]) };
                    let remote = remote.unwrap_or(SocketAddr::new(unspecified, 0));
                    let data = match source {
                        StreamSource::Pattern(id) => std::sync::Arc::new(media::pattern(*id, codec).unwrap_or_default()),
                        StreamSource::File(file) => {
                            let name = file.render_line(&self.ctx(env, self.idx));
                            let path = find_file(&name, &env.cfg.scenario_dir, env.log);
                            match media::stream_file(&path, env.log) {
                                Ok(data) => data,
                                Err(e) => {
                                    env.control.fatal = Some(e);
                                    return Ok(());
                                }
                            }
                        }
                    };
                    // startSrtp(): either side plays with its own keys.
                    let file = matches!(source, StreamSource::File(_));
                    if let Some(f) = self.srtpctx.as_deref_mut() {
                        let (name, bytes) = (["AUDIO", "VIDEO"][*video as usize], codec.bytes);
                        f.line(format_args!("Call::action():  TX/RX-{}-{name} SRTP contexts - setting SRTP payload size to {bytes}, deriving session encryption/salting/authentication keys\n", f.role()));
                    }
                    if !file {
                        srtpctx!(self.srtpctx, "Call::action():  mediapool::Cmd::Stream {{ video: {video}, .. }}\n");
                    }
                    self.media_port(env, *video);
                    // A WAV file of no audio plays nothing, as SIPp's
                    // rtpstream_play(): after its port, before the play,
                    // so that a stream playing plays on.
                    if matches!(source, StreamSource::File(_)) && data.is_empty() {
                        return Ok(());
                    }
                    let ssrc = Call::ssrc(env.cfg, self.number, *video);
                    let m = &self.media[*video as usize];
                    let mut stream = Stream::new(data, *loops, *codec, remote, ssrc);
                    stream.held = held;
                    // The keys go with the stream: none of it goes out with others.
                    stream.srtp = m.crypto().tx_context();
                    if media::rtp_debug::on() {
                        stream.rx = m.crypto().rx_context();
                    }
                    let check = match source {
                        StreamSource::Pattern(id) => {
                            let byte = media::pattern(*id, codec).map_or(0, |p| p[0]);
                            Some(mediapool::PatternCheck { rx: m.crypto().rx_context(), id: *id, byte, len: codec.bytes, ok: 0 })
                        }
                        StreamSource::File(_) => None,
                    };
                    self.media_cmd(mediapool::Cmd::Stream { video: *video, stream, check, end: None });
                }
            }
            Ok(())
        })();
        result.err().unwrap_or(ActionResult::Ok)
    }
}

/// SIPp's expand_user_path(): ~ and ~/path from HOME, else USERPROFILE,
/// and ~user/path from the user's entry; the path as it is if neither.
fn expand_user_path(path: &str, log: &mut Log) -> String {
    let Some(rest) = path.strip_prefix('~') else { return path.to_string() };
    if rest.is_empty() || rest.starts_with('/') {
        return std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).map_or(path.to_string(), |h| format!("{h}{rest}"));
    }
    // A user name up to Linux's 32 characters, and a file after it.
    let Some((user, file)) = rest.find('/').filter(|&s| s <= 32).map(|s| rest.split_at(s)) else { return path.to_string() };
    match crate::sys::user_home(user) {
        Some(Ok(home)) => format!("{home}{file}"),
        // No such user: no errno to tell.
        None if cfg!(unix) => {
            log.warning(&format!("Unable to resolve home path for [{path}]"));
            path.to_string()
        }
        Some(Err(e)) => {
            log.warning(&format!("Unable to resolve home path for [{path}], errno = {} ({})", e.raw_os_error().unwrap_or(0), crate::net::os_error(&e)));
            path.to_string()
        }
        None => path.to_string(),
    }
}

/// SIPp's find_file(): a relative media file next to the scenario, else
/// (with a warning) in the current directory.
pub fn find_file(name: &str, dir: &std::path::Path, log: &mut Log) -> String {
    let expanded = expand_user_path(name, log);
    if expanded.starts_with('/') || std::path::Path::new(&expanded).is_absolute() || dir.as_os_str().is_empty() {
        return expanded;
    }
    let next_to = dir.join(&expanded);
    if std::fs::File::open(&next_to).is_ok() {
        return next_to.to_string_lossy().into_owned();
    }
    log.warning(&format!(
        "SIPp now prefers looking for pcap/rtpstream files next to the scenario. {expanded} couldn't be found next to the scenario, falling back to using the current working directory"
    ));
    expanded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::Transport;
    use std::net::UdpSocket;

    /// glibc's tcache takes up to 1032 bytes: a larger Call costs every
    /// call a slower malloc() and free().
    #[test]
    fn a_call_fits_the_tcache() {
        assert!(std::mem::size_of::<Call>() <= 1032, "{}", std::mem::size_of::<Call>());
    }

    #[test]
    fn url_coding_and_strcmp_are_over_the_bytes() {
        let raw = |b: &[u8]| crate::raw::text(b).into_owned();
        assert_eq!(url_encode(&raw(b"Andr\xe9 \xc3\xa9")), "Andr%E9%20%C3%A9");
        assert_eq!(&*crate::raw::bytes(&url_decode("%E9%c3%a9+%ff")), b"\xe9\xc3\xa9 \xff");
        assert_eq!(url_decode("%c3%a9"), "\u{e9}");
        // As glibc's: the bytes are unsigned.
        assert_eq!(c_strcmp(&raw(b"\xff1"), "\u{e9}"), 0xff - 0xc3);
        assert_eq!(c_strcmp(&raw(b"\x80"), "\u{e9}"), 0x80 - 0xc3);
        assert_eq!(c_strcmp(&raw(b"\xc3\xa9"), "\u{e9}"), 0);
    }

    #[test]
    fn user_paths_expand_as_sipp_does() {
        let mut log = Log::default();
        let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap();
        assert_eq!(expand_user_path("~", &mut log), home);
        assert_eq!(expand_user_path("~/a.raw", &mut log), format!("{home}/a.raw"));
        // A user without a file, or with a name over 32 characters, stays.
        assert_eq!(expand_user_path("~root", &mut log), "~root");
        let long = format!("~{}/a.raw", "u".repeat(33));
        assert_eq!(expand_user_path(&long, &mut log), long);
        assert_eq!(expand_user_path("a/~/b", &mut log), "a/~/b");
        if cfg!(unix) {
            let root = crate::sys::user_home("root").unwrap().unwrap();
            assert_eq!(expand_user_path("~root/a.raw", &mut log), format!("{root}/a.raw"));
            assert_eq!(expand_user_path("~nosuchuserx/a.raw", &mut log), "~nosuchuserx/a.raw");
        }
    }

    /// A call on loopback, with a socket standing in for the peer.
    struct Harness {
        scenario: Scenario,
        defaults: Defaults,
        cfg: Config,
        net: Net,
        peer: UdpSocket,
        stats: Stats,
        log: Log,
        control: Control,
        rng: Rng,
        rtp_ports: RtpPorts,
        twin_out: Vec<(Option<String>, String)>,
        inject: Injection,
        verify: Vec<(std::process::Child, String)>,
    }

    impl Harness {
        fn new(xml: &str, client: bool) -> Harness {
            let net = Net::bind(Transport::Udp, "127.0.0.1:0".parse().unwrap(), !client, None, Default::default()).unwrap();
            let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
            peer.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
            let local = net.local_addr().unwrap();
            let scenario = crate::scenario::parse(xml, &HashMap::new(), 8).unwrap();
            Harness {
                stats: Stats::new(&scenario.layout),
                scenario,
                defaults: Defaults::with(Vec::new(), false),
                cfg: Config {
                    local,
                    local_ip: "127.0.0.1".into(),
                    media_ip: IpAddr::from([127, 0, 0, 1]),
                    media_ip_text: "127.0.0.1".into(),
                    service: "svc".into(),
                    media_port: 6000,
                    default_pause: Duration::ZERO,
                    recv_timeout: None,
                    default_behaviors: BEHAVIOR_ALL,
                    auth_user: "svc".into(),
                    auth_pass: "password".into(),
                    auth_uri: None,
                    auto_answer: false,
                    sendbuffer_warn: false,
                    retrans: true,
                    users: None,
                    base_cseq: 0,
                    max_invite_retrans: 5,
                    max_non_invite_retrans: 9,
                    t2: Duration::from_millis(4000),
                    pause_msg_ign: false,
                    lost: 0.0,
                    remote_host: String::new(),
                    rfc3339: false,
                    client,
                    ssrc_base: 0xCA11_0000,
                    rtcheck_loose: false,
                    audio_tolerance: 1.0,
                    video_tolerance: 1.0,
                    scenario_dir: Default::default(),
                    has_media: true,
                    rsa: false,
                    callid_slash_ign: false,
                },
                net,
                peer,
                log: Log::default(),
                control: Control::default(),
                rng: Rng::new(1),
                rtp_ports: RtpPorts::new(40000, 40100),
                twin_out: Vec::new(),
                inject: Injection::default(),
                verify: Vec::new(),
            }
        }

        fn run<R>(&mut self, f: impl FnOnce(&mut Env) -> R) -> R {
            let mut env = Env {
                scenario: &self.scenario,
                defaults: &self.defaults,
                cfg: &self.cfg,
                net: &mut self.net,
                pid: 42,
                stats: &mut self.stats,
                log: &mut self.log,
                control: &mut self.control,
                rng: &mut self.rng,
                rtp_ports: &mut self.rtp_ports,
                twin: &mut self.twin_out,
                inject: &mut self.inject,
                verify: &mut self.verify,
            };
            f(&mut env)
        }

        fn call(&self) -> Call {
            Call::new(1, "1-42@127.0.0.1".into(), Peer { addr: self.peer.local_addr().unwrap(), conn: None })
        }

        fn sent(&self) -> String {
            let mut buf = [0u8; 65536];
            let (n, _) = self.peer.recv_from(&mut buf).expect("nothing was sent");
            String::from_utf8_lossy(&buf[..n]).into_owned()
        }
    }

    const INVITE: &str = "INVITE sip:svc@127.0.0.1 SIP/2.0\r\n\
        Via: SIP/2.0/UDP 127.0.0.2;branch=z9hG4bK-1\r\n\
        From: \"Alice\" <sip:alice@a>;tag=f1\r\n\
        To: <sip:svc@b>\r\n\
        Call-ID: 1-42@127.0.0.1\r\n\
        CSeq: 7 INVITE\r\n\
        Record-Route: <sip:p1;lr>, <sip:p2;lr>\r\n\
        Contact: <sip:alice@10.0.0.9>\r\n\
        Content-Length: 0\r\n\r\n";

    #[test]
    fn uas_flow_with_ereg_next_and_route_set() {
        let mut h = Harness::new(r#"<scenario>
            <recv request="INVITE" rrs="true" next="answer" test="who">
              <action><ereg regexp="&lt;sip:([a-z]+)@" search_in="hdr" header="From:" assign_to="_,who"/></action>
            </recv>
            <send><![CDATA[SIP/2.0 486 Busy]]></send>
            <label id="answer"/>
            <send><![CDATA[
              SIP/2.0 200 OK
              [last_Via:]
              X-Who: [$who] cseq=[cseq]
              Content-Length: [len]
            ]]></send>
            <recv request="ACK"/>
            <send><![CDATA[
              BYE [next_url] SIP/2.0
              [routes]
              CSeq: [cseq] BYE
            ]]></send>
          </scenario>"#, false);
        let mut call = h.call();
        assert_eq!(h.run(|env| call.on_message(env, INVITE)), Outcome::Running);
        let ok = h.sent();
        assert!(ok.starts_with("SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 127.0.0.2;branch=z9hG4bK-1\r\n"), "{ok}");
        assert!(ok.contains("X-Who: alice cseq=7\r\n"), "{ok}");

        let ack = INVITE.replace("INVITE sip", "ACK sip").replace("7 INVITE", "7 ACK");
        assert_eq!(h.run(|env| call.on_message(env, ack.as_str())), Outcome::Success);
        let bye = h.sent();
        // A request's Record-Route keeps its order; the target is the Contact.
        assert!(bye.starts_with("BYE sip:alice@10.0.0.9 SIP/2.0\r\nRoute: <sip:p1;lr>, <sip:p2;lr>\r\nCSeq: 8 BYE\r\n"), "{bye}");
    }

    #[test]
    fn global_recv_is_taken_after_the_call_moved_past_it() {
        let mut h = Harness::new(r#"<scenario>
            <recv request="INFO" optional="global" next="info"/>
            <recv request="INVITE"/>
            <send><![CDATA[
              SIP/2.0 200 OK
              [last_Via:]
              CSeq: [cseq] INVITE
            ]]></send>
            <label id="wait"/>
            <recv request="ACK"/>
            <recv request="BYE"/>
            <nop next="end"/>
            <label id="info"/>
            <send><![CDATA[
              SIP/2.0 200 OK
              [last_Via:]
              CSeq: [cseq] INFO
            ]]></send>
            <nop next="wait"/>
            <label id="end"/>
          </scenario>"#, false);
        let mut call = h.call();
        assert_eq!(h.run(|env| call.on_message(env, INVITE)), Outcome::Running);
        assert!(h.sent().contains("CSeq: 7 INVITE"));
        // Waiting for the ACK, well past the INFO's <recv>.
        let info = INVITE.replace("INVITE sip", "INFO sip").replace("7 INVITE", "8 INFO");
        assert_eq!(h.run(|env| call.on_message(env, info.as_str())), Outcome::Running);
        assert!(h.sent().contains("CSeq: 8 INFO"));
        assert_eq!(h.stats.unexpected, 0);
        let ack = INVITE.replace("INVITE sip", "ACK sip").replace("7 INVITE", "7 ACK");
        assert_eq!(h.run(|env| call.on_message(env, ack.as_str())), Outcome::Running);
        let bye = INVITE.replace("INVITE sip", "BYE sip").replace("7 INVITE", "9 BYE");
        assert_eq!(h.run(|env| call.on_message(env, bye.as_str())), Outcome::Success);
    }

    #[test]
    fn unexpected_response_to_a_pending_invite_cancels_it() {
        let mut h = Harness::new(r#"<scenario>
            <send><![CDATA[
              INVITE sip:svc@[remote_ip] SIP/2.0
              Via: SIP/2.0/UDP [local_ip];branch=[branch]
              To: <sip:svc@[remote_ip]>
              Call-ID: [call_id]
              CSeq: [cseq] INVITE
            ]]></send>
            <recv response="200"/>
          </scenario>"#, true);
        let mut call = h.call();
        assert_eq!(h.run(|env| call.advance(env)), Outcome::Running);
        assert!(h.sent().contains("CSeq: 1 INVITE"));

        let ringing = "SIP/2.0 183 Session Progress\r\nVia: SIP/2.0/UDP x;branch=b\r\nTo: <sip:svc@h>;tag=t\r\nCall-ID: 1-42@127.0.0.1\r\nCSeq: 1 INVITE\r\n\r\n";
        assert_eq!(h.run(|env| call.on_message(env, ringing)), Outcome::Failed);
        let cancel = h.sent();
        assert!(cancel.starts_with("CANCEL sip:svc@h SIP/2.0\r\n"), "{cancel}");
        assert!(cancel.contains("CSeq: 1 CANCEL\r\n"), "{cancel}");
        assert_eq!(h.stats.unexpected, 1);
        // process_unexpected()'s words, with the whole message.
        let w = h.log.last_warning.clone().unwrap();
        let text = format!("Aborting call on unexpected message for Call-Id '1-42@127.0.0.1': while expecting '200' (index 1), received '{ringing}'");
        assert!(w.ends_with(&text), "{w}");
        assert_eq!(call.dead.as_deref(), Some("aborted at index 1"));
        assert_eq!(call.aborted_with, Some("CANCEL"));
    }

    #[test]
    fn aborting_bye_has_a_branch_of_its_own() {
        let mut h = Harness::new(r#"<scenario>
            <send><![CDATA[
              MESSAGE sip:svc@[remote_ip] SIP/2.0
              Via: SIP/2.0/UDP [local_ip];branch=[branch]
              To: <sip:svc@[remote_ip]>
              Call-ID: [call_id]
              CSeq: [cseq] MESSAGE
            ]]></send>
            <recv response="200"/>
            <pause milliseconds="1000"/>
          </scenario>"#, true);
        let mut call = h.call();
        assert_eq!(h.run(|env| call.advance(env)), Outcome::Running);
        h.sent();
        let ok = "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP x;branch=b\r\nTo: <sip:svc@h>;tag=t\r\nCall-ID: 1-42@127.0.0.1\r\nCSeq: 1 MESSAGE\r\n\r\n";
        assert_eq!(h.run(|env| call.on_message(env, ok)), Outcome::Running);
        let again = ok.replace("CSeq: 1", "CSeq: 2");
        assert_eq!(h.run(|env| call.on_message(env, again.as_str())), Outcome::Failed);
        let w = h.log.last_warning.clone().unwrap();
        assert!(w.contains("': while pausing (index 2), received 'SIP/2.0 200 OK\r\n"), "{w}");
        let bye = h.sent();
        // Not that of the MESSAGE, index 0, nor of the step before, 1:
        // that of index 3, past the last step.
        assert!(bye.starts_with("BYE ") && bye.contains(";branch=z9hG4bK-42-1-3\r\n"), "{bye}");
        assert_eq!(call.aborted_with, Some("BYE"));
    }

    #[test]
    fn an_abort_leaves_the_dialog_the_call_created() {
        // A 3PCC controller B takes a command first, like a server, but it
        // sends the INVITE: its abort sends the BYE. A UAS's doesn't.
        let b = r#"<scenario>
            <recvCmd/>
            <send><![CDATA[
              INVITE sip:svc@[remote_ip] SIP/2.0
              Via: SIP/2.0/UDP [local_ip];branch=[branch]
              To: <sip:svc@[remote_ip]>
              Call-ID: [call_id]
              CSeq: [cseq] INVITE
            ]]></send>
            <recv response="200"/>
            <send><![CDATA[
              ACK sip:svc@[remote_ip] SIP/2.0
              Via: SIP/2.0/UDP [local_ip];branch=[branch]
              To: <sip:svc@[remote_ip]>[peer_tag_param]
              Call-ID: [call_id]
              CSeq: [cseq] ACK
            ]]></send>
            <recv request="INFO"/>
          </scenario>"#;
        let mut h = Harness::new(b, false);
        let mut call = h.call();
        assert_eq!(h.run(|env| call.on_command(env, "Call-ID: 1-42@127.0.0.1\r\n\r\n")), Outcome::Running);
        assert!(h.sent().starts_with("INVITE "));
        let ok = "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP x;branch=b\r\nTo: <sip:svc@h>;tag=t\r\nCall-ID: 1-42@127.0.0.1\r\nCSeq: 1 INVITE\r\n\r\n";
        assert_eq!(h.run(|env| call.on_message(env, ok)), Outcome::Running);
        assert!(h.sent().starts_with("ACK "));
        h.run(|env| call.abort_now(env));
        assert!(h.sent().starts_with("BYE "));
        assert_eq!(call.aborted_with, Some("BYE"));

        let uas = r#"<scenario>
            <recv request="INVITE"/>
            <send><![CDATA[
              SIP/2.0 200 OK
              [last_Via:]
              [last_To:];tag=u
              [last_CSeq:]
            ]]></send>
            <recv request="ACK"/>
            <recv request="INFO"/>
          </scenario>"#;
        let mut h = Harness::new(uas, true);
        let mut call = h.call();
        assert_eq!(h.run(|env| call.on_message(env, INVITE)), Outcome::Running);
        h.sent();
        let ack = INVITE.replace("INVITE sip", "ACK sip").replace("7 INVITE", "7 ACK");
        assert_eq!(h.run(|env| call.on_message(env, ack.as_str())), Outcome::Running);
        h.run(|env| call.abort_now(env));
        assert_eq!(call.aborted_with, None);
        assert!(h.peer.recv_from(&mut [0u8; 1024]).is_err(), "the UAS sent something");
    }

    #[test]
    fn default_messages_and_the_twins_abort() {
        let xml = r#"<scenario>
            <DefaultMessage id="bye"><![CDATA[
              BYE sip:[remote_ip] SIP/2.0
              X-Mine: [$v]
              Content-Length: 4

              body
            ]]></DefaultMessage>
            <DefaultMessage id="3pcc_abort"><![CDATA[call-id: [call_id]
              internal-cmd: abort_call]]></DefaultMessage>
            <send><![CDATA[
              MESSAGE sip:svc@[remote_ip] SIP/2.0
              Call-ID: [call_id]
              CSeq: [cseq] MESSAGE
            ]]></send>
            <recv response="200"/>
            <recvCmd/>
          </scenario>"#;
        let mut h = Harness::new(xml, true);
        h.defaults = Defaults::with(std::mem::take(&mut h.scenario.default_messages), true);
        let mut call = h.call();
        call.vars.set_string("v", "x");
        assert_eq!(h.run(|env| call.advance(env)), Outcome::Running);
        h.sent();
        let ok = "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP x;branch=b\r\nTo: <sip:svc@h>;tag=t\r\nCall-ID: 1-42@127.0.0.1\r\nCSeq: 1 MESSAGE\r\n\r\n";
        assert_eq!(h.run(|env| call.on_message(env, ok)), Outcome::Running);
        // Unexpected: the twin's call is aborted, then ours, with our BYE,
        // whose body gets no CRLF after it.
        let info = "INFO sip:x SIP/2.0\r\nCall-ID: 1-42@127.0.0.1\r\nCSeq: 7 INFO\r\n\r\n";
        assert_eq!(h.run(|env| call.on_message(env, info)), Outcome::Failed);
        assert_eq!(h.twin_out, [(None, "call-id: 1-42@127.0.0.1\r\ninternal-cmd: abort_call\r\n\r\n".to_string())]);
        assert_eq!(h.sent(), "BYE sip:127.0.0.1 SIP/2.0\r\nX-Mine: x\r\nContent-Length: 4\r\n\r\nbody");

        // The twin's abort_call aborts the call, which leaves its dialog.
        let mut call = h.call();
        assert_eq!(h.run(|env| call.advance(env)), Outcome::Running);
        h.sent();
        assert_eq!(h.run(|env| call.on_message(env, ok)), Outcome::Running);
        assert_eq!(h.run(|env| call.on_command(env, "call-id: 1-42@127.0.0.1\r\ninternal-cmd: abort_call\r\n\r\n")), Outcome::Failed);
        assert!(h.sent().starts_with("BYE sip:127.0.0.1 SIP/2.0\r\n"));
        assert_eq!(call.dead.as_deref(), Some("aborted at index 2"));
        assert_eq!((internal_cmd("internal-cmd: \tabort_call\r\n"), internal_cmd("internal-cmd: abort_call")), (Some("abort_call"), None));
    }

    #[test]
    fn failed_checks_are_warned_about_in_sipps_words() {
        assert_eq!((c_strcmp("abc", "abz"), c_strcmp("abc", "ab"), c_strcmp("", "a"), c_strcmp("x", "x")), (-23, 99, -97, 0));
        let mut h = Harness::new(r#"<scenario>
            <recv request="INVITE">
              <action>
                <assign assign_to="n" value="3.5"/>
                <test assign_to="t" variable="n" compare="greater_than" value="5" check_it="true"/>
              </action>
            </recv>
          </scenario>"#, false);
        let mut call = h.call();
        assert_eq!(h.run(|env| call.on_message(env, INVITE)), Outcome::Failed);
        let w = h.log.last_warning.clone().unwrap();
        assert!(w.ends_with(": test \"n:3.500000 > :5.000000\" with check_it failed"), "{w}");
    }

    #[test]
    fn exec_verify_holds_the_next_step_and_fails_the_call() {
        let mut h = Harness::new(r#"<scenario>
            <nop><action><exec verify="exit 3"/></action></nop>
            <nop><action><exec verify="exit 0"/></action></nop>
          </scenario>"#, true);
        let mut call = h.call();
        // The second <nop> waits for the first command.
        assert_eq!(h.run(|env| call.advance(env)), Outcome::Running);
        assert_eq!((call.idx, call.verify_pending, h.verify.len()), (1, 1, 1));
        let (mut child, cmd) = h.verify.remove(0);
        let status = child.wait().unwrap();
        assert_eq!(h.run(|env| call.verify_done(env, &cmd, status)), Outcome::Running);
        let w = h.log.last_warning.clone().unwrap();
        assert!(w.ends_with("Call-Id: 1-42@127.0.0.1, 'exit 3' returned 3"), "{w}");
        // Past its last step, the call waits for the second one, and takes
        // no more messages.
        assert_eq!((call.idx, call.verify_pending, h.verify.len()), (2, 1, 1));
        assert_eq!(h.run(|env| call.on_message(env, INVITE)), Outcome::Running);
        assert_eq!(h.stats.unexpected, 0);
        let (mut child, cmd) = h.verify.remove(0);
        let status = child.wait().unwrap();
        // Failed, with no failure counter of its own.
        assert_eq!(h.run(|env| call.verify_done(env, &cmd, status)), Outcome::Failed);
        assert_eq!((call.fail, call.dead.as_deref()), (None, Some("exec verify failure at index 2")));
    }

    #[test]
    fn every_steps_actions_count_like_a_recvs() {
        // A failed check on a <send>, <pause> or <nop> fails the call at
        // its end; stop_call on any of them ends it at once.
        let send = r#"<send><![CDATA[
              MESSAGE sip:svc@[remote_ip] SIP/2.0
              Call-ID: [call_id]
              CSeq: [cseq] MESSAGE
            ]]>ACTION</send>"#;
        let check = r#"<action><assignstr assign_to="v" value="a"/><strcmp variable="v" value="b" check_it="true"/></action>"#;
        let stop = r#"<action><exec int_cmd="stop_call"/></action>"#;
        for (steps, outcome, idx) in [
            (send.replace("ACTION", check), Outcome::Failed, 1),
            (format!("{}<pause milliseconds=\"0\">{check}</pause>", send.replace("ACTION", "")), Outcome::Failed, 2),
            (format!("{}<nop>{check}</nop>", send.replace("ACTION", "")), Outcome::Failed, 2),
            (format!("{}<pause milliseconds=\"0\">{stop}</pause><nop/>", send.replace("ACTION", "")), Outcome::Failed, 1),
            (format!("{}<nop>{stop}</nop><nop/>", send.replace("ACTION", "")), Outcome::Failed, 1),
            (send.replace("ACTION", stop) + "<nop/>", Outcome::Failed, 0),
            (send.replace("ACTION", ""), Outcome::Success, 1),
        ] {
            let mut h = Harness::new(&format!("<scenario>{steps}</scenario>"), true);
            let mut call = h.call();
            assert_eq!(h.run(|env| call.advance(env)), outcome, "{steps}");
            assert_eq!(call.idx, idx, "{steps}");
            h.sent();
        }
    }

    #[test]
    fn a_command_before_the_reply_waits_for_its_recvcmd() {
        let xml = r#"<scenario>
            <send><![CDATA[
              OPTIONS sip:svc@[remote_ip] SIP/2.0
              Call-ID: [call_id]
              CSeq: [cseq] OPTIONS
            ]]></send>
            <sendCmd><![CDATA[Call-ID: [call_id]]]></sendCmd>
            <recv response="200"/>
            <recvCmd/>
          </scenario>"#;
        let ok = "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP x;branch=b\r\nTo: <sip:svc@h>;tag=t\r\nCall-ID: 1-42@127.0.0.1\r\nCSeq: 1 OPTIONS\r\n\r\n";
        let cmd = "Call-ID: 1-42@127.0.0.1\r\n\r\n";
        let mut h = Harness::new(xml, true);
        let mut call = h.call();
        assert_eq!(h.run(|env| call.advance(env)), Outcome::Running);
        h.sent();
        assert_eq!(h.run(|env| call.on_command(env, cmd)), Outcome::Running);
        assert_eq!(call.idx, 2);
        assert_eq!(h.run(|env| call.on_message(env, ok)), Outcome::Success);
        assert_eq!(h.stats.steps[3].cmds, 1);

        // Not with a <sendCmd> between: that command was not an answer.
        let mut h = Harness::new(&xml.replace("<recvCmd/>", "<sendCmd><![CDATA[Call-ID: [call_id]]]></sendCmd><recvCmd/>"), true);
        let mut call = h.call();
        assert_eq!(h.run(|env| call.advance(env)), Outcome::Running);
        h.sent();
        assert_eq!(h.run(|env| call.on_command(env, cmd)), Outcome::Failed);
    }

    #[test]
    fn an_unexpected_bye_or_cancel_is_worded_alike() {
        for m in ["BYE", "CANCEL"] {
            let mut h = Harness::new(r#"<scenario><recv request="INVITE"/><recv request="ACK"/></scenario>"#, false);
            h.cfg.default_behaviors = BEHAVIOR_ALL & !BEHAVIOR_ABORTUNEXP;
            let mut call = h.call();
            assert_eq!(h.run(|env| call.on_message(env, INVITE)), Outcome::Running);
            let req = INVITE.replace("INVITE sip", &format!("{m} sip")).replace("7 INVITE", &format!("7 {m}"));
            assert_eq!(h.run(|env| call.on_message(env, req.as_str())), Outcome::Running);
            let w = h.log.last_warning.clone().unwrap();
            assert!(w.ends_with(&format!(": Continuing call on an unexpected {m} for call: 1-42@127.0.0.1")), "{w}");
        }
    }

    /// A UAC's INVITE with an SDP offer, then `rest`.
    fn offering_uac(rest: &str) -> String {
        format!(
            r#"<scenario>
            <send><![CDATA[
              INVITE sip:svc@[remote_ip] SIP/2.0
              Via: SIP/2.0/UDP [local_ip];branch=[branch]
              To: <sip:svc@[remote_ip]>
              Call-ID: [call_id]
              CSeq: 1 INVITE
              Content-Type: application/sdp
              Content-Length: [len]

              v=0
              c=IN IP4 127.0.0.1
              m=audio 6000 RTP/AVP 0
            ]]></send>
            {rest}
          </scenario>"#
        )
    }

    const ANSWER: &str = "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP x;branch=b\r\nTo: <sip:svc@h>;tag=t\r\nCall-ID: 1-42@127.0.0.1\r\n\
        CSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: 49\r\n\r\nv=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 7000 RTP/AVP 0\r\n";

    #[test]
    fn an_unexpected_message_gives_its_sdp() {
        // SIPp takes the SDP before it looks for the step the message
        // matches: where the media go, and the offer/answer state.
        let mut h = Harness::new(&offering_uac(r#"<recv response="183"/>"#), true);
        h.cfg.has_media = true;
        let mut call = h.call();
        assert_eq!(h.run(|env| call.advance(env)), Outcome::Running);
        assert_eq!(call.sdp, SdpState::OfferSent);
        assert_eq!(h.run(|env| call.on_message(env, ANSWER)), Outcome::Failed);
        assert_eq!(h.stats.unexpected, 1);
        assert_eq!(call.sdp, SdpState::Completed);
        assert_eq!(call.pcap.as_ref().and_then(|p| p.to[0]), Some("192.0.2.1:7000".parse().unwrap()));
    }

    #[test]
    fn unexp_main_takes_the_sdp_once() {
        // Not again when the handler's <recv> gets it: the answer is not
        // a new offer.
        let xml = offering_uac(r#"<recv response="183"/><label id="_unexp.main"/><recv response="200"/>"#);
        let mut h = Harness::new(&xml, true);
        h.cfg.has_media = true;
        let mut call = h.call();
        assert_eq!(h.run(|env| call.advance(env)), Outcome::Running);
        assert_eq!(h.run(|env| call.on_message(env, ANSWER)), Outcome::Success);
        assert_eq!(call.sdp, SdpState::Completed);
    }

    #[test]
    fn unexpected_names_the_step_as_sipp_does() {
        let s = crate::scenario::parse(r#"<scenario>
            <recv request="INV.*" regexp_match="true"/>
            <send><![CDATA[SIP/2.0 200 OK]]></send>
            <pause milliseconds="10"/>
            <nop/>
            <recv request="ACK"/>
            <timewait milliseconds="10"/>
          </scenario>"#, &HashMap::new(), 8).unwrap();
        let words: Vec<String> = (0..7).map(|i| while_at(s.steps.get(i).map(|s| &s.op))).collect();
        assert_eq!(
            words,
            ["while expecting 'INV.*' ", "while sending ", "while pausing ", "while in message type 5 ", "while expecting 'ACK' ", "while pausing ", "while in message type 5 "]
        );
    }

    #[test]
    fn dead_call_reasons_follow_how_the_call_ended() {
        let xml = r#"<scenario>
            <recv request="INVITE">
              <action><ereg regexp="nothing-like-it" search_in="msg" check_it="true" assign_to="x"/></action>
            </recv>
            <send><![CDATA[SIP/2.0 200 OK]]></send>
          </scenario>"#;
        let mut h = Harness::new(xml, false);
        let mut call = h.call();
        assert_eq!(h.run(|env| call.on_message(env, INVITE)), Outcome::Failed);
        assert_eq!(call.dead.as_deref(), Some("regexp match failure at index 2"));

        let mut h = Harness::new(&xml.replace(" check_it=\"true\"", ""), false);
        let mut call = h.call();
        assert_eq!(h.run(|env| call.on_message(env, INVITE)), Outcome::Success);
        assert_eq!(call.dead.as_deref(), Some("successful"));

        // An unexpected BYE is answered and the call deleted: no dead call.
        let mut h = Harness::new(xml, false);
        let mut call = h.call();
        let bye = INVITE.replace("INVITE sip", "BYE sip").replace("7 INVITE", "8 BYE");
        assert_eq!(h.run(|env| call.on_message(env, bye.as_str())), Outcome::Failed);
        assert_eq!(call.dead, None);
    }

    #[test]
    fn header_search_finds_the_header_or_the_text() {
        // C 7299032: a header name starts a line; other text is anywhere.
        let msg = "INVITE sip:x SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9\r\nFrom: <sip:a>;tag=1\r\nX-From: nope\r\nTopic: none\r\nTo: <sip:b>\r\n\r\n";
        assert_eq!(header_text(msg, "From", false, 1, false), Some(": <sip:a>;tag=1"));
        assert_eq!(header_text(msg, "From:", false, 2, false), None);
        assert_eq!(header_text(msg, "X-From:", false, 1, false), Some(" nope"));
        assert_eq!(header_text(msg, "To", false, 1, false), Some(": <sip:b>"));
        assert_eq!(header_text(msg, "to:", false, 1, true), Some(" <sip:b>"));
        assert_eq!(header_text(msg, "Topic: no", false, 1, false), Some("ne"));
        assert_eq!(header_text(msg, "tag=", false, 1, false), Some("1"));
        assert_eq!(header_text(msg, "BRANCH=", false, 1, true), Some("z9"));
        assert_eq!(header_text(msg, "tag=", true, 1, false), None);
    }
}

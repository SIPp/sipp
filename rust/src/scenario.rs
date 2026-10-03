//! Scenario XML: the subset of SIPp's format the engine can run.

use crate::dist::Dist;
use crate::log::Log;
use crate::media::{self, Codec};
use crate::pcap::{Pcap, PcapMedia};
use crate::template::Template;
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use crate::posix::Regex;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

#[derive(Debug)]
pub enum Expect {
    Response(u16),
    Request(String),
    /// regexp_match="true": the code as text, or the method, matched anywhere.
    ResponseRe(Regex),
    RequestRe(Regex),
    /// Neither request= nor response=, which SIPp takes: nothing matches.
    Nothing,
}

#[derive(Debug)]
pub enum Op {
    Send {
        msg: Template,
        retrans_ms: Option<u64>,
        start_txn: Option<String>,
        /// ack_txn=: the ACK of that transaction, which SIPp sends again
        /// for a late final response to it.
        ack_txn: Option<String>,
        /// response_txn=: a response to the request received with that
        /// start_txn=, whose headers its [last_*] keywords take.
        response_txn: Option<String>,
        /// dialog=: the call's dialog it is in, 0 if not given.
        dialog: usize,
        /// Where the call goes when the retransmissions run out.
        ontimeout: Option<usize>,
    },
    Recv {
        expect: Expect,
        optional: bool,
        /// optional="global": taken whenever it comes, however far the call
        /// has gone past it.
        global: bool,
        response_txn: Option<String>,
        /// start_txn=: a request kept for the responses sent with that
        /// response_txn=.
        start_txn: Option<String>,
        /// dialog=: the call's dialog it is in, 0 if not given.
        dialog: usize,
        rrs: bool,
        /// auth="true": a 401/407 here is the challenge for [authentication].
        auth: bool,
        /// advance_state="false": an optional message that neither moves
        /// the call on nor becomes its last received one.
        advance_state: bool,
        timeout_ms: Option<u64>,
        /// timeout_variable=: the variable the timeout is read from, in ms,
        /// each time the call gets here.
        timeout_var: Option<String>,
        ontimeout: Option<usize>,
        /// Methods of the requests sent before this recv, glued together as
        /// SIPp does: a response must answer one of them.
        methods: String,
        /// response= with request=: the request matches, and the screen
        /// and -trace_counts show this, as SIPp's.
        shown: Option<String>,
    },
    Pause(PauseLen),
    Nop,
    /// 3PCC: a command to the twin SIPp, and waiting for one from it.
    /// dest=: the 3PCC extended mode peer it goes to.
    SendCmd { msg: Template, dest: Option<String> },
    /// src=: the extended mode peer it must come from; optional=: a SIP
    /// message may be matched past it.
    RecvCmd { src: Option<String>, optional: bool },
    /// End of the call; retransmissions are still answered for this long.
    Timewait(PauseLen),
}

#[derive(Debug)]
pub enum Source {
    Msg,
    Body,
    Hdr { header: String, start_line: bool, occurrence: usize, case_indep: bool },
    Var(String),
}

#[derive(Debug)]
pub enum Operand {
    Value(String),
    Var(String),
}

#[derive(Debug, Clone, Copy)]
pub enum Compare {
    Equal,
    NotEqual,
    Greater,
    Less,
    GreaterEqual,
    LessEqual,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Stop {
    Now,
    Gracefully,
    Call,
}

#[derive(Debug)]
pub struct Check {
    pub check_it: bool,
    pub inverse: bool,
}

#[derive(Debug)]
pub enum Action {
    Ereg { re: Regex, source: Source, check: Check, assign_to: Vec<String> },
    Strcmp { assign_to: Option<String>, var: String, rhs: Operand, check: Check },
    Test { assign_to: Option<String>, var: String, compare: Compare, rhs: Operand, check: Check },
    Assign { var: String, value: Num },
    Arith { op: Arith, var: String, rhs: Num },
    /// <index>: the step's own index.
    Index(String),
    GetTimeOfDay { sec: String, usec: String },
    /// <jump>: on to the step with this index.
    Jump(Num),
    Sample { var: String, dist: Dist },
    /// <todouble>: a string or match read as a number.
    ToDouble { to: String, from: String },
    Str { op: StrOp, var: String },
    /// <error>: fatal, as SIPp's ERROR().
    Error(Template),
    /// <lookup>: the line of an -infindex'd file with this key.
    Lookup { var: String, file: Template, key: Template },
    /// <insert> and <replace>: change an injection file's lines.
    Insert { file: Template, value: Template },
    Replace { file: Template, line: Template, value: Template },
    /// <setdest>: send the rest of the call elsewhere.
    SetDest { host: Template, port: Template, protocol: Template },
    /// <closecon>: close the call's connection.
    CloseCon,
    /// <pauserestore>: resume a pause saved in $_unexp.pausedaddr.
    PauseRestore(Num),
    /// <assignstr>: the value is expanded like a message.
    AssignStr { var: String, value: Template },
    Warning(Template),
    Log(Template),
    Exec(Template),
    /// <exec lua="function arg ...">: a function of the -lua_file.
    Lua(Template),
    /// <exec verify>: a command the call waits for before its next
    /// message, which fails the call unless it exits with 0.
    Verify(Template),
    Stop(Stop),
    /// <exec rtp_stream="file,loops,payload,codec"> or "apattern,id,payload,codec"
    RtpStream { source: StreamSource, video: bool, loops: i64, codec: Codec },
    RtpPause { video: bool },
    RtpResume { video: bool },
    /// <exec rtp_stream="wait" timeout=>: the next step waits until the
    /// call's rtp_stream has played, at most this long (0: for ever).
    RtpWait { timeout_ms: u64 },
    /// <exec rtp_echo="start|update|stop{audio,video},...">: echo this call's
    /// SRTP back, decrypted with the peer's key and encrypted with ours.
    /// Its payload's bytes per packet, as setRTPEchoActInfo() makes them,
    /// for -srtpcheck_debug's log.
    MediaEcho { video: bool, on: bool, update: bool, bytes: i32 },
    /// <rtp_echo value>: turns -rtp_echo off (0) and on again.
    RtpEcho(bool),
    /// An <exec rtp_echo> of no action SIPp knows: an error as it runs.
    Unknown,
    /// <rtp_stats assign_to="packets[,pt[,payload]]" media=>: the RTP
    /// packets the call's audio (or video) port received, and the payload
    /// type and payload (in hex) of the first.
    RtpStats { video: bool, vars: Vec<String> },
    /// <rtp_dtmf assign_to payload_type=>: the digits of the RFC 4733
    /// events of this payload type the call's audio port received.
    RtpDtmf { var: String, payload_type: u8 },
    /// <verifyauth>: do the received credentials match?
    VerifyAuth { assign_to: String, user: Template, pass: Template },
    /// <exec play_pcap_audio|image|video|text="file">: replay
    /// a capture's UDP packets to the peer's media port of that kind. The
    /// capture is read before the run starts (load_pcaps).
    PlayPcap { kind: PcapMedia, file: String, pcap: Option<Arc<Pcap>> },
    /// <exec play_dtmf="digits[,tone ms[,payload type]]">: RFC 2833 events
    /// on the audio stream.
    PlayDtmf(Template),
}

/// How long a <pause> lasts, in ms.
#[derive(Debug)]
pub enum PauseLen {
    /// The -d default.
    Default,
    Dist(Dist),
    /// variable=: the value of a call variable.
    Var(String),
}

/// A number from the scenario or from a call variable (value= or variable=).
#[derive(Debug, Clone)]
pub enum Num {
    Value(f64),
    Var(String),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Arith {
    Add,
    Subtract,
    Multiply,
    Divide,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StrOp {
    Trim,
    UrlEncode,
    UrlDecode,
}

#[derive(Debug)]
pub enum StreamSource {
    File(Template),
    /// apattern/vpattern N: a constant payload the peer echoes back.
    Pattern(u8),
}

#[derive(Debug)]
pub struct Step {
    pub op: Op,
    pub actions: Vec<Action>,
    pub next: Option<usize>,
    pub test: Option<String>,
    /// Probability of taking `next`.
    pub chance: f64,
    /// Run the step only if this variable is set (or unset, when true).
    pub condexec: Option<(String, bool)>,
    /// lost=: the percentage of this message to drop, over -lost's.
    pub lost: Option<f64>,
    /// start_rtd= and rtd=: the response times this step starts and ends
    /// (indexes into the scenario's stat layout, comma-separated names);
    /// repeat_rtd= lets it end one more than once; counter= a generic
    /// counter it increments.
    pub start_rtd: Vec<usize>,
    pub stop_rtd: Vec<usize>,
    pub repeat_rtd: bool,
    pub counter: Option<usize>,
    /// The screen's: a blank line after the step, the step hidden, and a
    /// <nop>'s text.
    pub crlf: bool,
    pub hide: bool,
    pub display: Option<String>,
    /// ignoresdp=: a message received while the call is here leaves the
    /// media alone.
    pub ignoresdp: bool,
    /// ontimeout=, on any step: where an rtp_stream wait that times out in
    /// its actions goes.
    pub ontimeout: Option<usize>,
}

#[derive(Debug)]
pub struct Scenario {
    pub name: String,
    pub steps: Vec<Step>,
    /// The _unexp.main label: where an unexpected message sends the call.
    pub unexpected_jump: Option<usize>,
    /// Whether $_unexp.retaddr and $_unexp.pausedaddr are used, which
    /// SIPp only sets then (and only then guards against a second jump).
    pub uses_retaddr: bool,
    pub uses_pausedaddr: bool,
    /// What the statistics count: RTDs, counters, repartitions.
    pub layout: crate::stat::Layout,
    /// <Global variables="..."/> and <User variables="..."/>.
    pub global_vars: std::collections::HashSet<String>,
    pub user_vars: std::collections::HashSet<String>,
    /// <init>: steps (nops) run once, before any call.
    pub init: Option<Box<Scenario>>,
    /// <DefaultMessage id>: SIPp's own messages the scenario replaces,
    /// in its order (for the whole run, as in SIPp).
    pub default_messages: Vec<(String, Template)>,
    /// A message has dialog="N" with N > 1, and a <recv request> does:
    /// a request of a Call-ID no call has may start a dialog of a call.
    pub dialogs: bool,
    pub new_dialogs: bool,
    /// The variables the scenario names, for the <exec lua> ones to be
    /// told if a name is one (empty without such an action).
    pub var_names: std::collections::HashSet<String>,
}

impl Scenario {
    /// SIPp's hasMedia: a play_pcap_*, play_dtmf, rtp_stream or rtp_echo
    /// action, <init>'s too.
    pub fn has_media(&self) -> bool {
        self.steps.iter().flat_map(|s| &s.actions).any(|a| {
            matches!(
                a,
                Action::RtpStream { .. } | Action::RtpPause { .. } | Action::RtpResume { .. } | Action::RtpWait { .. } | Action::MediaEcho { .. } | Action::Unknown | Action::PlayPcap { .. } | Action::PlayDtmf(_)
            )
        }) || self.init.as_ref().is_some_and(|i| i.has_media())
    }

    /// SIPp's rtp_stats_used: an <rtp_stats> or <rtp_dtmf>, <init>'s too,
    /// with the payload types of the <rtp_dtmf>s (rtp_dtmf_payload_types,
    /// bit n for type n).
    pub fn counts_received(&self) -> Option<u128> {
        let mut used = self.init.as_ref().and_then(|i| i.counts_received());
        for a in self.steps.iter().flat_map(|s| &s.actions) {
            match a {
                Action::RtpStats { .. } => {
                    used.get_or_insert(0);
                }
                Action::RtpDtmf { payload_type, .. } => *used.get_or_insert(0) |= 1 << payload_type,
                _ => {}
            }
        }
        used
    }

    /// Reads every play_pcap_* capture, as SIPp does when it loads the
    /// scenario: relative names next to the scenario first. An rtp_stream
    /// file without keywords must be readable too.
    pub fn load_pcaps(&mut self, dir: &std::path::Path, log: &mut Log) -> Result<(), String> {
        let mut loaded: HashMap<String, Arc<Pcap>> = HashMap::new();
        for action in self.steps.iter_mut().flat_map(|s| s.actions.iter_mut()) {
            if let Action::RtpStream { source: StreamSource::File(file), codec, .. } = action {
                if !file.source.contains('[') {
                    // -rtpcheck_debug's file of the stream's kind, as SIPp
                    // caches the file; a pattern's opens as it plays.
                    if let Some(w) = crate::media::rtp_debug::open(codec.video) {
                        log.warning(&w);
                    }
                    let path = crate::call::find_file(&file.source, dir, log);
                    crate::media::stream_file(&path, log)?;
                }
            }
            if let Action::PlayPcap { file, pcap, .. } = action {
                let path = crate::call::find_file(file, dir, log);
                if !loaded.contains_key(&path) {
                    loaded.insert(path.clone(), Arc::new(crate::pcap::load(&path)?));
                }
                *pcap = loaded.get(&path).cloned();
            }
        }
        Ok(())
    }
}

/// What SIPp checks a scenario against as it loads it (parse_checked()).
#[derive(Debug, Default)]
pub struct Checks {
    /// The -inf and -rxinf files by base name, and the first -inf: the
    /// ones a [fieldN] may read.
    pub inject: (Vec<String>, Option<String>),
    /// The scenario's file, for SIPp's XML error (None: a built-in one).
    pub file: Option<String>,
    /// The -slave_cfg names a <sendCmd dest> may send to.
    pub peers: Vec<String>,
    /// How often each variable is named, which SIPp wants twice at least:
    /// the <Global> and <User> ones, shared by the scenarios loaded, and
    /// this scenario's own.
    globals: BTreeMap<String, u32>,
    users: BTreeMap<String, u32>,
    locals: BTreeMap<String, u32>,
}

impl Checks {
    /// AllocVariableTable::find(): counts a reference to a variable, a new
    /// call variable if `allocate`; false if there is none.
    fn reference(&mut self, name: &str, allocate: bool) -> bool {
        for table in [&mut self.locals, &mut self.users, &mut self.globals] {
            if let Some(n) = table.get_mut(name) {
                *n += 1;
                return true;
            }
        }
        if allocate {
            self.locals.insert(name.to_string(), 1);
        }
        allocate
    }

    /// Every variable named so far.
    fn names(&self) -> std::collections::HashSet<String> {
        [&self.locals, &self.users, &self.globals].into_iter().flat_map(|t| t.keys().cloned()).collect()
    }

    /// validate_variable_usage(): a variable named only once is a mistake.
    fn validate(&self) -> Result<(), String> {
        for table in [&self.locals, &self.users, &self.globals] {
            if let Some((name, n)) = table.iter().find(|(name, n)| **n < 2 && name.as_str() != "_") {
                return Err(format!("Variable ${name} is referenced {n} times!"));
            }
        }
        Ok(())
    }
}

thread_local! {
    /// The checks of the scenario being loaded, if any.
    static LOADING: std::cell::RefCell<Option<Checks>> = const { std::cell::RefCell::new(None) };
}

/// parse(), with SIPp's load-time checks of what the scenario refers to.
pub fn parse_checked(xml: &str, keys: &HashMap<String, String>, default_payload: u8, checks: &mut Checks) -> Result<Scenario, String> {
    checks.locals.clear();
    LOADING.set(Some(std::mem::take(checks)));
    let scenario = parse(xml, keys, default_payload);
    *checks = LOADING.take().unwrap_or_default();
    scenario
}

/// Runs `f` on the checks of the scenario being loaded, if any.
fn loading<T>(f: impl FnOnce(&mut Checks) -> T) -> Option<T> {
    LOADING.with_borrow_mut(|c| c.as_mut().map(f))
}

/// A [fieldN] keyword's file= (None for the default one), which SIPp
/// wants loaded with -inf.
pub(crate) fn check_field_file(file: Option<&str>) -> Result<(), String> {
    LOADING.with_borrow(|checks| {
        let Some((names, default)) = checks.as_ref().map(|c| &c.inject) else { return Ok(()) };
        let name = match file {
            Some(f) => f,
            None => default.as_deref().ok_or("No injection file was specified!")?,
        };
        match names.iter().any(|n| n == name) {
            true => Ok(()),
            false => Err(format!("Invalid injection file: {}", file.unwrap_or(""))),
        }
    })
}

/// get_var(): a variable the scenario names, `what` naming the place in
/// errors.
pub(crate) fn var(name: &str, what: &str) -> Result<String, String> {
    if name.is_empty() {
        return Err(format!("Variable names may not be empty for {what}"));
    }
    if name.contains(['$', ',']) {
        return Err(format!("Variable names may not contain '$' or ',' for {what}"));
    }
    loading(|c| c.reference(name, true));
    Ok(name.to_string())
}

pub const UAC: &str = include_str!("../scenarios/uac.xml");
pub const UAS: &str = include_str!("../scenarios/uas.xml");
pub const UAC_PCAP: &str = include_str!("../scenarios/uac_pcap.xml");
/// -oocsn ooc_default: 200 OK to any request.
pub const OOC_DEFAULT: &str = include_str!("../scenarios/ooc_default.xml");
/// SIPp's ooc_dummy, which -aa's calls play: they only ever wait.
pub const OOC_DUMMY: &str = include_str!("../scenarios/ooc_dummy.xml");
pub const REGEXP: &str = include_str!("../scenarios/regexp.xml");
pub const BRANCHC: &str = include_str!("../scenarios/branchc.xml");
pub const BRANCHS: &str = include_str!("../scenarios/branchs.xml");
pub const BUILTIN_3PCC: [(&str, &str); 4] = [
    ("3pcc-C-A", include_str!("../scenarios/3pcc-C-A.xml")),
    ("3pcc-C-B", include_str!("../scenarios/3pcc-C-B.xml")),
    ("3pcc-A", include_str!("../scenarios/3pcc-A.xml")),
    ("3pcc-B", include_str!("../scenarios/3pcc-B.xml")),
];

type Attrs = Vec<(String, String)>;

/// Attributes that only feed SIPp's statistics screens.
const IGNORED_ATTRS: &[&str] = &[];
/// Control-flow attributes every step accepts.
const COMMON_ATTRS: &[&str] = &["next", "test", "chance", "condexec", "condexec_inverse", "lost", "rtd", "start_rtd", "repeat_rtd", "counter", "crlf", "hide", "hiderest", "display", "ignoresdp", "ontimeout"];

fn attrs(e: &BytesStart) -> Result<Attrs, String> {
    e.attributes()
        .map(|a| {
            let a = a.map_err(xml_error)?;
            // An entity it doesn't know stays as it is, as in SIPp.
            let value = match a.normalized_value(quick_xml::XmlVersion::default()) {
                Ok(v) => process_escapes(&v),
                Err(_) => process_escapes(&a.value),
            };
            Ok((a.key.as_ref().to_string(), value))
        })
        .collect()
}

/// xp_process_escapes(), which xp_get_value() applies to every attribute
/// value: \\, \", \n, \t and \r are that character, any other backslash
/// pair stays as it is.
fn process_escapes(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut chars = v.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('\\') => out.push('\\'),
            Some('"') => out.push('"'),
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

fn get<'a>(attrs: &'a Attrs, key: &str) -> Option<&'a str> {
    attrs.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

/// get_long(), get_double() and get_bool(): SIPp's numbers and booleans,
/// `what` naming the value in errors.
fn c_long(v: &str, what: &str) -> Result<i64, String> {
    crate::posix::integer(v).ok_or_else(|| format!("{what}, \"{v}\" is not a valid integer!"))
}

fn c_double(v: &str, what: &str) -> Result<f64, String> {
    match crate::posix::strtod(v) {
        (n, "") if !v.is_empty() => Ok(n),
        _ => Err(format!("{what}, \"{v}\" is not a floating point number!")),
    }
}

fn c_bool(v: &str, what: &str) -> Result<bool, String> {
    if v.eq_ignore_ascii_case("true") {
        return Ok(true);
    }
    if v.eq_ignore_ascii_case("false") {
        return Ok(false);
    }
    crate::posix::integer(v).map(|n| n != 0).ok_or_else(|| format!("{what}, \"{v}\" is not a valid boolean!"))
}

/// xp_get_long(), xp_get_double() and xp_get_bool(): an attribute, if
/// there, with its name after `what` in errors.
fn attr_long(a: &Attrs, key: &str, what: &str) -> Result<Option<i64>, String> {
    get(a, key).map(|v| c_long(v, &format!("{what} '{key}' parameter"))).transpose()
}

fn attr_double(a: &Attrs, key: &str, what: &str) -> Result<Option<f64>, String> {
    get(a, key).map(|v| c_double(v, &format!("{what} '{key}' parameter"))).transpose()
}

fn attr_bool(a: &Attrs, key: &str, what: &str, default: bool) -> Result<bool, String> {
    get(a, key).map_or(Ok(default), |v| c_bool(v, &format!("{what} '{key}' parameter")))
}

/// xp_get_string(): an attribute that must be there.
fn required(elem: &str, attrs: &Attrs, key: &str) -> Result<String, String> {
    get(attrs, key).map(str::to_string).ok_or_else(|| format!("{elem} is missing the required '{key}' parameter."))
}

/// xp_get_var(): a variable attribute, which must be there.
fn required_var(what: &str, attrs: &Attrs, key: &str) -> Result<String, String> {
    var(get(attrs, key).ok_or_else(|| format!("{what} is missing the required '{key}' variable parameter."))?, what)
}

fn optional_var(what: &str, attrs: &Attrs, key: &str) -> Result<Option<String>, String> {
    get(attrs, key).map(|v| var(v, what)).transpose()
}

/// Fails on anything the engine would not run as SIPp does.
fn check_attrs(elem: &str, attrs: &Attrs, known: &[&str]) -> Result<(), String> {
    match attrs.iter().find(|(k, _)| !known.contains(&k.as_str()) && !IGNORED_ATTRS.contains(&k.as_str())) {
        Some((k, _)) => Err(format!("<{elem} {k}=...> is not supported")),
        None => Ok(()),
    }
}

/// POSIX ERE, as SIPp compiles it.
fn regex(pattern: &str) -> Result<Regex, String> {
    Regex::new(pattern)
}

/// check_it= or check_it_inverse=, not both.
fn check(elem: &str, a: &Attrs) -> Result<Check, String> {
    if get(a, "check_it").is_some() {
        let check_it = attr_bool(a, "check_it", elem, false)?;
        if get(a, "check_it_inverse").is_some() {
            return Err(format!("Can not have both check_it and check_it_inverse for {elem}!"));
        }
        return Ok(Check { check_it, inverse: false });
    }
    Ok(Check { check_it: false, inverse: attr_bool(a, "check_it_inverse", elem, false)? })
}

/// <test> and <strcmp>: assign_to= (which check_it= makes optional),
/// variable= and value= or variable2=.
fn comparison(elem: &str, a: &Attrs) -> Result<(Check, Option<String>, String, Operand), String> {
    let check = check(elem, a)?;
    let unchecked = get(a, "check_it").is_none() && get(a, "check_it_inverse").is_none();
    let assign_to = if get(a, "assign_to").is_some() || unchecked { Some(required_var(elem, a, "assign_to")?) } else { None };
    let var = required_var(elem, a, "variable")?;
    let rhs = match get(a, "value") {
        Some(v) => {
            // <test>'s is a number, kept as one that reads back the same.
            // <strcmp>'s is xp_get_string()'s.
            let v = if elem == "test" { attr_double(a, "value", elem)?.unwrap_or_default().to_string() } else { v.to_string() };
            if get(a, "variable2").is_some() {
                return Err(format!("Can not have both a value and a variable2 for {elem}!"));
            }
            Operand::Value(v)
        }
        None => Operand::Var(required_var(elem, a, "variable2")?),
    };
    Ok((check, assign_to, var, rhs))
}

/// handle_rhs(): value= or variable=.
fn num(elem: &str, a: &Attrs) -> Result<Num, String> {
    if let Some(v) = attr_double(a, "value", elem)? {
        if get(a, "variable").is_some() {
            return Err(format!("Value and variable are mutually exclusive for {elem} action!"));
        }
        return Ok(Num::Value(v));
    }
    match get(a, "variable") {
        Some(_) => Ok(Num::Var(required_var(elem, a, "variable")?)),
        None => Err(format!("No value or variable defined for {elem} action!")),
    }
}

/// The attributes a distribution may take, besides `extra`.
fn known_dist(extra: &[&'static str]) -> Vec<&'static str> {
    let mut v = extra.to_vec();
    v.extend(["distribution", "value", "min", "max", "mean", "stdev", "lambda", "k", "x_m", "shape", "scale", "location", "theta", "p", "n"]);
    v
}

/// xp_get_keyword_value(): a play_pcap_* file that is all a [keyword]
/// is that -key's value.
fn keyword_value(name: &str, v: &str, keys: &HashMap<String, String>) -> Result<String, String> {
    match v.strip_prefix('[').and_then(|k| k.strip_suffix(']')) {
        Some(k) => keys.get(k).cloned().ok_or_else(|| format!("{name} \"{v}\" looks like a keyword value, but keyword not supplied!")),
        None => Ok(v.to_string()),
    }
}

/// atoi(), as SIPp reads rtp_stream's numbers.
fn atoi(v: &str) -> i64 {
    let v = v.trim_start();
    let (sign, digits) = match v.strip_prefix('-') {
        Some(d) => (-1, d),
        None => (1, v.strip_prefix('+').unwrap_or(v)),
    };
    let digits: String = digits.chars().take_while(char::is_ascii_digit).collect();
    sign * digits.parse::<i64>().unwrap_or(0)
}

fn action(elem: &str, a: &Attrs, keys: &HashMap<String, String>, default_payload: u8) -> Result<Action, String> {
    Ok(match elem {
        "ereg" => {
            check_attrs(elem, a, &["regexp", "search_in", "header", "check_it", "check_it_inverse", "assign_to",
                "start_line", "occurrence", "occurence", "case_indep", "variable"])?;
            let regexp = required(elem, a, "regexp")?;
            let case_indep = attr_bool(a, "case_indep", elem, false)?;
            let start_line = attr_bool(a, "start_line", elem, false)?;
            let source = match get(a, "search_in") {
                None | Some("msg") => Source::Msg,
                Some("body") => Source::Body,
                Some("var") => Source::Var(required_var(elem, a, "variable")?),
                Some("hdr") => Source::Hdr {
                    header: get(a, "header").filter(|h| !h.is_empty()).ok_or("search_in=\"hdr\" requires header field")?.to_string(),
                    start_line,
                    // atol(), the old misspelling too.
                    occurrence: get(a, "occurrence").or(get(a, "occurence")).map_or(1, |v| atoi(v).max(0) as usize),
                    case_indep,
                },
                Some(other) => return Err(format!("Unknown search_in value {other}")),
            };
            let check = check(elem, a)?;
            let names = get(a, "assign_to").ok_or("assign_to value is missing")?;
            let assign_to: Vec<String> = names.split(',').map(|s| s.trim().to_string()).collect();
            var(&assign_to[0], "assign_to")?;
            for name in &assign_to[1..] {
                var(name, "sub expression assign_to")?;
            }
            // The match and nine groups: executeRegExp()'s ten regmatch_t.
            if assign_to.len() > 10 {
                return Err("You can only have nine sub expressions!".into());
            }
            Action::Ereg { re: regex(&regexp)?, source, check, assign_to }
        }
        "strcmp" | "test" => {
            check_attrs(elem, a, &["assign_to", "variable", "value", "variable2", "compare", "check_it", "check_it_inverse"])?;
            let (check, assign_to, var, rhs) = comparison(elem, a)?;
            if elem == "strcmp" {
                Action::Strcmp { assign_to, var, rhs, check }
            } else {
                let compare = match required(elem, a, "compare")?.as_str() {
                    "equal" => Compare::Equal,
                    "not_equal" => Compare::NotEqual,
                    "greater_than" => Compare::Greater,
                    "less_than" => Compare::Less,
                    "greater_than_equal" => Compare::GreaterEqual,
                    "less_than_equal" => Compare::LessEqual,
                    other => return Err(format!("Invalid 'compare' parameter: {other}")),
                };
                Action::Test { assign_to, var, compare, rhs, check }
            }
        }
        "assign" => {
            check_attrs(elem, a, &["assign_to", "value", "variable"])?;
            Action::Assign { var: required_var(elem, a, "assign_to")?, value: num(elem, a)? }
        }
        "add" | "subtract" | "multiply" | "divide" => {
            check_attrs(elem, a, &["assign_to", "value", "variable"])?;
            let op = match elem {
                "add" => Arith::Add,
                "subtract" => Arith::Subtract,
                "multiply" => Arith::Multiply,
                _ => Arith::Divide,
            };
            let var = required_var(elem, a, "assign_to")?;
            let rhs = num(elem, a)?;
            if let (Arith::Divide, Num::Value(v)) = (op, &rhs) {
                if *v == 0.0 {
                    return Err("divide actions can not have a value of zero!".into());
                }
            }
            Action::Arith { op, var, rhs }
        }
        "index" => {
            check_attrs(elem, a, &["assign_to"])?;
            Action::Index(required_var(elem, a, "assign_to")?)
        }
        "gettimeofday" => {
            check_attrs(elem, a, &["assign_to"])?;
            let vars: Vec<&str> = get(a, "assign_to").ok_or("assign_to value is missing")?.split(',').map(str::trim).collect();
            let [sec, usec] = vars[..] else {
                return Err("The gettimeofday action requires two output variables!".into());
            };
            Action::GetTimeOfDay { sec: var(sec, "gettimeofday seconds assign_to")?, usec: var(usec, "gettimeofday useconds assign_to")? }
        }
        "jump" => {
            check_attrs(elem, a, &["value", "variable"])?;
            Action::Jump(num(elem, a)?)
        }
        "sample" => {
            check_attrs(elem, a, &known_dist(&["assign_to"]))?;
            let var = required_var(elem, a, "assign_to")?;
            let dist = Dist::parse(|k| get(a, k).map(str::to_string))?
                .ok_or("statistically distributed actions or pauses requires 'distribution' parameter")?;
            Action::Sample { var, dist }
        }
        "todouble" => {
            check_attrs(elem, a, &["assign_to", "variable"])?;
            Action::ToDouble { to: required_var(elem, a, "assign_to")?, from: required_var(elem, a, "variable")? }
        }
        "trim" => {
            check_attrs(elem, a, &["assign_to"])?;
            Action::Str { op: StrOp::Trim, var: required_var(elem, a, "assign_to")? }
        }
        "urlencode" | "urldecode" => {
            check_attrs(elem, a, &["variable"])?;
            let op = if elem == "urlencode" { StrOp::UrlEncode } else { StrOp::UrlDecode };
            Action::Str { op, var: required_var(elem, a, "variable")? }
        }
        "lookup" => {
            check_attrs(elem, a, &["assign_to", "file", "key"])?;
            let var = required_var(elem, a, "assign_to")?;
            let t = |k| Template::parse_line(&required(elem, a, k)?, keys);
            Action::Lookup { var, file: t("file")?, key: t("key")? }
        }
        "insert" => {
            check_attrs(elem, a, &["file", "value"])?;
            let t = |k| Template::parse_line(&required(elem, a, k)?, keys);
            Action::Insert { file: t("file")?, value: t("value")? }
        }
        "replace" => {
            check_attrs(elem, a, &["file", "line", "value"])?;
            let t = |k| Template::parse_line(&required(elem, a, k)?, keys);
            Action::Replace { file: t("file")?, line: t("line")?, value: t("value")? }
        }
        "setdest" => {
            check_attrs(elem, a, &["host", "port", "protocol"])?;
            let t = |k| Template::parse_line(&required(elem, a, k)?, keys);
            Action::SetDest { host: t("host")?, port: t("port")?, protocol: t("protocol")? }
        }
        "closecon" => {
            check_attrs(elem, a, &[])?;
            Action::CloseCon
        }
        "pauserestore" => {
            check_attrs(elem, a, &["value", "variable"])?;
            Action::PauseRestore(num(elem, a)?)
        }
        "error" => {
            check_attrs(elem, a, &["message"])?;
            Action::Error(Template::parse_line(&required(elem, a, "message")?, keys)?)
        }
        "assignstr" => {
            check_attrs(elem, a, &["assign_to", "value"])?;
            let var = required_var(elem, a, "assign_to")?;
            Action::AssignStr { var, value: Template::parse_line(&required(elem, a, "value")?, keys)? }
        }
        "warning" | "log" => {
            check_attrs(elem, a, &["message"])?;
            let msg = Template::parse_line(&required(elem, a, "message")?, keys)?;
            if elem == "log" { Action::Log(msg) } else { Action::Warning(msg) }
        }
        "verifyauth" => {
            check_attrs(elem, a, &["assign_to", "username", "password"])?;
            Action::VerifyAuth {
                assign_to: required_var(elem, a, "assign_to")?,
                user: Template::parse_line(&required(elem, a, "username")?, keys)?,
                pass: Template::parse_line(&required(elem, a, "password")?, keys)?,
            }
        }
        "rtp_echo" => {
            check_attrs(elem, a, &["value"])?;
            match num(elem, a)? {
                Num::Value(v) => Action::RtpEcho(v != 0.0),
                Num::Var(_) => return Err("<rtp_echo variable=...> is not supported".into()),
            }
        }
        "rtp_stats" => {
            check_attrs(elem, a, &["assign_to", "media"])?;
            let names: Vec<&str> = get(a, "assign_to").ok_or("assign_to value is missing in rtp_stats")?.split(',').collect();
            if names.len() > 3 {
                return Err("rtp_stats assigns one to three variables: the packets, and the payload type and payload of the first".into());
            }
            let mut vars = vec![var(names[0], "rtp_stats packets assign_to")?];
            for name in &names[1..] {
                vars.push(var(name, "rtp_stats assign_to")?);
            }
            let video = match get(a, "media") {
                None | Some("audio") => false,
                Some("video") => true,
                Some(other) => return Err(format!("rtp_stats media must be audio or video, not {other}")),
            };
            Action::RtpStats { video, vars }
        }
        "rtp_dtmf" => {
            check_attrs(elem, a, &["assign_to", "payload_type"])?;
            let var = var(get(a, "assign_to").ok_or("assign_to value is missing in rtp_dtmf")?, "rtp_dtmf assign_to")?;
            let payload_type = match get(a, "payload_type") {
                Some(v) => match c_long(v, "rtp_dtmf payload_type")? {
                    pt @ 0..=127 => pt as u8,
                    _ => return Err(format!("rtp_dtmf payload_type must be from 0 to 127, not {v}")),
                },
                None => 96,
            };
            Action::RtpDtmf { var, payload_type }
        }
        "exec" => exec(a, keys, default_payload)?,
        _ => return Err(format!("Unknown action: {elem}")),
    })
}

/// An <exec>: what its first attribute SIPp looks for asks for.
fn exec(a: &Attrs, keys: &HashMap<String, String>, default_payload: u8) -> Result<Action, String> {
    const KINDS: [&str; 11] =
        ["command", "lua", "verify", "int_cmd", "play_pcap_audio", "play_pcap_image", "play_pcap_video", "play_pcap_text", "play_dtmf", "rtp_stream", "rtp_echo"];
    let Some((kind, spec)) = KINDS.iter().find_map(|&k| get(a, k).map(|v| (k, v))) else {
        return Err("illegal <exec> in the scenario".into());
    };
    let wait = kind == "rtp_stream" && spec == "wait";
    let known = [kind, "timeout"];
    check_attrs("exec", a, &known[..if wait { 2 } else { 1 }])?;
    Ok(match kind {
        "command" => Action::Exec(Template::parse_line(spec, keys)?),
        "lua" if !crate::lua::BUILT_IN => return Err("Scenario specifies a lua action, but this version of SIPp does not have Lua support".into()),
        "lua" => Action::Lua(Template::parse_line(spec, keys)?),
        "verify" => Action::Verify(Template::parse_line(spec, keys)?),
        "int_cmd" => Action::Stop(match spec {
            "stop_now" => Stop::Now,
            "stop_gracefully" => Stop::Gracefully,
            _ => Stop::Call,
        }),
        "play_pcap_audio" | "play_pcap_image" | "play_pcap_video" | "play_pcap_text" => {
            let pcap_kind = match kind {
                "play_pcap_audio" => PcapMedia::Audio,
                "play_pcap_image" => PcapMedia::Image,
                "play_pcap_video" => PcapMedia::Video,
                _ => PcapMedia::Text,
            };
            Action::PlayPcap { kind: pcap_kind, file: keyword_value(kind, spec, keys)?, pcap: None }
        }
        "play_dtmf" => {
            // Without keywords, what would be played is known now.
            if let (false, (_, _, _, Some(e))) = (spec.contains('['), crate::pcap::parse_dtmf(spec)) {
                return Err(format!("Invalid play_dtmf \"{spec}\": {e}"));
            }
            Action::PlayDtmf(Template::parse_line(spec, keys)?)
        }
        "rtp_stream" => match spec {
            "pause" | "pauseapattern" => Action::RtpPause { video: false },
            "resume" | "resumeapattern" => Action::RtpResume { video: false },
            "pausevpattern" => Action::RtpPause { video: true },
            "resumevpattern" => Action::RtpResume { video: true },
            "wait" => {
                let timeout = attr_long(a, "timeout", "rtp_stream wait")?.unwrap_or(0);
                if timeout < 0 {
                    return Err("rtp_stream wait timeout must not be negative".into());
                }
                Action::RtpWait { timeout_ms: timeout as u64 }
            }
            _ => {
                // setRTPStreamActInfo(): "file,loops,payload,name", or a
                // pattern's "apattern,id,payload,name", numbers as get_int().
                let mut f = spec.split(',');
                let first = f.next().unwrap_or("");
                let pattern = [("apattern", false), ("vpattern", true)].into_iter().find(|(p, _)| first.starts_with(p)).map(|(_, v)| v);
                let int = |v: &str, what: &str| {
                    crate::posix::integer(v)
                        .filter(|n| i32::try_from(*n).is_ok())
                        .ok_or_else(|| format!("rtp_stream {what}, \"{v}\" is not a valid integer!"))
                };
                // SIPp's defaults: pattern 1 for ever, or a file once; -rtp_payload.
                let second = f.next().map(|v| int(v, if pattern.is_some() { "pattern id" } else { "loop count" })).transpose()?;
                let payload = f.next().map_or(Ok(i64::from(default_payload)), |v| int(v, "payload type"))?;
                let codec = media::codec(payload, f.next())?;
                match pattern {
                    Some(video) => {
                        let id = second.unwrap_or(1);
                        media::pattern(u8::try_from(id).unwrap_or(0), &codec)?;
                        Action::RtpStream { source: StreamSource::Pattern(id as u8), video, loops: -1, codec }
                    }
                    None => {
                        let file = Template::parse_line(first, keys)?;
                        Action::RtpStream { source: StreamSource::File(file), video: false, loops: second.unwrap_or(1), codec }
                    }
                }
            }
        },
        _ => {
            // SIPp takes an action of the value's start: one of none is
            // left without a type, which fails as the call runs it.
            // Of each: video, on, update.
            let kinds = [
                ("startaudio", false, true, false),
                ("updateaudio", false, true, true),
                ("stopaudio", false, false, false),
                ("startvideo", true, true, false),
                ("updatevideo", true, true, true),
                ("stopvideo", true, false, false),
            ];
            let Some((_, video, on, update)) = kinds.into_iter().find(|(k, ..)| spec.starts_with(k)) else {
                return Ok(Action::Unknown);
            };
            // setRTPEchoActInfo(): the payload type after the first ',' is
            // get_int()'s, the payload name after it; SIPp knows the
            // bytes per packet of these payloads.
            if spec.len() >= 256 {
                return Err(format!("RTPEcho keyword {spec} is too long -- maximum supported length 255\n"));
            }
            let mut payload = i64::from(default_payload);
            if let Some(v) = spec.split(',').nth(1) {
                match crate::posix::integer(v).filter(|n| i32::try_from(*n).is_ok()) {
                    Some(n) => payload = n,
                    None => return Err(format!("rtp_echo payload type, \"{v}\" is not a valid integer!")),
                }
            }
            let name = spec.split(',').nth(2).filter(|n| !n.is_empty());
            let name = name.or(match payload {
                0 => Some("PCMU/8000"),
                8 => Some("PCMA/8000"),
                9 => Some("G722/8000"),
                18 => Some("G729/8000"),
                _ => None,
            });
            let Some(name) = name else { return Err("Missing mandatory payload_name parameter in rtp_echo action".into()) };
            let bytes = match (payload, name) {
                (0, "PCMU/8000") | (8, "PCMA/8000") | (9, "G722/8000") => 160,
                (18, "G729/8000") => 20,
                (0 | 8 | 9 | 18, _) => 0,
                (13, _) => 1,
                (96..=127, "H264/90000") => 1280,
                (96..=127, "iLBC/8000") => 50,
                (0..=95, _) => return Err(format!("Unknown static rtp payload type {payload} - cannot set playback parameters\n")),
                (96..=127, _) => return Err(format!("Unknown dynamic rtp payload type {payload} - cannot set playback parameters\n")),
                _ => return Err(format!("Invalid rtp payload type {payload} - cannot set playback parameters\n")),
            };
            Action::MediaEcho { video, on, update, bytes }
        }
    })
}

/// A <pause>'s length, as parse_distribution(): variable=, distribution=,
/// or the old style, where normal=, exponential= and the like name the
/// distribution (its value is not used), min= or max= a uniform one and
/// milliseconds= a fixed one.
fn pause_len(a: &Attrs) -> Result<PauseLen, String> {
    if let Some(v) = optional_var("pause", a, "variable")? {
        return Ok(PauseLen::Var(v));
    }
    let old_style = ["normal", "exponential", "lognormal", "weibull", "pareto", "gamma"]
        .into_iter()
        .find(|k| get(a, k).is_some())
        .or_else(|| (get(a, "min").is_some() || get(a, "max").is_some()).then_some("uniform"));
    let name = get(a, "distribution").or(old_style);
    if name.is_none() {
        return Ok(match get(a, "milliseconds") {
            Some(ms) => PauseLen::Dist(Dist::Fixed(c_double(ms, "Pause milliseconds")?)),
            None => PauseLen::Default,
        });
    }
    let dist = Dist::parse(|k| if k == "distribution" { name.map(str::to_string) } else { get(a, k).map(str::to_string) })?;
    let dist = dist.expect("a distribution name");
    let p99 = dist.p99();
    if attr_bool(a, "sanity_check", "pause", true)? && p99 > f64::from(i32::MAX) {
        return Err(format!(
            "The distribution {} has a 99th percentile of {}, which is larger than INT_MAX.  You should chose different parameters.",
            dist.describe(),
            crate::dist::time_string(p99)
        ));
    }
    Ok(PauseLen::Dist(dist))
}

/// A step being read, with its label references still unresolved.
struct Pending {
    step: Step,
    next: Option<String>,
    ontimeout: Option<String>,
    /// rtd=, start_rtd= and counter= names, numbered once all are read.
    rtd: Vec<String>,
    start_rtd: Vec<String>,
    counter: Option<String>,
}

/// get_rtds(): a comma-separated list, each as get_rtd(): "true" is the
/// RTD called "1", "false" none.
fn rtd_names(v: Option<&str>) -> Vec<String> {
    let Some(v) = v else { return Vec::new() };
    // getline(): nothing after a trailing comma.
    let v = v.strip_suffix(',').unwrap_or(v);
    let names = if v.is_empty() { Vec::new() } else { v.split(',').collect() };
    names
        .into_iter()
        .filter(|&name| name != "false")
        .map(|name| if name == "true" { "1".into() } else { name.to_string() })
        .collect()
}

/// getCommonAttributes(), but for the actions; hiderest= sets the hide=
/// default of this step and those after it.
fn common(elem: &str, a: &Attrs, op: Op, hide_default: &mut bool) -> Result<Pending, String> {
    let rtd = rtd_names(get(a, "rtd"));
    let repeat_rtd = match get(a, "repeat_rtd") {
        Some(_) if rtd.is_empty() => return Err("There is a repeat_rtd element without an rtd element".into()),
        Some(v) => c_bool(v, "repeat_rtd")?,
        None => false,
    };
    let start_rtd = rtd_names(get(a, "start_rtd"));
    let counter = match get(a, "counter") {
        Some("") => return Err("Counter names may not be empty for counter".into()),
        Some(c) if c.contains(['$', ',']) => return Err("Counter names may not contain '$' or ',' for counter".into()),
        c => c.map(str::to_string),
    };
    let lost = get(a, "lost").map(|v| c_double(v, "lost percentage")).transpose()?;
    let ignoresdp = get(a, "ignoresdp").map_or(Ok(false), |v| c_bool(v, "ignoresdp"))?;
    if get(a, "hiderest").is_some() {
        *hide_default = attr_bool(a, "hiderest", "hiderest", false)?;
    }
    let hide = attr_bool(a, "hide", "hide", *hide_default)?;
    let condexec = optional_var("condexec variable", a, "condexec")?;
    let condexec_inverse = attr_bool(a, "condexec_inverse", "condexec_inverse", false)?;
    let timewait = elem == "timewait";
    let next = get(a, "next").map(str::to_string);
    let (mut test, mut chance) = (None, 1.0);
    if next.is_some() {
        if timewait {
            return Err("next labels are not allowed in <timewait> elements.".into());
        }
        test = optional_var("test variable", a, "test")?;
        if let Some(v) = get(a, "chance") {
            chance = c_double(v, "chance")?;
            if !(0.0..=1.0).contains(&chance) {
                return Err(format!("Chance {v} not in range [0..1]"));
            }
        }
    }
    let ontimeout = get(a, "ontimeout").map(str::to_string);
    if timewait && ontimeout.is_some() {
        return Err("ontimeout labels are not allowed in <timewait> elements.".into());
    }
    Ok(Pending {
        step: Step {
            op,
            actions: Vec::new(),
            next: None,
            test,
            chance,
            condexec: condexec.map(|v| (v, condexec_inverse)),
            lost,
            start_rtd: Vec::new(),
            stop_rtd: Vec::new(),
            repeat_rtd,
            counter: None,
            // Any value.
            crlf: get(a, "crlf").is_some(),
            hide,
            display: get(a, "display").map(str::to_string),
            ignoresdp,
            ontimeout: None,
        },
        next,
        ontimeout,
        rtd,
        start_rtd,
        counter,
    })
}

/// A step element, the index its message has in SIPp.
fn step(elem: &str, a: &Attrs, index: usize, hide_default: &mut bool) -> Result<Pending, String> {
    fn known<'a>(extra: &[&'a str]) -> Vec<&'a str> {
        [COMMON_ATTRS, extra].concat()
    }
    let mut op = match elem {
        "send" => {
            check_attrs(elem, a, &known(&["retrans", "start_txn", "ack_txn", "response_txn", "timeout", "dialog"]))?;
            let retrans_ms = attr_long(a, "retrans", "retransmission timer")?.map(|v| v.max(0) as u64);
            // How long a send may block, as -send_timeout: sipp-rs's sends
            // don't.
            attr_long(a, "timeout", "message send timeout")?;
            Op::Send {
                msg: Template::parse("", &HashMap::new())?,
                retrans_ms,
                start_txn: get(a, "start_txn").map(str::to_string),
                ack_txn: get(a, "ack_txn").map(str::to_string),
                response_txn: get(a, "response_txn").map(str::to_string),
                dialog: 0,
                ontimeout: None,
            }
        }
        "recv" => {
            check_attrs(elem, a, &known(&["response", "request", "optional", "advance_state", "response_txn", "start_txn", "rrs", "auth", "regexp_match", "timeout", "timeout_variable", "dialog"]))?;
            if get(a, "request").is_some() && get(a, "response_txn").is_some() {
                return Err("response_txn can only be used for received responses.".into());
            }
            if get(a, "request") == Some("ACK") && get(a, "start_txn").is_some() {
                return Err("An ACK message can not start a transaction!".into());
            }
            // SIPp compiles it when it first matches a message.
            let re = |p: &str| Regex::new(p).map_err(|_| format!("Invalid regular expression for index {index}: {p}"));
            let regexp_match = get(a, "regexp_match") == Some("true");
            let expect = match (get(a, "response"), get(a, "request")) {
                (Some(code), None) if regexp_match => Expect::ResponseRe(re(code)?),
                // atoi(): a code that is no number matches nothing.
                (Some(code), None) => Expect::Response(u16::try_from(atoi(code)).unwrap_or(0)),
                // With response= too, as SIPp: the request matches.
                (_, Some(method)) if regexp_match => Expect::RequestRe(re(method)?),
                (_, Some(method)) => Expect::Request(method.to_string()),
                (None, None) => Expect::Nothing,
            };
            let (optional, global) = optional_attr(a)?;
            let advance_state = attr_bool(a, "advance_state", "recv", true)?;
            if !advance_state && !optional {
                return Err(format!("advance_state is allowed only for optional messages (index = {index})"));
            }
            let timeout_ms = attr_long(a, "timeout", "message timeout")?.map(|v| v.max(0) as u64);
            let timeout_var = optional_var("recv", a, "timeout_variable")?;
            if timeout_var.is_some() && get(a, "timeout").is_some() {
                return Err(format!("timeout and timeout_variable cannot both be set (index = {index})"));
            }
            let rrs = get(a, "rrs").map_or(Ok(false), |v| c_bool(v, "record route set"))?;
            let auth = get(a, "auth").map_or(Ok(false), |v| c_bool(v, "message authentication"))?;
            Op::Recv {
                expect,
                optional,
                global,
                response_txn: get(a, "response_txn").map(str::to_string),
                start_txn: get(a, "start_txn").map(str::to_string),
                dialog: 0,
                rrs,
                auth,
                advance_state,
                timeout_ms,
                timeout_var,
                ontimeout: None,
                methods: String::new(),
                shown: get(a, "request").and(get(a, "response")).map(str::to_string),
            }
        }
        "pause" => {
            let mut attrs = known_dist(&["milliseconds", "variable", "sanity_check", "normal", "exponential", "lognormal", "weibull", "pareto", "gamma"]);
            attrs.extend(known(&[]));
            check_attrs(elem, a, &attrs)?;
            Op::Pause(pause_len(a)?)
        }
        "nop" => {
            check_attrs(elem, a, COMMON_ATTRS)?;
            Op::Nop
        }
        "sendCmd" => {
            check_attrs(elem, a, &known(&["dest"]))?;
            if let Some(dest) = get(a, "dest") {
                if loading(|c| c.peers.iter().any(|p| p == dest)) == Some(false) {
                    return Err(format!("get_peer_addr: Peer {dest} not found"));
                }
            }
            Op::SendCmd { msg: Template::parse("", &HashMap::new())?, dest: get(a, "dest").map(str::to_string) }
        }
        "recvCmd" => {
            check_attrs(elem, a, &known(&["src", "optional"]))?;
            let (optional, _) = optional_attr(a)?;
            Op::RecvCmd { src: get(a, "src").map(str::to_string), optional }
        }
        "timewait" => {
            // A <pause>, as SIPp parses it.
            let mut attrs = known_dist(&["milliseconds", "variable", "sanity_check", "normal", "exponential", "lognormal", "weibull", "pareto", "gamma"]);
            attrs.extend(known(&[]));
            check_attrs(elem, a, &attrs)?;
            Op::Timewait(pause_len(a)?)
        }
        _ => return Err(format!("Unknown element '{elem}' in xml scenario file")),
    };
    if let Op::Send { dialog, .. } | Op::Recv { dialog, .. } = &mut op {
        if let Some(n) = attr_long(a, "dialog", "dialog number")? {
            if !(1..=i64::from(i32::MAX)).contains(&n) {
                return Err(format!("dialog must be a positive number, not '{}'", get(a, "dialog").unwrap_or_default()));
            }
            *dialog = n as usize;
        }
    }
    common(elem, a, op, hide_default)
}

/// xp_get_optional("optional", "recv"): optional, and whether globally.
fn optional_attr(a: &Attrs) -> Result<(bool, bool), String> {
    match get(a, "optional") {
        None | Some("false") => Ok((false, false)),
        Some("true") => Ok((true, false)),
        Some("global") => Ok((true, true)),
        Some(other) => Err(format!("Could not understand optional value for recv: {other}")),
    }
}

/// SIPp's error for a scenario it can't read as XML.
fn xml_error(e: impl std::fmt::Display) -> String {
    match loading(|c| c.file.clone()) {
        Some(Some(file)) => format!("Unable to load or parse '{file}' xml scenario file"),
        Some(None) => "Unable to load default xml scenario file".into(),
        None => format!("XML error: {e}"),
    }
}

/// SIPp's XP_MAX_INCLUDE_DEPTH: deep enough for any real scenario, low
/// enough to stop a loop.
const MAX_INCLUDE_DEPTH: usize = 16;

/// A scenario text's elements, as SIPp's pugixml loads it.
#[derive(Default)]
struct Scan {
    /// Each outermost <xi:include>, as where it stands and its href.
    includes: Vec<(std::ops::Range<usize>, String)>,
    /// The first element: whether it is a <scenario>, where it stands,
    /// and where its content does.
    root: Option<(bool, std::ops::Range<usize>, std::ops::Range<usize>)>,
}

/// pugixml's description of why it can't load a text as XML.
fn load_error(e: &quick_xml::Error) -> &'static str {
    use quick_xml::errors::{IllFormedError, SyntaxError};
    match e {
        quick_xml::Error::Syntax(e) => match e {
            SyntaxError::InvalidBangMarkup => "Could not determine tag type",
            SyntaxError::UnclosedPI | SyntaxError::UnclosedXmlDecl => "Error parsing document declaration/processing instruction",
            SyntaxError::UnclosedComment => "Error parsing comment",
            SyntaxError::UnclosedDoctype => "Error parsing document type declaration",
            SyntaxError::UnclosedCData => "Error parsing CDATA section",
            SyntaxError::UnclosedTag => "Error parsing start element tag",
            _ => "Error parsing element attribute",
        },
        quick_xml::Error::IllFormed(IllFormedError::MismatchedEndTag { .. } | IllFormedError::UnmatchedEndTag(_) | IllFormedError::MissingEndTag(_)) => "Start-end tags mismatch",
        quick_xml::Error::IllFormed(IllFormedError::MissingDoctypeName) => "Error parsing document type declaration",
        quick_xml::Error::IllFormed(_) => "Error parsing document declaration/processing instruction",
        quick_xml::Error::InvalidAttr(_) => "Error parsing element attribute",
        quick_xml::Error::Io(_) => "Error reading from file/stream",
        _ => "Unknown error",
    }
}

/// Where a text's <xi:include>s and first element are, or why pugixml
/// would not load it.
fn scan(xml: &str) -> Result<Scan, &'static str> {
    let mut reader = Reader::from_str(xml);
    let mut scan = Scan::default();
    // The open elements, as where each starts and its content does.
    let mut open: Vec<(usize, usize)> = Vec::new();
    // The <xi:include> being read: its depth, where it starts, its href.
    let mut include: Option<(usize, usize, String)> = None;
    loop {
        let at = reader.buffer_position() as usize;
        let event = reader.read_event().map_err(|e| load_error(&e))?;
        let end = reader.buffer_position() as usize;
        let (e, empty) = match &event {
            Event::Start(e) => (e, false),
            Event::Empty(e) => (e, true),
            Event::End(_) => {
                let (start, content) = open.pop().ok_or("Start-end tags mismatch")?;
                if let Some((_, from, href)) = include.take_if(|(depth, ..)| *depth == open.len()) {
                    scan.includes.push((from..end, href));
                }
                if open.is_empty() {
                    if let Some((_, outer, inner)) = scan.root.as_mut().filter(|(_, outer, _)| outer.start == start) {
                        (*outer, *inner) = (start..end, content..at);
                    }
                }
                continue;
            }
            Event::Eof if open.is_empty() => return Ok(scan),
            Event::Eof => return Err("Start-end tags mismatch"),
            _ => continue,
        };
        let mut href = None;
        for a in e.attributes() {
            let a = a.map_err(|_| "Error parsing element attribute")?;
            if a.key.as_ref() == "href" {
                // An entity it doesn't know stays as it is, as in SIPp.
                href = Some(a.normalized_value(quick_xml::XmlVersion::default()).map_or_else(|_| a.value.to_string(), |v| v.into_owned()));
            }
        }
        if include.is_none() && e.name().as_ref() == "xi:include" {
            let href = href.unwrap_or_default();
            match empty {
                true => scan.includes.push((at..end, href)),
                false => include = Some((open.len(), at, href)),
            }
        }
        if open.is_empty() && scan.root.is_none() {
            scan.root = Some((e.name().as_ref() == "scenario", at..end, end..end));
        }
        if !empty {
            open.push((at, end));
        }
    }
}

/// SIPp's xp_expand_includes(): the text with each <xi:include> replaced,
/// its relative hrefs taken from `dir`, the including file's directory.
fn expand(xml: &str, scan: &Scan, dir: &str, depth: usize) -> Result<String, String> {
    let mut out = String::with_capacity(xml.len());
    let mut copied = 0;
    for (range, href) in &scan.includes {
        out.push_str(&xml[copied..range.start]);
        out.push_str(&include(href, dir, depth)?);
        copied = range.end;
    }
    out.push_str(&xml[copied..]);
    Ok(out)
}

/// xp_include(): what <xi:include href> stands for, the children of the
/// file's <scenario>, or else its root element.
fn include(href: &str, dir: &str, depth: usize) -> Result<String, String> {
    if href.is_empty() {
        return Err("<xi:include> without an href".into());
    }
    let path = match href.starts_with('/') || std::path::Path::new(href).is_absolute() {
        true => href.to_string(),
        false => format!("{dir}{href}"),
    };
    let fail = |why: &str| format!("cannot include '{path}': {why}");
    if depth >= MAX_INCLUDE_DEPTH {
        return Err(fail(&format!("more than {MAX_INCLUDE_DEPTH} nested includes")));
    }
    let text = read_xml(&path).map_err(fail)?;
    let found = scan(&text).map_err(fail)?;
    if found.root.is_none() {
        return Err(fail("No document element found"));
    }
    let text = expand(&text, &found, dir_of(&path), depth + 1)?;
    // The first element once its own includes are in.
    let Some((scenario, outer, inner)) = scan(&text).map_err(fail)?.root else { return Ok(String::new()) };
    Ok(text[if scenario { inner } else { outer }].to_string())
}

/// A file's text as pugixml's load_file() reads it, or its description of
/// why it can't.
fn read_xml(path: &str) -> Result<String, &'static str> {
    use std::io::Read;
    let mut file = std::fs::File::open(crate::raw::os(path)).map_err(|_| "File was not found")?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|_| "Error reading from file/stream")?;
    Ok(xml_text(&bytes))
}

/// An XML file's bytes as text, as pugixml takes them (its
/// guess_buffer_encoding()): UTF-32 or UTF-16 by a BOM or how a '<'
/// starts, ISO-8859-1 when the declaration says so (most scenarios' does),
/// each byte a character, else UTF-8, whose invalid bytes stay as they
/// are (raw). A BOM goes.
pub fn xml_text(bytes: &[u8]) -> String {
    let text = match bytes {
        _ if bytes.len() < 4 => crate::raw::text(bytes).into_owned(),
        [0, 0, 0xfe, 0xff, ..] | [0, 0, 0, 0x3c, ..] => wide_text(bytes, 4, |c| u32::from_be_bytes(c.try_into().unwrap())),
        [0xff, 0xfe, 0, 0, ..] | [0x3c, 0, 0, 0, ..] => wide_text(bytes, 4, |c| u32::from_le_bytes(c.try_into().unwrap())),
        [0xfe, 0xff, ..] | [0, 0x3c, ..] => wide_text(bytes, 2, |c| u32::from(u16::from_be_bytes(c.try_into().unwrap()))),
        [0xff, 0xfe, ..] | [0x3c, 0, ..] => wide_text(bytes, 2, |c| u32::from(u16::from_le_bytes(c.try_into().unwrap()))),
        _ if declared_latin1(bytes) => bytes.iter().map(|&b| char::from(b)).collect(),
        _ => crate::raw::text(bytes).into_owned(),
    };
    match text.strip_prefix('\u{feff}') {
        Some(rest) => rest.to_string(),
        None => text,
    }
}

/// UTF-16 or UTF-32 text (`width` bytes a unit, `unit` reading one) made
/// UTF-8 as pugixml's decoders and utf8_writer make it: a surrogate that
/// is not in a pair is dropped from UTF-16, and UTF-32 is not checked, a
/// surrogate or a unit past U+10FFFF giving bytes that are not UTF-8.
fn wide_text(bytes: &[u8], width: usize, unit: impl Fn(&[u8]) -> u32) -> String {
    let units: Vec<u32> = bytes.chunks_exact(width).map(unit).collect();
    let mut out = Vec::with_capacity(units.len());
    let mut i = 0;
    while i < units.len() {
        let mut c = units[i];
        i += 1;
        if width == 2 && (0xd800..0xe000).contains(&c) {
            match units.get(i) {
                Some(&next) if c < 0xdc00 && (0xdc00..0xe000).contains(&next) => {
                    c = 0x10000 + ((c & 0x3ff) << 10) + (next & 0x3ff);
                    i += 1;
                }
                _ => continue,
            }
        }
        match c {
            0..0x80 => out.push(c as u8),
            0x80..0x800 => out.extend([0xc0 | (c >> 6) as u8, 0x80 | (c & 0x3f) as u8]),
            0x800..0x10000 => out.extend([0xe0 | (c >> 12) as u8, 0x80 | ((c >> 6) & 0x3f) as u8, 0x80 | (c & 0x3f) as u8]),
            _ => out.extend([(0xf0 | (c >> 18)) as u8, 0x80 | ((c >> 12) & 0x3f) as u8, 0x80 | ((c >> 6) & 0x3f) as u8, 0x80 | (c & 0x3f) as u8]),
        }
    }
    crate::raw::text_owned(out)
}

/// Whether the <?xml ...?> declaration at the start names ISO-8859-1 (or
/// latin1), in any case, as pugixml's guess of the encoding reads it.
fn declared_latin1(bytes: &[u8]) -> bool {
    let Some(decl) = bytes.strip_prefix(b"<?xml") else { return false };
    let decl = &decl[..decl.windows(2).position(|w| w == b"?>").unwrap_or(0)];
    let Some(at) = decl.windows(8).position(|w| w == b"encoding") else { return false };
    let rest = decl[at + 8..].trim_ascii_start();
    let Some(rest) = rest.strip_prefix(b"=") else { return false };
    let rest = rest.trim_ascii_start();
    let Some((&quote, value)) = rest.split_first().filter(|(q, _)| matches!(q, b'"' | b'\'')) else { return false };
    let value = &value[..value.iter().position(|&b| b == quote).unwrap_or(value.len())];
    value.eq_ignore_ascii_case(b"ISO-8859-1") || value.eq_ignore_ascii_case(b"latin1")
}

/// The directory of a file's path, with its separator, or "".
fn dir_of(path: &str) -> &str {
    let separators: &[char] = if cfg!(windows) { &['/', '\\'] } else { &['/'] };
    path.rfind(separators).map_or("", |i| &path[..=i])
}

/// A scenario file's text as SIPp's xp_set_xml_buffer_from_file() loads
/// it, its <xi:include>s expanded relative to the file, or SIPp's error.
pub fn with_includes(xml: String, path: &str) -> Result<String, String> {
    let found = scan(&xml).map_err(|_| format!("Unable to load or parse '{path}' xml scenario file"))?;
    if found.includes.is_empty() {
        return Ok(xml);
    }
    expand(&xml, &found, dir_of(path), 0).map_err(|e| format!("Unable to load '{path}' xml scenario file: {e}"))
}

/// A transaction the scenario names, as get_txn() counts its uses.
struct Txn {
    name: String,
    started: u32,
    responses: u32,
    acks: u32,
    invite: bool,
    /// Started by a received request, answered by sent responses.
    server: bool,
    sent_responses: u32,
}

/// get_txn(): `start` for the request that starts it, `ack` for its ACK,
/// neither for a response to it; `server` when a received request starts
/// it, or a sent response answers it.
fn txn(txns: &mut Vec<Txn>, name: &str, what: &str, start: bool, invite: bool, ack: bool, server: bool) -> Result<(), String> {
    if name.is_empty() {
        return Err(format!("Transaction names may not be empty for {what}"));
    }
    if name.contains(['$', ',']) {
        return Err(format!("Transaction names may not contain '$' or ',' for {what}"));
    }
    let t = match txns.iter_mut().position(|t| t.name == name) {
        Some(i) => &mut txns[i],
        None => {
            txns.push(Txn { name: name.to_string(), started: 0, responses: 0, acks: 0, invite: start && invite, server: false, sent_responses: 0 });
            txns.last_mut().unwrap()
        }
    };
    match (start, ack, server) {
        (true, ..) => {
            if t.started > 0 && t.server != server {
                return Err(format!("Transaction {name} is started by both a sent and a received message"));
            }
            t.started += 1;
            t.server = server;
        }
        (_, true, _) => t.acks += 1,
        (.., true) => t.sent_responses += 1,
        _ => t.responses += 1,
    }
    Ok(())
}

/// `default_payload`: -rtp_payload, for rtp_stream actions that name none.
pub fn parse(xml: &str, keys: &HashMap<String, String>, default_payload: u8) -> Result<Scenario, String> {
    let mut reader = Reader::from_str(xml);
    let mut name = String::new();
    let mut steps: Vec<Pending> = Vec::new();
    let mut labels: HashMap<String, usize> = HashMap::new();
    let (mut global_vars, mut user_vars) = (std::collections::HashSet::new(), std::collections::HashSet::new());
    let (mut response_times, mut call_lengths) = (None::<(Vec<u64>, usize)>, None);
    // The step element we're inside, its <send> text (None without a
    // CDATA section), and whether we're in its <action>.
    let mut open: Option<(String, Option<String>)> = None;
    let mut in_action = false;
    // hiderest='s default for hide=, from one step to the next.
    let mut hide_default = false;
    // <init>: nops and labels the initialization call runs, once.
    let (mut in_init, mut init_steps, mut init_labels) = (false, Vec::<Pending>::new(), HashMap::<String, usize>::new());
    // Sends that name a transaction don't answer "which method" questions.
    let mut txn_sends: Vec<bool> = Vec::new();
    let mut txns: Vec<Txn> = Vec::new();
    let (mut dialogs, mut new_dialogs) = (false, false);
    // The <scenario> element: not yet, open, or closed.
    let mut root = None::<bool>;
    // The scenario's elements so far, whether the last <recv> was
    // optional, and whether a <timewait> was seen, for SIPp's checks.
    let (mut cursor, mut last_optional, mut timewait) = (0usize, false, false);
    // <DefaultMessage>: the one being read, and those read, as id and text.
    let (mut default_id, mut default_raw) = (None::<String>, Vec::<(String, String)>::new());

    loop {
        let event = reader.read_event().map_err(xml_error)?;
        let (e, empty) = match &event {
            Event::Start(e) => (e, false),
            Event::Empty(e) => (e, true),
            Event::CData(t) => {
                // SIPp reads a <send>'s first one, and no others.
                if let Some((elem, text @ None)) = open.as_mut() {
                    if elem == "send" || elem == "sendCmd" || elem == "DefaultMessage" {
                        let mut s = String::new();
                        s.push_str(t);
                        *text = Some(s);
                    }
                }
                continue;
            }
            Event::End(e) => {
                let elem = e.name().as_ref().to_string();
                if elem == "action" {
                    in_action = false;
                } else if elem == "init" && open.is_none() {
                    in_init = false;
                } else if elem == "DefaultMessage" && open.as_ref().is_some_and(|(o, _)| *o == elem) {
                    let (_, text) = open.take().unwrap();
                    default_raw.push(default_message(default_id.take().unwrap_or_default(), text)?);
                } else if open.as_ref().is_some_and(|(o, _)| *o == elem) {
                    let (_, text) = open.take().unwrap();
                    let target = if in_init { &mut init_steps } else { &mut steps };
                    let cdata = |text: Option<String>| {
                        let text = text.ok_or_else(|| format!("No CDATA in '{elem}' section of xml scenario file"))?;
                        // clean_cdata() trims blanks, tabs and newlines.
                        match text.trim_matches([' ', '\t', '\n']).is_empty() {
                            true => Err("Empty cdata in xml scenario file".to_string()),
                            false => Ok(text),
                        }
                    };
                    match &mut target.last_mut().unwrap().step.op {
                        Op::Send { msg, start_txn, ack_txn, response_txn, .. } => {
                            *msg = Template::parse(&cdata(text)?, keys)?;
                            msg.check_start_line()?;
                            send_txns(&mut txns, msg, start_txn.as_deref(), ack_txn.as_deref(), response_txn.as_deref())?;
                        }
                        Op::SendCmd { msg, .. } => *msg = Template::parse(&cdata(text)?, keys)?,
                        _ => {}
                    }
                } else if elem == "scenario" && open.is_none() && !in_init {
                    root = Some(false);
                    break;
                }
                continue;
            }
            Event::Eof => break,
            _ => continue,
        };
        let elem = e.name().as_ref().to_string();
        let a = attrs(e)?;
        if root.is_none() {
            if elem != "scenario" {
                return Err("No 'scenario' section in xml scenario file".into());
            }
            name = get(&a, "name").unwrap_or_default().to_string();
            root = Some(!empty);
            if empty {
                break;
            }
            continue;
        }
        if in_action {
            let act = action(&elem, &a, keys, default_payload)?;
            let target = if in_init { &mut init_steps } else { &mut steps };
            target.last_mut().unwrap().step.actions.push(act);
            continue;
        }
        if in_init && open.is_none() {
            match elem.as_str() {
                "nop" => {
                    init_steps.push(step(&elem, &a, init_steps.len(), &mut hide_default)?);
                    if !empty {
                        open = Some((elem, None));
                    }
                }
                "label" => {
                    // xp_get_value(), not xp_get_string(), here.
                    let id = get(&a, "id").ok_or_else(|| format!("{elem} is missing the required 'id' parameter."))?.to_string();
                    if init_labels.insert(id.clone(), init_steps.len()).is_some() {
                        return Err(format!("The label name '{id}' is used twice."));
                    }
                }
                other => return Err(format!("Invalid element in an init stanza: '{other}'")),
            }
            continue;
        }
        if open.is_some() {
            if elem == "action" && !empty {
                in_action = true;
                continue;
            }
            return Err(format!("<{elem}> inside a step is not supported"));
        }
        cursor += 1;
        match elem.as_str() {
            "label" => {
                let id = required(&elem, &a, "id")?;
                if labels.insert(id.clone(), steps.len()).is_some() {
                    return Err(format!("The label name '{id}' is used twice."));
                }
            }
            "Reference" => {
                for v in required(&elem, &a, "variables")?.split(',') {
                    if loading(|c| c.reference(v, false)) == Some(false) {
                        return Err(format!("Could not reference non-existent variable '{v}'"));
                    }
                }
            }
            "DefaultMessage" => {
                let id = required(&elem, &a, "id")?;
                if empty {
                    default_raw.push(default_message(id, None)?);
                } else {
                    default_id = Some(id);
                    open = Some((elem, None));
                }
            }
            "init" if !empty => in_init = true,
            "init" => {}
            "ResponseTimeRepartition" | "CallLengthRepartition" => {
                let list = &required(&elem, &a, "value")?;
                let what = if elem == "CallLengthRepartition" { "call length" } else { "response time" };
                let borders = list
                    .split(',')
                    .map(|v| v.trim().parse::<u64>().map_err(|_| format!("Could not create table for {what} repartition '{list}'")))
                    .collect::<Result<Vec<_>, _>>()?;
                if elem == "CallLengthRepartition" {
                    call_lengths = Some(borders);
                } else {
                    response_times = Some((borders, steps.len()));
                }
            }
            "Global" | "User" => {
                let names: Vec<String> = required(&elem, &a, "variables")?.split(',').map(|v| v.trim().to_string()).collect();
                loading(|c| {
                    let table = if elem == "Global" { &mut c.globals } else { &mut c.users };
                    for n in &names {
                        *table.entry(n.clone()).or_default() += 1;
                    }
                });
                if elem == "Global" { global_vars.extend(names) } else { user_vars.extend(names) }
            }
            _ => {
                if timewait {
                    return Err("<timewait> can only be the last message in a scenario!".into());
                }
                if matches!(elem.as_str(), "send" | "pause" | "timewait" | "nop" | "sendCmd") {
                    if last_optional {
                        return Err(format!("<recv> before <{elem}> sequence without a mandatory message. Please remove one 'optional=true' (element {cursor})."));
                    }
                    last_optional = false;
                }
                timewait = elem == "timewait";
                let index = steps.len();
                let p = step(&elem, &a, index, &mut hide_default)?;
                match &p.step.op {
                    Op::Recv { optional, response_txn, start_txn, expect, dialog, .. } => {
                        last_optional = *optional;
                        match (expect, response_txn, start_txn) {
                            (Expect::Response(_) | Expect::ResponseRe(_), Some(t), _) => txn(&mut txns, t, "transaction response", false, false, false, false)?,
                            (Expect::Request(_) | Expect::RequestRe(_), _, Some(t)) => txn(&mut txns, t, "start transaction", true, false, false, true)?,
                            _ => {}
                        }
                        if *dialog > 1 {
                            dialogs = true;
                            new_dialogs |= matches!(expect, Expect::Request(_) | Expect::RequestRe(_));
                        }
                    }
                    Op::Send { dialog, .. } => dialogs |= *dialog > 1,
                    Op::RecvCmd { optional, .. } => last_optional = *optional,
                    _ => {}
                }
                txn_sends.push(elem == "send" && (get(&a, "start_txn").is_some() || get(&a, "ack_txn").is_some()));
                steps.push(p);
                if !empty {
                    open = Some((elem, None));
                } else if elem == "send" || elem == "sendCmd" {
                    return Err(format!("No CDATA in '{elem}' section of xml scenario file"));
                }
            }
        }
    }
    // No element at all, or one left open.
    if root != Some(false) {
        return Err(xml_error("unexpected end of the document"));
    }

    let resolve = |label: &Option<String>, labels: &HashMap<String, usize>, i: usize, attr: &str| -> Result<Option<usize>, String> {
        label
            .as_ref()
            .map(|l| labels.get(l).copied().ok_or_else(|| format!("The label '{l}' was not defined (index {i}, {attr} attribute)")))
            .transpose()
    };
    let mut methods = String::new();
    let mut out = Vec::new();
    // RTDs and counters are numbered as findRtd() and findCounter() meet them.
    let mut layout = crate::stat::Layout::default();
    let mut rtds_before_repartition = 0;
    let find = |names: &mut Vec<String>, name: &str| -> usize {
        names.iter().position(|n| n == name).unwrap_or_else(|| {
            names.push(name.to_string());
            names.len() - 1
        })
    };
    // validateRtds(): an RTD started should be stopped somewhere.
    let (mut started, mut stopped) = (std::collections::BTreeSet::new(), std::collections::HashSet::new());
    for (i, mut p) in steps.into_iter().enumerate() {
        if response_times.as_ref().is_some_and(|(_, at)| i == *at) {
            rtds_before_repartition = layout.rtds.len();
        }
        p.step.stop_rtd = p.rtd.iter().map(|n| find(&mut layout.rtds, n)).collect();
        p.step.start_rtd = p.start_rtd.iter().map(|n| find(&mut layout.rtds, n)).collect();
        started.extend(p.start_rtd.iter().cloned());
        stopped.extend(p.rtd.iter().cloned());
        p.step.counter = p.counter.as_deref().map(|n| find(&mut layout.counters, n));
        p.step.next = resolve(&p.next, &labels, i, "next")?;
        let to = resolve(&p.ontimeout, &labels, i, "ontimeout")?;
        p.step.ontimeout = to;
        match &mut p.step.op {
            Op::Send { msg, ontimeout, .. } => {
                if !txn_sends[i] {
                    methods += msg.method().unwrap_or("");
                }
                *ontimeout = to;
            }
            Op::Recv { methods: m, ontimeout, .. } => {
                *m = methods.clone();
                *ontimeout = to;
            }
            _ => {}
        }
        out.push(p.step);
    }
    if response_times.as_ref().is_some_and(|(_, at)| *at >= out.len()) {
        rtds_before_repartition = layout.rtds.len();
    }
    // A <exec lua> may use any variable, so SIPp does not count them.
    let uses_lua = out.iter().chain(init_steps.iter().map(|p| &p.step)).any(|s| s.actions.iter().any(|a| matches!(a, Action::Lua(_))));
    let var_names: std::collections::HashSet<String> = match uses_lua {
        true => loading(|c| c.names()).unwrap_or_default().into_iter().chain(global_vars.iter().chain(&user_vars).cloned()).collect(),
        false => Default::default(),
    };
    let init = if init_steps.is_empty() {
        None
    } else {
        let mut out = Vec::new();
        for (i, mut p) in init_steps.into_iter().enumerate() {
            p.step.next = resolve(&p.next, &init_labels, i, "next")?;
            resolve(&p.ontimeout, &init_labels, i, "ontimeout")?;
            out.push(p.step);
        }
        let layout = crate::stat::Layout { steps: out.len(), ..Default::default() };
        Some(Box::new(Scenario {
            name: format!("{name} initialization"),
            steps: out,
            layout,
            unexpected_jump: None,
            uses_retaddr: false,
            uses_pausedaddr: false,
            global_vars: global_vars.clone(),
            user_vars: user_vars.clone(),
            init: None,
            default_messages: Vec::new(),
            dialogs: false,
            new_dialogs: false,
            var_names: var_names.clone(),
        }))
    };
    if let Some(rtd) = started.iter().find(|r| !stopped.contains(*r)) {
        return Err(format!("You have started Response Time Duration {rtd}, but have never stopped it!"));
    }
    // find_var() of these counts as a reference too.
    for v in ["_unexp.retaddr", "_unexp.pausedaddr"] {
        loading(|c| c.reference(v, false));
    }
    if !uses_lua {
        loading(|c| c.validate()).transpose()?;
    }
    // validate_txn_usage().
    for t in &txns {
        if t.started == 0 {
            return Err(format!("Transaction {} is never started!", t.name));
        }
        if t.server {
            // Started by a received request: we send its responses.
            if t.sent_responses == 0 {
                return Err(format!("Transaction {} has no responses defined!", t.name));
            } else if t.responses > 0 || t.acks > 0 {
                return Err(format!("Transaction {} is started by a received request: it takes no received responses or ACK!", t.name));
            }
            continue;
        }
        if t.sent_responses > 0 {
            return Err(format!("Transaction {} is started by a sent request: it takes no sent responses!", t.name));
        } else if t.responses == 0 {
            return Err(format!("Transaction {} has no responses defined!", t.name));
        }
        if t.invite && t.acks == 0 {
            return Err(format!("Transaction {} is an INVITE transaction without an ACK!", t.name));
        }
        if !t.invite && t.acks > 0 {
            return Err(format!("Transaction {} is a non-INVITE transaction with an ACK!", t.name));
        }
    }
    if out.is_empty() {
        return Err("Did not find any messages inside of scenario!".into());
    }
    if let Op::Recv { dialog: n @ 2.., .. } = out[0].op {
        return Err(format!("A call begins in dialog 1: its first message can not have dialog=\"{n}\""));
    }
    // init_default_messages() reads them once all scenarios are loaded,
    // with the checks of a <send>.
    let default_messages = default_raw
        .into_iter()
        .map(|(id, text)| {
            let t = Template::parse_default(&text, keys)?;
            t.check_start_line()?;
            Ok((id, t))
        })
        .collect::<Result<Vec<_>, String>>()?;
    layout.response_times = response_times.map(|(b, _)| (b, rtds_before_repartition));
    layout.steps = out.len();
    layout.call_lengths = call_lengths;
    Ok(Scenario {
        layout,
        name,
        steps: out,
        unexpected_jump: labels.get("_unexp.main").copied(),
        uses_retaddr: xml.contains("_unexp.retaddr"),
        uses_pausedaddr: xml.contains("_unexp.pausedaddr"),
        global_vars,
        user_vars,
        init,
        default_messages,
        dialogs,
        new_dialogs,
        var_names,
    })
}

/// A <DefaultMessage>, as SIPp reads it: its CDATA as a <send>'s (and
/// SIPp's words for one), then an id set_default_message() knows.
fn default_message(id: String, text: Option<String>) -> Result<(String, String), String> {
    let text = text.ok_or("No CDATA in 'send' section of xml scenario file")?;
    if text.trim_matches([' ', '\t', '\n']).is_empty() {
        return Err("Empty cdata in xml scenario file".into());
    }
    if !crate::call::Defaults::NAMES.contains(&id.as_str()) {
        return Err(format!("Internal Error: Unknown default message: {id}!"));
    }
    Ok((id, text))
}

/// A <send>'s start_txn=, ack_txn= or response_txn=, which its message
/// decides on.
fn send_txns(txns: &mut Vec<Txn>, msg: &Template, start: Option<&str>, ack: Option<&str>, response: Option<&str>) -> Result<(), String> {
    match msg.method() {
        Some(method) => {
            let is_ack = method == "ACK";
            if let Some(t) = start {
                if is_ack {
                    return Err("An ACK message can not start a transaction!".into());
                }
                txn(txns, t, "start transaction", true, method == "INVITE", false, false)?;
            } else if let Some(t) = ack {
                if !is_ack {
                    return Err("The ack_txn attribute is valid only for ACK messages!".into());
                }
                txn(txns, t, "ack transaction", false, false, true, false)?;
            }
            match response {
                Some(_) => Err("response_txn can only be used for received responses or sent responses.".into()),
                None => Ok(()),
            }
        }
        None if start.is_some() => Err("Responses can not start a transaction".into()),
        None if ack.is_some() => Err("Responses can not ACK a transaction".into()),
        None => response.map_or(Ok(()), |t| txn(txns, t, "transaction response", false, false, false, true)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_latin1_scenario_is_decoded_as_pugixml_does() {
        let body = b"<scenario>Andr\xe9</scenario>";
        for decl in [&b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>"[..], b"<?xml version='1.0' encoding = 'latin1'?>", b"<?xml encoding=\"iso-8859-1\"?>"] {
            assert_eq!(xml_text(&[decl, body].concat()), format!("{}<scenario>Andr\u{e9}</scenario>", String::from_utf8_lossy(decl)));
        }
        // UTF-8, declared or not; its bytes stay as they are.
        assert_eq!(xml_text("<?xml encoding=\"UTF-8\"?><s>Andr\u{e9}</s>".as_bytes()), "<?xml encoding=\"UTF-8\"?><s>Andr\u{e9}</s>");
        // Undeclared, or declared in an encoding pugixml doesn't know: the
        // bytes that are not UTF-8 stay as they are.
        assert_eq!(&*crate::raw::bytes(&xml_text(b"<s>Andr\xe9</s>")), b"<s>Andr\xe9</s>");
        let cp1252 = b"<?xml version=\"1.0\" encoding=\"windows-1252\"?><s>\x80</s>";
        assert_eq!(&*crate::raw::bytes(&xml_text(cp1252)), cp1252);
        // A UTF-8 BOM goes.
        assert_eq!(xml_text(b"\xef\xbb\xbf<s>Andr\xc3\xa9</s>"), "<s>Andr\u{e9}</s>");
    }

    #[test]
    fn utf16_and_utf32_scenarios_are_decoded_as_pugixml_does() {
        let text = "<?xml version=\"1.0\"?><s>Andr\u{e9} \u{1F600}</s>";
        let utf16: Vec<u16> = text.encode_utf16().collect();
        let le16: Vec<u8> = utf16.iter().flat_map(|u| u.to_le_bytes()).collect();
        let be16: Vec<u8> = utf16.iter().flat_map(|u| u.to_be_bytes()).collect();
        let le32: Vec<u8> = text.chars().flat_map(|c| u32::from(c).to_le_bytes()).collect();
        let be32: Vec<u8> = text.chars().flat_map(|c| u32::from(c).to_be_bytes()).collect();
        for (bom, body) in [(&[0xff, 0xfe][..], &le16), (&[0xfe, 0xff], &be16), (&[0xff, 0xfe, 0, 0], &le32), (&[0, 0, 0xfe, 0xff], &be32)] {
            // With a BOM, which goes, or without, by the "<?" pattern.
            assert_eq!(xml_text(&[bom, body].concat()), text);
            assert_eq!(xml_text(body), text);
        }
        // A '<' and a name, in UTF-16; an odd last byte is left out.
        assert_eq!(xml_text(b"<\0s\0>\0x"), "<s>");
        assert_eq!(xml_text(b"\0<\0s\0>"), "<s>");
        // A lone surrogate is dropped from UTF-16, and given as its bytes
        // from UTF-32, as pugixml writes it.
        assert_eq!(xml_text(b"<\0\x00\xd8s\0\x00\xdc>\0"), "<s>");
        assert_eq!(&*crate::raw::bytes(&xml_text(b"<\0\0\0\x00\xd8\0\0>\0\0\0")), b"<\xed\xa0\x80>");
    }

    fn parse(xml: &str) -> Result<Scenario, String> {
        super::parse(xml, &HashMap::new(), 8)
    }

    fn kinds(s: &Scenario) -> String {
        s.steps
            .iter()
            .map(|s| match &s.op {
                Op::Send { retrans_ms: Some(_), .. } => "S+",
                Op::Send { .. } => "S",
                Op::Recv { optional: true, .. } => "r",
                Op::Recv { .. } => "R",
                Op::Pause { .. } => "P",
                Op::Nop => "N",
                Op::SendCmd { .. } => "C",
                Op::RecvCmd { .. } => "c",
                Op::Timewait { .. } => "T",
            })
            .collect()
    }

    #[test]
    fn builtin_scenarios_parse() {
        let uac = parse(UAC).unwrap();
        assert_eq!(uac.name, "Basic Sipstone UAC");
        assert_eq!(kinds(&uac), "S+rrrRSPS+R");
        assert!(matches!(&uac.steps[8].op, Op::Recv { expect: Expect::Response(200), methods, .. } if methods == "INVITEACKBYE"));

        let uas = parse(UAS).unwrap();
        assert_eq!(kinds(&uas), "RSS+rRST");
        assert!(matches!(&uas.steps[0].op, Op::Recv { expect: Expect::Request(m), .. } if m == "INVITE"));

        assert_eq!(kinds(&parse(OOC_DEFAULT).unwrap()), "RST");
    }

    #[test]
    fn recv_with_request_and_response_matches_the_request() {
        let sc = parse(r#"<scenario><recv request="INVITE" response="183"/></scenario>"#).unwrap();
        assert!(matches!(&sc.steps[0].op, Op::Recv { expect: Expect::Request(m), shown: Some(r), .. } if m == "INVITE" && r == "183"));
        let err = parse(r#"<scenario><recv request="INVITE" response="183" response_txn="t"/></scenario>"#).unwrap_err();
        assert_eq!(err, "response_txn can only be used for received responses.");
    }

    #[test]
    fn builtin_3pcc_scenarios_parse() {
        let kinds: Vec<String> = BUILTIN_3PCC.iter().map(|(_, xml)| kinds(&parse(xml).unwrap())).collect();
        assert_eq!(kinds, ["S+rrrRCcSPS+R", "cS+rrrRSCPS+R", "RSRRST", "RSRRST"]);
    }

    #[test]
    fn actions_labels_and_flow() {
        let s = parse(r#"<scenario>
            <recv request="INVITE" next="ok" test="v" chance="0.5">
              <action>
                <ereg regexp=": *(.*)" search_in="hdr" header="From" assign_to="_,them"/>
                <exec int_cmd="stop_now"/>
              </action>
            </recv>
            <nop condexec="v" condexec_inverse="true"><action><log message="x [$them]"/></action></nop>
            <label id="ok"/>
            <send><![CDATA[SIP/2.0 200 OK]]></send>
          </scenario>"#).unwrap();
        assert_eq!(s.steps[0].next, Some(2));
        assert_eq!(s.steps[0].test.as_deref(), Some("v"));
        assert_eq!(s.steps[0].chance, 0.5);
        assert_eq!(s.steps[0].actions.len(), 2);
        assert!(matches!(&s.steps[0].actions[0], Action::Ereg { source: Source::Hdr { header, .. }, assign_to, .. } if header == "From" && assign_to == &["_", "them"]));
        assert!(matches!(s.steps[1].condexec, Some((ref v, true)) if v == "v"));
    }

    #[test]
    fn pcap_actions_and_their_files() {
        let mut s = parse(r#"<scenario><nop><action>
            <exec play_pcap_video="v.pcap"/><exec play_dtmf="12[$d],100"/><exec play_pcap_audio="g711a.pcap"/>
          </action></nop></scenario>"#).unwrap();
        let a = &s.steps[0].actions;
        assert!(matches!(&a[0], Action::PlayPcap { kind: PcapMedia::Video, file, pcap: None } if file == "v.pcap"));
        assert!(matches!(&a[1], Action::PlayDtmf(_)));
        let dir = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../pcap"));
        let err = s.load_pcaps(dir, &mut Log::default()).unwrap_err();
        assert!(err.contains("v.pcap"), "{err}");
        s.steps[0].actions.remove(0);
        s.load_pcaps(dir, &mut Log::default()).unwrap();
        assert!(matches!(&s.steps[0].actions[1], Action::PlayPcap { pcap: Some(p), .. } if p.packets.len() == 236));
    }

    #[test]
    fn received_rtp_actions() {
        let s = parse(r#"<scenario><nop><action>
            <exec play_pcap_text="t.pcap"/>
            <rtp_stats assign_to="n,pt,p" media="video"/><rtp_dtmf assign_to="d"/><rtp_dtmf assign_to="e" payload_type="0x65"/>
          </action></nop></scenario>"#).unwrap();
        let a = &s.steps[0].actions;
        assert!(matches!(&a[0], Action::PlayPcap { kind: PcapMedia::Text, file, .. } if file == "t.pcap"));
        assert!(matches!(&a[1], Action::RtpStats { video: true, vars } if vars == &["n", "pt", "p"]));
        assert!(matches!(&a[2], Action::RtpDtmf { var, payload_type: 96 } if var == "d"));
        assert!(matches!(&a[3], Action::RtpDtmf { payload_type: 101, .. }));
        assert_eq!(s.counts_received(), Some(1 << 96 | 1 << 101));
        let stats = parse(r#"<scenario><nop><action><rtp_stats assign_to="n"/></action></nop></scenario>"#).unwrap();
        assert_eq!(stats.counts_received(), Some(0));
        assert_eq!(parse("<scenario><nop/></scenario>").unwrap().counts_received(), None);
    }

    #[test]
    fn injection_files_are_checked_at_load() {
        let load = |xml: &str, names: &[&str]| {
            let names = names.iter().map(|n| n.to_string()).collect::<Vec<_>>();
            let mut checks = Checks { inject: (names.clone(), names.first().cloned()), ..Default::default() };
            parse_checked(xml, &HashMap::new(), 8, &mut checks).map(|_| ())
        };
        let send = r#"<scenario><send><![CDATA[INVITE sip:[field0] SIP/2.0]]></send></scenario>"#;
        assert_eq!(load(send, &[]), Err("No injection file was specified!".into()));
        assert_eq!(load(send, &["a.csv"]), Ok(()));
        let log = r#"<scenario><send><![CDATA[INVITE sip:x SIP/2.0]]></send>
            <nop><action><log message="[field1 file=b.csv]"/></action></nop></scenario>"#;
        assert_eq!(load(log, &["a.csv"]), Err("Invalid injection file: b.csv".into()));
        assert_eq!(load(log, &["a.csv", "b.csv"]), Ok(()));
        // Unchecked outside parse_checked().
        assert!(parse(send).is_ok());
    }

    #[test]
    fn what_sipp_dtd_declares() {
        // C 534da44: hiderest= sets hide='s default from its step on.
        let s = parse(
            r#"<scenario><send><![CDATA[INVITE sip:x SIP/2.0]]></send><recv response="100" optional="true" hiderest="true"/>
            <recv response="200" ignoresdp="true"/><nop hiderest="false" hide="true"/><recvCmd optional="global"/><recvCmd/>
            <timewait distribution="uniform" min="10" max="20"/></scenario>"#,
        )
        .unwrap();
        assert_eq!(s.steps.iter().map(|s| s.hide).collect::<Vec<_>>(), [false, true, true, true, false, false, false]);
        assert!(s.steps[2].ignoresdp);
        assert!(matches!(s.steps[4].op, Op::RecvCmd { optional: true, .. }));
        assert!(matches!(s.steps[6].op, Op::Timewait(PauseLen::Dist(_))));
    }

    #[test]
    fn load_errors_are_sipps() {
        let load = |body: &str| {
            let xml = format!("<scenario><send><![CDATA[INVITE sip:x SIP/2.0]]></send>{body}</scenario>");
            parse_checked(&xml, &HashMap::new(), 8, &mut Checks::default()).map(|_| ()).unwrap_err()
        };
        let cases = [
            (r#"<recv response="200"><action><foo/></action></recv>"#, "Unknown action: foo"),
            (r#"<bar/>"#, "Unknown element 'bar' in xml scenario file"),
            (r#"<recv response="200"><action><ereg assign_to="x"/></action></recv>"#, "ereg is missing the required 'regexp' parameter."),
            (r#"<recv response="200"><action><assign value="1"/></action></recv>"#, "assign is missing the required 'assign_to' variable parameter."),
            (r#"<recv response="200" timeout="x"/>"#, r#"message timeout 'timeout' parameter, "x" is not a valid integer!"#),
            (r#"<recv response="200" next="no"/>"#, "The label 'no' was not defined (index 1, next attribute)"),
            (r#"<recv response="200"><action><assign assign_to="a$b" value="1"/></action></recv>"#, "Variable names may not contain '$' or ',' for assign"),
            (r#"<recv response="200"><action><assign assign_to="x" value="1"/></action></recv>"#, "Variable $x is referenced 1 times!"),
            (r#"<recv response="200" response_txn="a$b"/>"#, "Transaction names may not contain '$' or ',' for transaction response"),
            (r#"<recv response="200" counter=""/>"#, "Counter names may not be empty for counter"),
            (r#"<recv response="200" timeout=""/>"#, r#"message timeout 'timeout' parameter, "" is not a valid integer!"#),
            (r#"<recv response="200" rrs=""/>"#, r#"record route set, "" is not a valid boolean!"#),
            (r#"<recv response="200" lost=""/>"#, r#"lost percentage, "" is not a floating point number!"#),
            (r#"<recv response="200"><action><exec rtp_stream="silence.raw,1x,0"/></action></recv>"#, r#"rtp_stream loop count, "1x" is not a valid integer!"#),
            (r#"<recv response="200"><action><exec rtp_stream="apattern,,0"/></action></recv>"#, r#"rtp_stream pattern id, "" is not a valid integer!"#),
            (r#"<recv response="200"><action><exec rtp_stream="apattern,1,x"/></action></recv>"#, r#"rtp_stream payload type, "x" is not a valid integer!"#),
            (r#"<recv response="200"><action><exec rtp_echo="startaudio,x"/></action></recv>"#, r#"rtp_echo payload type, "x" is not a valid integer!"#),
            (r#"<recv response="200"><action><exec rtp_echo="startaudio,13"/></action></recv>"#, "Missing mandatory payload_name parameter in rtp_echo action"),
            (r#"<recv response="200"><action><exec rtp_echo="stopvideo,50,X"/></action></recv>"#, "Unknown static rtp payload type 50 - cannot set playback parameters\n"),
            (r#"<recv response="200"><action><exec rtp_echo="startvideo,96,VP8/90000"/></action></recv>"#, "Unknown dynamic rtp payload type 96 - cannot set playback parameters\n"),
            (r#"<recv response="200"><action><exec rtp_echo="updateaudio,200,X"/></action></recv>"#, "Invalid rtp payload type 200 - cannot set playback parameters\n"),
            (r#"<nop><action><exec rtp_stream="wait" timeout="-1"/></action></nop>"#, "rtp_stream wait timeout must not be negative"),
            (r#"<nop><action><exec rtp_stream="wait" timeout="x"/></action></nop>"#, r#"rtp_stream wait 'timeout' parameter, "x" is not a valid integer!"#),
            (r#"<recv response="100" optional="true"/><pause/>"#, "<recv> before <pause> sequence without a mandatory message. Please remove one 'optional=true' (element 3)."),
            (r#"<recv response="200" rrs="maybe"/>"#, r#"record route set, "maybe" is not a valid boolean!"#),
            (r#"<timewait/><recv response="200"/>"#, "<timewait> can only be the last message in a scenario!"),
            (r#"<recv response="200" response_txn="t"/>"#, "Transaction t is never started!"),
            (r#"<recv response="200"><action><exec foo="x"/></action></recv>"#, "illegal <exec> in the scenario"),
            (r#"<send><![CDATA[SIP/2.0 99 OK]]></send>"#, "Response codes must be in the range of 100-700"),
            (r#"<recv response="200"/"#, "Unable to load default xml scenario file"),
            (r#"<recv response="100" advance_state="false"/>"#, "advance_state is allowed only for optional messages (index = 1)"),
            (r#"<recv response="200" ignoresdp="maybe"/>"#, r#"ignoresdp, "maybe" is not a valid boolean!"#),
            (r#"<send ontimeout="no"><![CDATA[INVITE sip:x SIP/2.0]]></send>"#, "The label 'no' was not defined (index 1, ontimeout attribute)"),
            (r#"<send timeout="x"><![CDATA[INVITE sip:x SIP/2.0]]></send>"#, r#"message send timeout 'timeout' parameter, "x" is not a valid integer!"#),
            (r#"<recvCmd optional="true"/><pause/>"#, "<recv> before <pause> sequence without a mandatory message. Please remove one 'optional=true' (element 3)."),
            (r#"<send response_txn="t"><![CDATA[INVITE sip:x SIP/2.0]]></send>"#, "response_txn can only be used for received responses or sent responses."),
            (r#"<recv request="ACK" start_txn="t"/>"#, "An ACK message can not start a transaction!"),
            (r#"<recv request="INVITE" start_txn="t"/>"#, "Transaction t has no responses defined!"),
            (r#"<recv request="INVITE" dialog="0"/>"#, "dialog must be a positive number, not '0'"),
            (
                r#"<recv request="INVITE" start_txn="t"/><send response_txn="t"><![CDATA[SIP/2.0 200 OK]]></send><recv response="200" response_txn="t"/>"#,
                "Transaction t is started by a received request: it takes no received responses or ACK!",
            ),
            (r#"<send start_txn="t"><![CDATA[OPTIONS sip:x SIP/2.0]]></send><recv request="INFO" start_txn="t"/>"#, "Transaction t is started by both a sent and a received message"),
            (
                r#"<send start_txn="t"><![CDATA[OPTIONS sip:x SIP/2.0]]></send><recv response="200" response_txn="t"/><send response_txn="t"><![CDATA[SIP/2.0 200 OK]]></send>"#,
                "Transaction t is started by a sent request: it takes no sent responses!",
            ),
        ];
        for (body, err) in cases {
            assert_eq!(load(body), err, "{body}");
        }
        // Referenced twice, and _unexp.retaddr also by SIPp itself.
        let ok = r#"<scenario><send><![CDATA[INVITE sip:x SIP/2.0]]></send>
            <recv response="200"><action><assign assign_to="x" value="1"/><log message="[$x]"/></action></recv>
            <label id="_unexp.main"/><nop><action><jump variable="_unexp.retaddr"/></action></nop></scenario>"#;
        assert!(parse_checked(ok, &HashMap::new(), 8, &mut Checks::default()).is_ok());
        // An <exec lua> may use any variable, so once is enough, and the
        // scenario keeps the names for it.
        let lua = r#"<scenario><send><![CDATA[INVITE sip:x SIP/2.0]]></send>
            <recv response="200"><action><assign assign_to="x" value="1"/><exec lua="f [$y]"/></action></recv></scenario>"#;
        let lua = parse_checked(lua, &HashMap::new(), 8, &mut Checks::default());
        if crate::lua::BUILT_IN {
            let mut names: Vec<_> = lua.unwrap().var_names.into_iter().collect();
            names.sort();
            assert_eq!(names, ["x", "y"]);
        } else {
            assert!(lua.unwrap_err().contains("does not have Lua support"));
        }
        assert_eq!(parse("<scenario/>").unwrap_err(), "Did not find any messages inside of scenario!");
        let other_dialog = r#"<scenario><recv request="INVITE" dialog="2"/></scenario>"#;
        assert_eq!(parse(other_dialog).unwrap_err(), r#"A call begins in dialog 1: its first message can not have dialog="2""#);
    }

    #[test]
    fn attribute_escapes_are_sipps() {
        // xp_process_escapes(): five escapes, other pairs kept, a lone
        // backslash at the end too.
        assert_eq!(process_escapes(r#"a\\b\"c\nd\te\rf\qg\x5bh\"#), "a\\b\"c\nd\te\rf\\qg\\x5bh\\");
        let s = parse(r#"<scenario name="a\tb"><send><![CDATA[INVITE sip:x SIP/2.0]]></send>
            <recv response="200"><action>
              <ereg regexp="[0-9]\\.x\\\\&amp;lt;" search_in="msg" assign_to="m"/>
              <strcmp assign_to="r" variable="m" value="&amp;amp;\n"/>
              <log message="a\nb&amp;gt;"/>
            </action></recv></scenario>"#).unwrap();
        assert_eq!(s.name, "a\tb");
        let a = &s.steps[1].actions;
        let Action::Ereg { re, .. } = &a[0] else { panic!() };
        // XML entities are decoded once: "[0-9]\.x\\&lt;" is a digit, a
        // dot, "x\&lt;".
        assert!(re.is_match("1.x\\&lt;") && !re.is_match("1.x\\<"));
        assert!(matches!(&a[1], Action::Strcmp { rhs: Operand::Value(v), .. } if v == "&amp;\n"));
        assert!(matches!(&a[2], Action::Log(t) if t.source == "a\nb&gt;"));
    }

    #[test]
    fn default_messages_are_read_as_sipps() {
        let send = "<send><![CDATA[INVITE sip:x SIP/2.0]]></send>";
        let s = parse(&format!(r#"<scenario><DefaultMessage id="ack"><![CDATA[
            ACK sip:[remote_ip] SIP/2.0
            ]]></DefaultMessage>{send}<DefaultMessage id="ack2"><![CDATA[ACK x SIP/2.0]]></DefaultMessage></scenario>"#)).unwrap();
        let ids: Vec<&str> = s.default_messages.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!((ids, s.steps.len()), (vec!["ack", "ack2"], 1));
        let err = |dm: &str| parse(&format!("<scenario>{dm}{send}</scenario>")).unwrap_err();
        assert_eq!(err(r#"<DefaultMessage id="x"><![CDATA[ACK x SIP/2.0]]></DefaultMessage>"#), "Internal Error: Unknown default message: x!");
        assert_eq!(err(r#"<DefaultMessage><![CDATA[ACK x SIP/2.0]]></DefaultMessage>"#), "DefaultMessage is missing the required 'id' parameter.");
        assert_eq!(err(r#"<DefaultMessage id="x"/>"#), "No CDATA in 'send' section of xml scenario file");
        assert_eq!(err(r#"<DefaultMessage id="bye"><![CDATA[SIP/2.0 99 x]]></DefaultMessage>"#), "Response codes must be in the range of 100-700");
        assert_eq!(err(r#"<init><DefaultMessage id="bye"/></init>"#), "Invalid element in an init stanza: 'DefaultMessage'");
    }

    #[test]
    fn unsupported_features_fail_loudly() {
        assert!(parse(r#"<scenario><recv response="200" lost="x"/></scenario>"#).unwrap_err().contains("lost"));
        assert!(parse(r#"<scenario><recv response="200"><action><exec verbose="x"/></action></recv></scenario>"#).is_err());
        assert!(parse(r#"<scenario><recv response="200" next="nowhere"/></scenario>"#).unwrap_err().contains("nowhere"));
        assert!(parse(r#"<scenario><sendCmd/></scenario>"#).unwrap_err().contains("sendCmd"));
    }
}

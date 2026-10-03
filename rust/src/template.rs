//! Message templates: the text of a <send> (or an action's message), with
//! its [keywords].

use crate::infile::Injection;
use crate::sip;
use crate::srtp::{self, MediaCrypto, Suite};
use crate::vars::Vars;
use std::cell::Cell;
use std::collections::HashMap;
use std::sync::Arc;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq)]
pub enum Kw {
    Service,
    RemoteIp,
    RemotePort,
    Transport,
    LocalIp,
    LocalPort,
    LocalIpType,
    MediaIp,
    MediaIpType,
    MediaPort,
    /// [auto_media_port]: [media_port], four more per call.
    AutoMediaPort,
    RemoteHost,
    /// [server_ip]: the address of the call's own socket.
    ServerIp,
    /// [dynamic_id]: SIPp's shared counter (see `dynamic`).
    DynamicId,
    MsgIndex,
    LastMessage,
    ClockTick,
    Timestamp,
    SippVersion,
    CallNumber,
    TdmMap,
    /// A keyword from a -plugin, and the text after its name.
    Plugin { id: usize, args: String },
    /// [users]: the -users count (-1 without), and [userid]: this call's user.
    Users,
    UserId,
    CallId,
    Pid,
    Branch,
    Len,
    Cseq,
    PeerTagParam,
    Routes,
    NextUrl,
    LastRequestUri,
    LastCseqNumber,
    Date,
    RtpstreamAudioPort,
    RtpstreamVideoPort,
    /// SDP crypto: [cryptotag1audio], [cryptosuite...2video], [cryptokeyparams1audio], ...
    Crypto(Crypto),
    /// [last_Via:] and friends: the named header of the last message received.
    LastHeader(String),
    /// [last_From.value]: the same without the header's name.
    LastHeaderValue(String),
    /// [$name]
    Var(String),
    /// [fieldN file="..." line="..."]
    Field { n: usize, file: Option<String>, line: Option<Box<Template>> },
    /// [file name="..."]: the file's bytes as they are, its name a
    /// message of its own.
    File(Box<Template>),
    /// [authentication username=... password=...]: credentials for the
    /// last challenge, filled in once the rest of the message is known.
    /// [authentication username= password= aka_K= aka_OP= aka_AMF=]; aka_K
    /// defaults to the password's text, unrendered, as SIPp.
    Auth { user: Option<Box<Template>>, pass: Option<Box<Template>>, aka: [Option<Box<Template>>; 3] },
}

#[derive(Debug, Clone, PartialEq)]
enum Part {
    Lit(String),
    /// A keyword and the offset written after it, as in [local_port+1].
    Kw(Kw, i64),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Template {
    lines: Vec<Vec<Part>>,
    has_body_separator: bool,
    /// The text ended in a newline, so the last line keeps its CRLF.
    trailing_newline: bool,
    /// It has srtp_keywords(), which most messages have none of.
    srtp: bool,
    /// The text as the scenario gave it, for the variables screen.
    pub source: String,
}

/// Values a template is rendered with.
pub struct Ctx<'a> {
    pub service: &'a str,
    pub remote_ip: &'a str,
    pub remote_port: u16,
    pub local_ip: &'a str,
    pub local_port: u16,
    /// -mi, else the local IP: [media_ip] has no brackets, as SIPp's.
    pub media_ip: IpAddr,
    pub media_ip_text: &'a str,
    pub media_port: u16,
    /// The call's RTP socket ports, for [rtpstream_audio_port] and [rtpstream_video_port].
    pub rtp_port: u16,
    pub rtp_video_port: u16,
    /// Audio and video SRTP state, for the crypto keywords.
    pub crypto: Option<[&'a MediaCrypto; 2]>,
    pub ipv6: bool,
    pub transport: &'a str,
    pub pid: u32,
    pub call_number: u64,
    pub users: Option<u32>,
    pub user_id: u32,
    pub call_id: &'a str,
    pub msg_index: usize,
    pub cseq: u32,
    pub last_recv: Option<&'a str>,
    /// The remote host as given, the call socket's address, and -rfc3339.
    pub remote_host: &'a str,
    pub server_ip: Option<IpAddr>,
    pub rfc3339: bool,
    pub peer_tag: Option<&'a str>,
    pub routes: Option<&'a str>,
    pub next_url: &'a str,
    pub vars: &'a Vars,
    pub inject: Option<(&'a Injection, &'a HashMap<String, usize>)>,
    pub auth: Option<&'a AuthCtx>,
    /// -tdmmap: the call's circuit.
    pub tdmmap: Option<&'a str>,
    /// abortCall()'s BYE after a request from the peer: [last_From] is its
    /// To, [last_To] its From, and [last_cseq_number] our [cseq].
    pub bye_after_peer_request: bool,
}

/// A crypto keyword: which media, which of the two offered lines, and what.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Crypto {
    pub video: bool,
    pub slot: usize,
    pub what: CryptoWhat,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CryptoWhat {
    Tag,
    Suite(Suite),
    Key,
    /// [ueaescm128sha180...]: UNENCRYPTED_SRTP for that line, of that suite.
    Unencrypted(Suite),
}

fn crypto_keyword(name: &str) -> Option<Crypto> {
    let (rest, video) = match (name.strip_suffix("audio"), name.strip_suffix("video")) {
        (Some(r), _) => (r, false),
        (_, Some(r)) => (r, true),
        _ => return None,
    };
    let slot = match rest.as_bytes().last()? {
        b'1' => 0,
        b'2' => 1,
        _ => return None,
    };
    let what = match &rest[..rest.len() - 1] {
        "cryptotag" => CryptoWhat::Tag,
        "cryptokeyparams" => CryptoWhat::Key,
        "cryptosuiteaescm128sha180" => CryptoWhat::Suite(Suite::AesCm128Sha1_80),
        "cryptosuiteaescm128sha132" => CryptoWhat::Suite(Suite::AesCm128Sha1_32),
        "cryptosuiteaescm192sha180" => CryptoWhat::Suite(Suite::AesCm192Sha1_80),
        "cryptosuiteaescm192sha132" => CryptoWhat::Suite(Suite::AesCm192Sha1_32),
        "cryptosuiteaescm256sha180" => CryptoWhat::Suite(Suite::AesCm256Sha1_80),
        "cryptosuiteaescm256sha132" => CryptoWhat::Suite(Suite::AesCm256Sha1_32),
        "cryptosuitenullsha180" => CryptoWhat::Suite(Suite::NullSha1_80),
        "cryptosuitenullsha132" => CryptoWhat::Suite(Suite::NullSha1_32),
        "ueaescm128sha180" => CryptoWhat::Unencrypted(Suite::AesCm128Sha1_80),
        "ueaescm128sha132" => CryptoWhat::Unencrypted(Suite::AesCm128Sha1_32),
        _ => return None,
    };
    Some(Crypto { video, slot, what })
}

/// What [authentication] needs: the challenge and SIPp's defaults.
pub struct AuthCtx {
    pub challenge: String,
    /// 401 means Authorization, 407 Proxy-Authorization.
    pub code: u16,
    pub nonce_count: u32,
    pub cnonce: String,
    pub uri: String,
    pub user: String,
    pub pass: String,
}

/// Stand in for [len] and [authentication] until the body is known.
const LEN_MARK: char = '\u{FFFF}';
const AUTH_MARK: char = '\u{FFFE}';

/// SIPp's KEYWORD_SIZE: the longest [keyword], and parameter value.
const KEYWORD_SIZE: usize = 256;

/// closing_quote(): the '"' that ends the quoted string at `i`, or the end
/// of its line, past the characters escaped with '\\'.
fn closing_quote(b: &[u8], mut i: usize) -> usize {
    while i < b.len() {
        match b[i] {
            b'\\' if i + 1 < b.len() => i += 2,
            b'"' | b'\n' => return i,
            _ => i += 1,
        }
    }
    i
}

/// closing_bracket(): the ']' that closes the '[' before `s`, past quoted
/// strings and the [keyword]s nested in it.
fn closing_bracket(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    let (mut i, mut depth) = (0, 0);
    while i < b.len() {
        match b[i] {
            b'"' => {
                i = closing_quote(b, i + 1);
                if i == b.len() {
                    return None;
                }
            }
            b'[' => depth += 1,
            b']' if depth == 0 => return Some(i),
            b']' => depth -= 1,
            _ => {}
        }
        i += 1;
    }
    None
}

/// find_param(): where `param` ("username=") starts a word of the keyword
/// `s`, not in a quoted string or a nested [keyword].
fn find_param(s: &str, param: &str) -> Option<usize> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'"' => {
                i = closing_quote(b, i + 1);
                if i == b.len() {
                    return None;
                }
            }
            b'[' => i += 1 + closing_bracket(&s[i + 1..])?,
            _ if (i == 0 || b[i - 1].is_ascii_whitespace()) && b[i..].starts_with(param.as_bytes()) => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

/// getKeywordParam(): the value of `param` ("username=") in the keyword
/// `kw`, empty without one: "0x" hex digits as their bytes (if
/// `decode_hex`), a quoted string with its '\\' escapes, or the text up to
/// a space or the ']', nested [keyword]s included.
fn keyword_param(kw: &str, param: &str, decode_hex: bool) -> Result<String, String> {
    let Some(at) = find_param(kw, param) else { return Ok(String::new()) };
    let start = at + param.len();
    let value = &kw[start..];
    if let Some(hex) = value.strip_prefix("0x").filter(|_| decode_hex) {
        let digits: Vec<u8> = hex.bytes().take_while(u8::is_ascii_hexdigit).collect();
        let bytes: Vec<u8> = digits.chunks(2).map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap()).collect();
        return Ok(crate::raw::text_owned(bytes));
    }
    if let Some(quoted) = value.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = quoted.chars();
        while let Some(c) = chars.next() {
            match c {
                '"' => break,
                '\\' => match chars.next() {
                    Some(c) => out.push(c),
                    None => break,
                },
                c => out.push(c),
            }
        }
        return Ok(out);
    }
    let b = kw.as_bytes();
    let mut k = start;
    let syntax = || format!("Syntax error parsing '{param}' parameter");
    while k < b.len() {
        if k > KEYWORD_SIZE {
            return Err(syntax());
        } else if b[k] == b'[' {
            // Past a whole nested [keyword]
            k += 1 + closing_bracket(&kw[k + 1..]).ok_or_else(syntax)?;
        } else if b[k] == b']' || b[k] < 33 || b[k] > 126 {
            break;
        }
        k += 1;
    }
    Ok(kw[start..k.min(b.len())].to_string())
}

/// Splits "local_port+1" into the name and offset. Like SIPp, only a sign
/// followed by a digit starts an offset, '+' before '-'.
fn split_offset(name: &str) -> (&str, i64) {
    for sign in ['+', '-'] {
        if let Some(pos) = name.find(sign) {
            if name[pos + 1..].starts_with(|c: char| c.is_ascii_digit()) {
                let digits: String = name[pos + 1..].chars().take_while(char::is_ascii_digit).collect();
                let n: i64 = digits.parse().unwrap_or(0);
                return (&name[..pos], if sign == '-' { -n } else { n });
            }
        }
    }
    (name, 0)
}

fn keyword(full: &str, keys: &HashMap<String, String>) -> Result<Part, String> {
    let (head, args) = full.split_once(char::is_whitespace).unwrap_or((full, ""));
    // As in SIPp, plugins come first and may replace our own keywords.
    if let Some(id) = crate::plugin::lookup(head) {
        return Ok(Part::Kw(Kw::Plugin { id, args: args.trim().to_string() }, 0));
    }
    // A parameter's value is a message of its own, keywords included.
    let template = |text: &str| -> Result<Option<Box<Template>>, String> {
        Ok(if text.is_empty() { None } else { Some(Box::new(Template::parse_line(text, keys)?)) })
    };
    if head == "authentication" {
        let user = template(&keyword_param(full, "username=", true)?)?;
        let pass = template(&keyword_param(full, "password=", true)?)?;
        // The AKA keys stay text, "0x" included, for the AKA code to
        // decode. Without aka_K, the password is the key.
        let mut k = keyword_param(full, "aka_K=", false)?;
        if k.is_empty() {
            k = keyword_param(full, "password=", false)?;
        }
        let aka = [template(&k)?, template(&keyword_param(full, "aka_OP=", false)?)?, template(&keyword_param(full, "aka_AMF=", false)?)?];
        return Ok(Part::Kw(Kw::Auth { user, pass, aka }, 0));
    }
    if let Some(n) = head.strip_prefix("field").and_then(|n| n.parse().ok()) {
        let file = Some(keyword_param(full, "file=", true)?).filter(|f| !f.is_empty());
        crate::scenario::check_field_file(file.as_deref())?;
        let line = template(&keyword_param(full, "line=", true)?)?;
        return Ok(Part::Kw(Kw::Field { n, file, line }, 0));
    }
    // SIPp takes any keyword that starts with "file", after "field".
    if head.starts_with("file") {
        let name = template(&keyword_param(full, "name=", true)?)?.ok_or("No name specified for 'file' keyword!")?;
        return Ok(Part::Kw(Kw::File(name), 0));
    }
    let (name, offset) = split_offset(full);
    let kw = match name {
        "service" => Kw::Service,
        "remote_ip" => Kw::RemoteIp,
        "remote_port" => Kw::RemotePort,
        "transport" => Kw::Transport,
        "local_ip" => Kw::LocalIp,
        "local_port" => Kw::LocalPort,
        "local_ip_type" => Kw::LocalIpType,
        "media_ip" => Kw::MediaIp,
        "media_ip_type" => Kw::MediaIpType,
        "media_port" => Kw::MediaPort,
        "auto_media_port" => Kw::AutoMediaPort,
        "remote_host" => Kw::RemoteHost,
        "server_ip" => Kw::ServerIp,
        "dynamic_id" => Kw::DynamicId,
        "msg_index" => Kw::MsgIndex,
        "last_message" => Kw::LastMessage,
        "clock_tick" => Kw::ClockTick,
        "timestamp" => Kw::Timestamp,
        "sipp_version" => Kw::SippVersion,
        "call_number" => Kw::CallNumber,
        "tdmmap" => Kw::TdmMap,
        "users" => Kw::Users,
        "userid" => Kw::UserId,
        "call_id" => Kw::CallId,
        "pid" => Kw::Pid,
        "branch" => Kw::Branch,
        "len" => Kw::Len,
        "cseq" => Kw::Cseq,
        "peer_tag_param" => Kw::PeerTagParam,
        "routes" => Kw::Routes,
        "next_url" => Kw::NextUrl,
        "last_Request_URI" => Kw::LastRequestUri,
        "last_cseq_number" => Kw::LastCseqNumber,
        "date" => Kw::Date,
        "rtpstream_audio_port" => Kw::RtpstreamAudioPort,
        "rtpstream_video_port" => Kw::RtpstreamVideoPort,
        _ => {
            if let Some(c) = crypto_keyword(name) {
                Kw::Crypto(c)
            } else if let Some(var) = name.strip_prefix('$') {
                Kw::Var(crate::scenario::var(var, "Variable keyword")?)
            } else if let Some(header) = name.strip_prefix("last_").filter(|h| !h.is_empty()) {
                // "From" or "From:": the name without the colon.
                let name = |h: &str| h.strip_suffix(':').unwrap_or(h).to_string();
                match header.strip_suffix(".value").filter(|h| !h.is_empty()) {
                    Some(h) => Kw::LastHeaderValue(name(h)),
                    None => Kw::LastHeader(name(header)),
                }
            } else if let Some(value) = keys.get(name) {
                // -key values are plain text, fixed when the scenario loads.
                return Ok(Part::Lit(value.clone()));
            } else {
                return Err(format!("Unsupported keyword '{name}' in xml scenario file"));
            }
        }
    };
    Ok(Part::Kw(kw, offset))
}

/// SIPp's \xNN escapes, as in \x5b for a '[' that isn't a keyword: any
/// byte, UTF-8 or not (raw). A newline in the text (an attribute's \n)
/// is a CRLF, as SendingMessage makes it; one written \x0a is not.
fn unescape(text: &str) -> Result<String, String> {
    if !text.contains("\\x") {
        return Ok(text.replace('\n', "\r\n"));
    }
    let bytes = crate::raw::bytes(text);
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            // One or two hex digits make a byte; a "\x" without one stays
            // as it is.
            b'\\' if bytes.get(i + 1) == Some(&b'x') && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit) => {
                let digits = bytes[i + 2..].iter().take(2).take_while(|b| b.is_ascii_hexdigit()).count();
                out.push(u8::from_str_radix(std::str::from_utf8(&bytes[i + 2..i + 2 + digits]).unwrap(), 16).unwrap());
                i += 2 + digits;
                continue;
            }
            b'\n' => out.extend_from_slice(b"\r\n"),
            b => out.push(b),
        }
        i += 1;
    }
    Ok(crate::raw::text_owned(out))
}

/// `newline_after`: the text is a line followed by a '\n', which SIPp
/// quotes in a syntax error; it quotes none for a last line.
fn parse_line(line: &str, keys: &HashMap<String, String>, newline_after: bool) -> Result<Vec<Part>, String> {
    let mut parts = Vec::new();
    let mut rest = line;
    while let Some(open) = rest.find('[') {
        // Brackets nest: [authentication username=[field0]]. A literal '['
        // is written \x5B.
        let close = closing_bracket(&rest[open + 1..]).filter(|&len| len > 0 && len <= KEYWORD_SIZE);
        let Some(close) = close else {
            let at = line.len() - rest.len() + open;
            let begin = line[..at].rfind('\n').map_or(0, |i| i + 1);
            let current = match line[at..].find('\n') {
                Some(end) => &line[begin..at + end],
                None if newline_after => &line[begin..],
                None => "",
            };
            return Err(format!("Syntax error or invalid [keyword] in scenario while parsing '{current}'"));
        };
        if open > 0 {
            parts.push(Part::Lit(unescape(&rest[..open])?));
        }
        parts.push(keyword(&rest[open + 1..open + 1 + close], keys)?);
        rest = &rest[open + close + 2..];
    }
    if !rest.is_empty() {
        parts.push(Part::Lit(unescape(rest)?));
    }
    Ok(parts)
}

impl Template {
    /// SIPp's clean_cdata(): whitespace around the text goes, every line
    /// loses its indentation, headers without a body get their blank line,
    /// and lines end in CRLF. A body keeps a final CRLF only if the text had
    /// a newline after it.
    pub fn parse(text: &str, keys: &HashMap<String, String>) -> Result<Template, String> {
        let blank = |c: char| c == ' ' || c == '\t' || c == '\n' || c == '\r';
        let body = text.trim_start_matches(blank);
        let trimmed = body.trim_end_matches(blank);
        let trailing_newline = body[trimmed.len()..].contains('\n');
        let lines: Vec<&str> = trimmed.split('\n').map(|l| l.trim_matches([' ', '\t', '\r'])).collect();
        let has_body_separator = lines.iter().any(|l| l.is_empty());
        // SIPp ends a message without a body in a blank line: a '\n' after each.
        let newline_after = |i: usize| i + 1 < lines.len() || !has_body_separator;
        let lines = lines.iter().enumerate().map(|(i, l)| parse_line(l, keys, newline_after(i))).collect::<Result<_, _>>()?;
        Ok(Template { source: text.to_string(), has_body_separator, trailing_newline, srtp: false, lines }.with_srtp())
    }

    fn with_srtp(mut self) -> Template {
        let srtp = self.srtp_keywords().next().is_some();
        self.srtp = srtp;
        self
    }

    /// A <DefaultMessage>: clean_cdata() without the final newline a
    /// <send>'s body gets back.
    pub fn parse_default(text: &str, keys: &HashMap<String, String>) -> Result<Template, String> {
        Ok(Template { trailing_newline: false, ..Template::parse(text, keys)? })
    }

    /// A one-line text, such as a <log message> or <exec command>, taken as is.
    pub fn parse_line(text: &str, keys: &HashMap<String, String>) -> Result<Template, String> {
        Ok(Template {
            lines: vec![parse_line(text, keys, false)?],
            has_body_separator: true,
            trailing_newline: false,
            srtp: false,
            source: text.to_string(),
        }
        .with_srtp())
    }

    /// Uses [authentication], so the call has to supply a challenge; an
    /// injected [fieldN] may hold one too.
    pub fn uses_auth(&self) -> bool {
        self.lines.iter().flatten().any(|p| matches!(p, Part::Kw(Kw::Auth { .. } | Kw::Field { .. }, _)))
    }

    /// SIPp's pcap play source ports: each [media_port] or [auto_media_port]
    /// on a line whose text before it names audio, image or video, or has
    /// m=text (in that order), with the port it renders.
    pub fn media_ports(&self, c: &Ctx) -> Vec<(&'static str, u16)> {
        const KINDS: [(&str, &str); 4] = [("audio", "audio"), ("image", "image"), ("video", "video"), ("m=text", "text")];
        let mut out = Vec::new();
        let mut before = String::with_capacity(128);
        // Only the lines with a media port: most have none.
        for line in self.lines.iter().filter(|l| l.iter().any(|p| matches!(p, Part::Kw(Kw::MediaPort | Kw::AutoMediaPort, _)))) {
            before.clear();
            for part in line {
                match part {
                    Part::Lit(s) => before += s,
                    Part::Kw(kw @ (Kw::MediaPort | Kw::AutoMediaPort), offset) => {
                        let port = value(kw, *offset, c);
                        if let Some((_, kind)) = KINDS.into_iter().find(|(k, _)| before.contains(k)) {
                            out.push((kind, port.parse().unwrap_or(0)));
                        }
                        before += &port;
                    }
                    Part::Kw(..) => {}
                }
            }
        }
        out
    }

    /// Uses [media_port] or [auto_media_port], whose ports a pcap play
    /// sends from.
    pub fn uses_media_port(&self) -> bool {
        self.lines.iter().flatten().any(|p| matches!(p, Part::Kw(Kw::MediaPort | Kw::AutoMediaPort, _)))
    }

    /// Uses [rtpstream_audio_port], so the call needs its RTP socket first.
    pub fn uses_rtp_port(&self) -> bool {
        self.lines.iter().flatten().any(|p| matches!(p, Part::Kw(Kw::RtpstreamAudioPort, _)))
    }

    /// Whether [call_id] is rendered, in the text or in a keyword's own.
    pub fn uses_call_id(&self) -> bool {
        self.lines.iter().flatten().any(|p| match p {
            Part::Kw(Kw::CallId, _) => true,
            Part::Kw(Kw::Field { line: Some(t), .. } | Kw::File(t), _) => t.uses_call_id(),
            Part::Kw(Kw::Auth { user, pass, aka }, _) => [user, pass].into_iter().chain(aka).flatten().any(|t| t.uses_call_id()),
            _ => false,
        })
    }

    /// The same for [rtpstream_video_port] (not [rtpstream_video_port+N],
    /// which only shows the port, as in SIPp).
    pub fn uses_rtp_video_port(&self) -> bool {
        self.lines.iter().flatten().any(|p| matches!(p, Part::Kw(Kw::RtpstreamVideoPort, 0)))
    }

    /// Whether it has srtp_keywords(), known once.
    pub fn has_srtp_keywords(&self) -> bool {
        self.srtp
    }

    /// The crypto keywords in order, with their offsets, which set the
    /// call's SRTP state before the message is rendered, and among them
    /// [rtpstream_audio_port] and [rtpstream_video_port].
    pub fn srtp_keywords(&self) -> impl Iterator<Item = (&Kw, i64)> {
        self.lines.iter().flatten().filter_map(|p| match p {
            Part::Kw(kw @ (Kw::Crypto(_) | Kw::RtpstreamAudioPort | Kw::RtpstreamVideoPort), offset) => Some((kw, *offset)),
            _ => None,
        })
    }

    /// The request method, when the template starts with one.
    /// A response's status code, from its start line.
    pub fn response_code(&self) -> Option<u16> {
        match self.lines.first()?.first()? {
            Part::Lit(s) => s.strip_prefix("SIP/2.0 ")?.get(..3)?.parse().ok(),
            _ => None,
        }
    }

    /// SendingMessage's check of a <send>: the method, or "SIP/2.0" and a
    /// response code, as literal text up front.
    pub fn check_start_line(&self) -> Result<(), String> {
        // The literal text up to the first keyword, lines ending in CRLF.
        let mut first = String::new();
        let mut keyword = false;
        'lines: for line in &self.lines {
            for part in line {
                match part {
                    Part::Lit(s) => first += s,
                    Part::Kw(..) => {
                        keyword = true;
                        break 'lines;
                    }
                }
            }
            first += "\r\n";
        }
        if !keyword && !self.has_body_separator {
            first += "\r\n";
        }
        let Some((method, rest)) = first.split_once(' ') else {
            // clean_cdata()'s text.
            let blank = |c: char| c == ' ' || c == '\t' || c == '\n';
            let lines: Vec<&str> = self.source.trim_matches(blank).split('\n').map(|l| l.trim_matches([' ', '\t'])).collect();
            let mut text = lines.join("\n");
            if !text.contains("\n\n") {
                text += "\n\n";
            }
            return Err(format!("You can not use a keyword for the METHOD or to generate \"SIP/2.0\" to ensure proper [cseq] operation!\n{text}\n"));
        };
        if method == "SIP/2.0" {
            let q = rest.trim_start();
            let digits = q.len() - q.trim_start_matches(|c: char| c.is_ascii_digit()).len();
            if q[digits..].starts_with(|c: char| !c.is_ascii_whitespace()) {
                return Err(format!("Invalid reply code: {q}"));
            }
            let code: u64 = q[..digits].parse().unwrap_or(0);
            if !(100..700).contains(&code) {
                return Err("Response codes must be in the range of 100-700".into());
            }
        }
        Ok(())
    }

    pub fn method(&self) -> Option<&str> {
        match self.lines.first()?.first()? {
            Part::Lit(s) if !s.starts_with("SIP/2.0") => s.split(' ').next().filter(|m| !m.is_empty()),
            _ => None,
        }
    }

    /// For one-line templates: the text without a line ending.
    pub fn render_line(&self, c: &Ctx) -> String {
        self.render(c)
    }

    pub fn render(&self, c: &Ctx) -> String {
        let mut out = String::with_capacity(1024);
        self.render_into(c, &mut out);
        // A call keeps what it sent, for retransmissions: its size, not
        // the room it was rendered in.
        out.shrink_to_fit();
        out
    }

    /// render(), in the room of the last message rendered so, then copied
    /// once into what a call keeps.
    pub fn render_shared(&self, c: &Ctx) -> Arc<str> {
        thread_local! {
            static ROOM: Cell<String> = const { Cell::new(String::new()) };
        }
        let mut out = ROOM.take();
        out.clear();
        out.reserve(1024);
        self.render_into(c, &mut out);
        let text = Arc::from(out.as_str());
        ROOM.set(out);
        text
    }

    fn render_into(&self, c: &Ctx, out: &mut String) {
        let mut auth_user_pass = None;
        let mut first = true;
        let mut suppress = Suppress::Off;
        for line in &self.lines {
            let mark = out.len();
            if !first {
                push_lit(out, "\r\n", &mut suppress);
            }
            let start = out.len();
            // SIPp drops the rest of a line's CRLF when a keyword at its start
            // comes out empty ([last_*], [$var], [fieldN], [routes]), so a
            // missing header doesn't leave a blank line that ends the headers.
            let mut dropped = false;
            render_parts(line, c, out, start, &mut dropped, &mut suppress, &mut auth_user_pass);
            if dropped && out[start..].trim().is_empty() {
                out.truncate(mark);
                continue;
            }
            first = false;
        }
        if !self.has_body_separator {
            push_lit(out, "\r\n\r\n", &mut suppress);
        } else if self.trailing_newline {
            push_lit(out, "\r\n", &mut suppress);
        }
        if out.contains(LEN_MARK) {
            // A [len] in the body counts as the 5 bytes it becomes.
            let mark = |t: &str| t.matches(LEN_MARK).count() * (5 - LEN_MARK.len_utf8());
            let body_len = sip::body_start(out).map_or(0, |end| crate::raw::len(&out[end + 4..]) + mark(&out[end..]));
            let len = format!("{body_len:5}");
            // In place, from the last: the message is not copied.
            let mut end = out.len();
            while let Some(i) = out[..end].rfind(LEN_MARK) {
                out.replace_range(i..i + LEN_MARK.len_utf8(), &len);
                end = i;
            }
        }
        if let Some(args) = auth_user_pass {
            *out = out.replace(AUTH_MARK, &authorization(out, c, &args));
        }
    }
}

/// Renders `parts` onto `text`, whose current line began at `start`.
/// What [authentication] asks for, filled in once the message is whole.
pub struct AuthArgs {
    user: String,
    pass: String,
    aka: Option<crate::auth::Aka>,
}

/// SIPp's suppresscrlf: after a [$var], [last_*] or [fieldN] whose value
/// ends a line, the text up to the next keyword loses its leading
/// whitespace, so the value's CRLF isn't followed by another.
#[derive(PartialEq)]
enum Suppress {
    Off,
    On,
    /// Only whitespace so far in the text after the value.
    InText,
}

fn push_lit(text: &mut String, s: &str, suppress: &mut Suppress) {
    if *suppress == Suppress::Off {
        *text += s;
        return;
    }
    let rest = s.trim_start();
    *text += rest;
    *suppress = if rest.is_empty() { Suppress::InText } else { Suppress::Off };
}

fn render_parts(parts: &[Part], c: &Ctx, text: &mut String, start: usize, dropped: &mut bool, suppress: &mut Suppress, auth: &mut Option<AuthArgs>) {
    for part in parts {
        // A keyword ends the text that suppresscrlf applies to.
        if matches!(part, Part::Kw(..)) && *suppress == Suppress::InText {
            *suppress = Suppress::Off;
        }
        match part {
            Part::Lit(s) => push_lit(text, s, suppress),
            Part::Kw(Kw::Auth { user, pass, aka }, _) => {
                let (du, dp) = c.auth.map(|a| (a.user.as_str(), a.pass.as_str())).unwrap_or(("", ""));
                let user = user.as_ref().map_or(du.to_string(), |t| t.render_line(c));
                let pass = pass.as_ref().map_or(dp.to_string(), |t| t.render_line(c));
                let render = |t: &Option<Box<Template>>| t.as_ref().map(|t| t.render_line(c));
                // Without aka_K= or password=, aka_K is -ap.
                let k = render(&aka[0]).or_else(|| Some(dp.to_string()));
                // aka_AMF is taken, and ignored, as by SIPp.
                let aka = crate::auth::Aka::from_strings(k.as_deref(), render(&aka[1]).as_deref());
                *auth = Some(AuthArgs { user, pass, aka });
                text.push(AUTH_MARK);
            }
            Part::Kw(kw, offset) => {
                let at = text.len();
                write_value(kw, *offset, c, text);
                // SIPp expands an [authentication] keyword found in injected text.
                if matches!(kw, Kw::Field { .. }) && text[at..].contains("[authentication") {
                    let v = text.split_off(at);
                    if let Ok(t) = Template::parse_line(&v, &HashMap::new()) {
                        render_parts(&t.lines[0], c, text, start, dropped, suppress, auth);
                        continue;
                    }
                    *text += &v;
                }
                if text.len() == at && at == start && droppable(kw, c) {
                    *dropped = true;
                }
                if text[at..].ends_with('\n') && matches!(kw, Kw::LastHeader(_) | Kw::LastHeaderValue(_) | Kw::Var(_) | Kw::Field { .. }) {
                    *suppress = Suppress::On;
                }
            }
        }
    }
}

/// The Authorization (401) or Proxy-Authorization (407) header for the
/// message around it, as createSendingMessage() builds it.
fn authorization(msg: &str, c: &Ctx, args: &AuthArgs) -> String {
    let (user, pass) = (args.user.as_str(), args.pass.as_str());
    let Some(a) = c.auth else {
        return String::new();
    };
    let method = msg.split(' ').next().unwrap_or("");
    let body = msg.find("\r\n\r\n").map_or("", |e| &msg[e + 4..]);
    let name = if a.code == 401 { "Authorization" } else { "Proxy-Authorization" };
    match crate::auth::credentials(user, pass, method, &a.uri, body, &a.challenge, a.nonce_count, &a.cnonce, args.aka.as_ref()) {
        Ok(creds) => format!("{name}: {creds}"),
        // SIPp's ERROR(): the message is not sent.
        Err(e) => {
            crate::log::defer_fatal(e);
            String::new()
        }
    }
}

fn droppable(kw: &Kw, c: &Ctx) -> bool {
    match kw {
        Kw::LastHeader(_) | Kw::LastHeaderValue(_) | Kw::Var(_) | Kw::Field { .. } => true,
        Kw::Routes => c.routes.is_none(),
        _ => false,
    }
}

fn last_request_uri(c: &Ctx) -> String {
    // get_last_header(): all the To values, joined.
    let to = c.last_recv.map(|m| sip::header_content(m, "To")).unwrap_or_default();
    match to.find('<').and_then(|b| Some((b, b + to[b..].find('>')?))) {
        Some((b, e)) => to[b + 1..e].to_string(),
        None => String::new(),
    }
}

/// call::dynamicId: [dynamic_id]'s counter, shared by all calls, from
/// -dynamicStart (10000) by -dynamicStep (4), back to the start once past
/// -dynamicMax (12000), as SIPp's (whose call.cpp says 18000, but the
/// option's default replaces it).
pub mod dynamic {
    use std::sync::atomic::{AtomicI32, Ordering::Relaxed};

    pub static START: AtomicI32 = AtomicI32::new(10000);
    pub static MAX: AtomicI32 = AtomicI32::new(12000);
    pub static STEP: AtomicI32 = AtomicI32::new(4);
    /// The next value: -dynamicStart's, once the options are read.
    pub static NEXT: AtomicI32 = AtomicI32::new(10000);

    /// Every use takes the next, back to the start past the maximum or
    /// the int's range.
    pub fn next() -> i32 {
        let (start, max, step) = (START.load(Relaxed), MAX.load(Relaxed), STEP.load(Relaxed));
        NEXT.fetch_update(Relaxed, Relaxed, |id| {
            let next = i64::from(id) + i64::from(step);
            Some(if next > i64::from(max) { start } else { i32::try_from(next).unwrap_or(start) })
        })
        .unwrap()
    }
}

fn value(kw: &Kw, offset: i64, c: &Ctx) -> String {
    let mut out = String::new();
    write_value(kw, offset, c, &mut out);
    out
}

/// An integer's digits, onto the message, without fmt's machinery: the
/// ports, numbers and CSeqs of every message.
fn push_int(out: &mut String, n: i64) {
    if n < 0 {
        out.push('-');
    }
    let mut v = n.unsigned_abs();
    let mut digits = [0u8; 20];
    let mut at = digits.len();
    loop {
        at -= 1;
        digits[at] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    // SAFETY: ASCII digits.
    *out += unsafe { std::str::from_utf8_unchecked(&digits[at..]) };
}

/// A keyword's text, onto the message: most are short, and a String of
/// each, copied in, was a good part of a message's rendering.
fn write_value(kw: &Kw, offset: i64, c: &Ctx, out: &mut String) {
    use std::fmt::Write;
    let ip_type = if c.ipv6 { "6" } else { "4" };
    let num = |out: &mut String, n: i64| push_int(out, n + offset);
    match kw {
        Kw::Service => *out += c.service,
        Kw::RemoteIp if c.remote_ip.contains(':') => {
            let _ = write!(out, "[{}]", c.remote_ip);
        }
        Kw::RemoteIp => *out += c.remote_ip,
        Kw::RemotePort => num(out, c.remote_port.into()),
        Kw::Transport => *out += c.transport,
        Kw::LocalIp => *out += c.local_ip,
        Kw::MediaIp => *out += c.media_ip_text,
        Kw::LocalPort => num(out, c.local_port.into()),
        Kw::LocalIpType => *out += ip_type,
        Kw::MediaIpType => *out += if c.media_ip.is_ipv6() { "6" } else { "4" },
        Kw::MediaPort => num(out, c.media_port.into()),
        Kw::AutoMediaPort => {
            push_int(out, i64::from(c.media_port) + offset + (4 * (c.call_number as i64 - 1)) % 10000);
        }
        Kw::RemoteHost => *out += c.remote_host,
        Kw::ServerIp => {
            if let Some(ip) = c.server_ip {
                let _ = write!(out, "{ip}");
            }
        }
        Kw::DynamicId => {
            push_int(out, dynamic::next().into());
        }
        Kw::MsgIndex => {
            push_int(out, c.msg_index as i64);
        }
        Kw::LastMessage => *out += c.last_recv.unwrap_or(""),
        Kw::ClockTick => {
            let _ = write!(out, "{}", crate::call::epoch().elapsed().as_millis());
        }
        Kw::Timestamp => *out += &crate::stat::format_time(std::time::SystemTime::now(), c.rfc3339),
        Kw::SippVersion => {
            let _ = write!(out, "{}-rs", env!("SIPP_VERSION_BARE"));
        }
        Kw::CallNumber => {
            push_int(out, c.call_number as i64);
        }
        Kw::TdmMap => *out += c.tdmmap.unwrap_or(""),
        Kw::Plugin { id, args } => *out += &crate::plugin::expand(*id, args, c),
        Kw::Users => {
            push_int(out, c.users.map_or(-1, i64::from));
        }
        Kw::UserId => {
            push_int(out, c.user_id as i64);
        }
        Kw::CallId => *out += c.call_id,
        Kw::Pid => {
            push_int(out, c.pid as i64);
        }
        Kw::Branch => {
            *out += "z9hG4bK-";
            push_int(out, c.pid as i64);
            out.push('-');
            push_int(out, c.call_number as i64);
            out.push('-');
            push_int(out, c.msg_index as i64 + offset);
        }
        Kw::Len => out.push(LEN_MARK),
        // Printed unsigned, as SIPp does: [cseq-1] of 0 wraps.
        Kw::Cseq => {
            push_int(out, (c.cseq as i64 + offset).rem_euclid(1 << 32));
        }
        Kw::PeerTagParam => {
            if let Some(t) = c.peer_tag {
                let _ = write!(out, ";tag={t}");
            }
        }
        Kw::Routes => {
            if let Some(r) = c.routes {
                let _ = write!(out, "Route: {r}");
            }
        }
        Kw::NextUrl if !c.next_url.is_empty() => *out += c.next_url,
        Kw::NextUrl | Kw::LastRequestUri => *out += &last_request_uri(c),
        Kw::LastCseqNumber => {
            let n: i64 = match c.bye_after_peer_request {
                true => c.cseq.into(),
                false => c.last_recv.and_then(sip::cseq_number).map_or(0, i64::from),
            };
            num(out, n);
        }
        Kw::Date => *out += &crate::log::http_date(),
        Kw::RtpstreamAudioPort => num(out, c.rtp_port.into()),
        Kw::RtpstreamVideoPort => num(out, c.rtp_video_port.into()),
        Kw::Crypto(k) => {
            let Some(media) = c.crypto.map(|m| m[k.video as usize]) else { return };
            let slot = media.tx[k.slot].as_ref();
            match k.what {
                CryptoWhat::Tag => {
                    push_int(out, k.slot as i64 + 1);
                }
                CryptoWhat::Suite(s) => *out += s.name(),
                CryptoWhat::Key => {
                    if let Some(s) = slot {
                        *out += &srtp::base64(&s.key);
                    }
                }
                CryptoWhat::Unencrypted(_) => *out += "UNENCRYPTED_SRTP",
            }
        }
        Kw::LastHeader(name) | Kw::LastHeaderValue(name) if c.bye_after_peer_request && (name.eq_ignore_ascii_case("From") || name.eq_ignore_ascii_case("To")) => {
            let other = if name.eq_ignore_ascii_case("From") { "To" } else { "From" };
            if let Some(v) = c.last_recv.map(|m| sip::header_content(m, other)).filter(|v| !v.is_empty()) {
                match kw {
                    Kw::LastHeader(_) => {
                        let _ = write!(out, "{name}: {v}");
                    }
                    _ => *out += &v,
                }
            }
        }
        // get_last_header(): the name as the scenario has it, then the
        // header's values, joined with ", ".
        Kw::LastHeader(name) => {
            if let Some(m) = c.last_recv {
                sip::write_header(out, m, name, true);
            }
        }
        Kw::LastHeaderValue(name) => {
            if let Some(m) = c.last_recv {
                sip::write_header(out, m, name, false);
            }
        }
        Kw::Var(name) => *out += &c.vars.render(name),
        Kw::Field { .. } | Kw::File(_) => *out += &owned_value(kw, c),
        Kw::Auth { .. } => unreachable!("rendered by the caller"),
    }
}

/// The keywords that read an injection file's field or a file.
fn owned_value(kw: &Kw, c: &Ctx) -> String {
    match kw {
        Kw::Field { n, file, line } => {
            let Some((inject, lines)) = c.inject else { return String::new() };
            let Some(name) = file.clone().or_else(|| inject.default_name().map(str::to_string)) else {
                return String::new();
            };
            let row = match line {
                Some(t) => {
                    // SIPp's: a 64-byte buffer, read with strtod ([$n]
                    // renders "2.000000"), cast to int; an empty or too
                    // long text is no line; past the last line, or before
                    // the first, is none.
                    let mut text = t.render_line(c);
                    while text.len() > 63 {
                        text.pop();
                    }
                    let (v, rest) = crate::posix::strtod(&text);
                    if !rest.is_empty() || rest.len() == text.len() || text.len() == 63 {
                        crate::log::defer_fatal(format!("Invalid line number generated: '{text}'"));
                        return String::new();
                    }
                    let n = inject.get(&name).map_or(0, |f| f.lines());
                    usize::try_from(v as i32).ok().filter(|&l| l <= n)
                }
                None => lines.get(&name).copied(),
            };
            match (inject.get(&name), row) {
                (Some(f), Some(row)) => f.field(row, *n),
                _ => String::new(),
            }
        }
        Kw::File(name) => {
            // Read whole, newlines and all; an error is SIPp's ERROR().
            use std::io::Read;
            let name = name.render_line(c);
            let mut data = Vec::new();
            let read = std::fs::File::open(crate::raw::os(&name))
                .map_err(|e| format!("Could not open '{name}': {}", crate::net::os_error(&e)))
                .and_then(|mut f| f.read_to_end(&mut data).map_err(|e| format!("Error reading '{name}': {}", crate::net::os_error(&e))));
            if let Err(e) = read {
                crate::log::defer_fatal(e);
            }
            crate::raw::text_owned(data)
        }
        _ => unreachable!("not a file's keyword"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_id_as_sipp() {
        use dynamic::*;
        use std::sync::atomic::Ordering::Relaxed;
        // As C SIPp gives them, for -dynamicStart, -dynamicMax and -dynamicStep.
        let run = |start, max, step| {
            START.store(start, Relaxed);
            MAX.store(max, Relaxed);
            STEP.store(step, Relaxed);
            NEXT.store(start, Relaxed);
            (0..7).map(|_| next()).collect::<Vec<_>>()
        };
        assert_eq!(run(10000, 12000, 4), [10000, 10004, 10008, 10012, 10016, 10020, 10024]);
        assert_eq!(run(11996, 12000, 4), [11996, 12000, 11996, 12000, 11996, 12000, 11996]);
        assert_eq!(run(1, 5, 1), [1, 2, 3, 4, 5, 1, 2]);
        // Past the max from the start, or a step past it: the start.
        assert_eq!(run(100, 50, 4), [100; 7]);
        assert_eq!(run(0, 10, 100), [0; 7]);
        assert_eq!(run(-5, -2, 1), [-5, -4, -3, -2, -5, -4, -3]);
        assert_eq!(run(10000, 12000, -3), [10000, 9997, 9994, 9991, 9988, 9985, 9982]);
        // Where SIPp's int overflows to negative values.
        assert_eq!(run(i32::MAX - 7, i32::MAX, 3), [i32::MAX - 7, i32::MAX - 4, i32::MAX - 1, i32::MAX - 7, i32::MAX - 4, i32::MAX - 1, i32::MAX - 7]);
        assert_eq!(run(i32::MIN + 2, 0, -2), [i32::MIN + 2, i32::MIN, i32::MIN + 2, i32::MIN, i32::MIN + 2, i32::MIN, i32::MIN + 2]);
        run(10000, 12000, 4);
    }

    #[test]
    fn integers_as_display_writes_them() {
        for n in [0, 7, -7, 10, 5060, -1, 4_294_967_295, i64::MAX, i64::MIN] {
            let mut out = String::from("x");
            push_int(&mut out, n);
            assert_eq!(out, format!("x{n}"));
        }
    }

    fn keys() -> HashMap<String, String> {
        HashMap::from([("custom_port".to_string(), "7000".to_string())])
    }

    fn with_ctx<R>(last_recv: Option<&str>, routes: Option<&str>, f: impl FnOnce(&Ctx) -> R) -> R {
        let mut vars = Vars::default();
        vars.set_string("who", "alice");
        vars.set_string("sdp", "Content-Length: 4\r\n\r\nx=1\r\n");
        f(&Ctx {
            service: "svc",
            remote_ip: "10.0.0.2",
            remote_port: 5060,
            local_ip: "10.0.0.1",
            local_port: 5070,
            media_ip: IpAddr::from([10, 0, 0, 1]),
            media_ip_text: "10.0.0.1",
            media_port: 6000,
            rtp_port: 6002,
            rtp_video_port: 6004,
            crypto: None,
            ipv6: false,
            transport: "UDP",
            pid: 42,
            call_number: 7,
            users: None,
            user_id: 0,
            call_id: "7-42@10.0.0.1",
            msg_index: 3,
            cseq: 0,
            last_recv,
            remote_host: "",
            server_ip: None,
            rfc3339: false,
            peer_tag: Some("pt"),
            routes,
            next_url: "",
            vars: &vars,
            inject: None,
            auth: None,
            tdmmap: None,
            bye_after_peer_request: false,
        })
    }

    fn render(text: &str, last_recv: Option<&str>, routes: Option<&str>) -> String {
        let t = Template::parse(text, &keys()).unwrap();
        with_ctx(last_recv, routes, |c| t.render(c))
    }

    #[test]
    fn media_ports_as_pcap_sources() {
        let t = Template::parse("m=audio [media_port] RTP/AVP 0\nm=video [media_port+2] x\nm=image 5000\nport [media_port]\nm=text [media_port+4] RTP/AVP 98\ntext [media_port]", &keys()).unwrap();
        assert_eq!(with_ctx(None, None, |c| t.media_ports(c)), [("audio", 6000), ("video", 6002), ("text", 6004)]);
    }

    #[test]
    fn value_ending_a_line_takes_the_next_crlf() {
        assert_eq!(render("INVITE x SIP/2.0\n[$sdp]", None, None), "INVITE x SIP/2.0\r\nContent-Length: 4\r\n\r\nx=1\r\n");
        assert_eq!(render("A\n[$sdp]\n  B: [$who]", None, None), "A\r\nContent-Length: 4\r\n\r\nx=1\r\nB: alice\r\n\r\n");
    }

    #[test]
    fn crlf_body_and_len_follow_sipp() {
        assert_eq!(
            render("\n   INVITE sip:[service]@[remote_ip] SIP/2.0\n   Content-Length: [len]\n\n   abc\n   ", None, None),
            "INVITE sip:svc@10.0.0.2 SIP/2.0\r\nContent-Length:     5\r\n\r\nabc\r\n"
        );
        assert_eq!(
            render("BYE sip:x SIP/2.0\nVia: SIP/2.0/[transport] h;branch=[branch]\nContent-Length: [len]", None, None),
            "BYE sip:x SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK-42-7-3\r\nContent-Length:     0\r\n\r\n"
        );
    }

    #[test]
    fn body_ends_as_the_text_does_and_escapes_are_literal() {
        // No newline after the body: no CRLF after it (github-#0034).
        assert_eq!(render("NOTIFY x SIP/2.0\nContent-Length: 4\n\n\\x01\\x02\\x03\\x04", None, None),
            "NOTIFY x SIP/2.0\r\nContent-Length: 4\r\n\r\n\x01\x02\x03\x04");
        assert_eq!(render("NOTIFY x SIP/2.0\nContent-Length: [len]\n\nX\n   ", None, None),
            "NOTIFY x SIP/2.0\r\nContent-Length:     3\r\n\r\nX\r\n");
        assert_eq!(render("NOTIFY x SIP/2.0\nContent-Length: 0\n\n\n\n", None, None),
            "NOTIFY x SIP/2.0\r\nContent-Length: 0\r\n\r\n");
        // github-#0018: an escaped bracket is not a keyword.
        assert_eq!(render("X-Literal: \\x5bdate]", None, None), "X-Literal: [date]\r\n\r\n");
        // Any byte, UTF-8 or not, and the text's own raw bytes: [len]
        // counts the bytes.
        let text = crate::raw::text(b"NOTIFY x SIP/2.0\nContent-Length: [len]\n\nAndr\xe9\\xe9\\xc3\\xa9\\xff").into_owned();
        let sent = render(&text, None, None);
        assert_eq!(&*crate::raw::bytes(&sent), b"NOTIFY x SIP/2.0\r\nContent-Length:     9\r\n\r\nAndr\xe9\xe9\xc3\xa9\xff");
        assert!(sent.contains('\u{e9}'));
    }

    #[test]
    fn hex_escapes_take_only_their_digits() {
        // One or two hex digits, nothing after them; a "\x" without one
        // stays as it is.
        assert_eq!(unescape("A\\x5\nB\\xgC\\x41\\x4g1\\x").unwrap(), "A\x05\r\nB\\xgCA\x04g1\\x");
        assert_eq!(unescape("\\x\\x41\\x").unwrap(), "\\xA\\x");
    }

    #[test]
    fn empty_keywords_at_line_start_drop_the_line() {
        let recv = "INVITE sip:a SIP/2.0\r\nVia: v1\r\nVia: v2\r\nTo: <sip:a@b>\r\n\r\n";
        assert_eq!(
            render("SIP/2.0 200 OK\n[last_Via:]\n[last_Record-Route:]\n[routes]\n[$unset]\n[last_To];tag=x[peer_tag_param]", Some(recv), None),
            "SIP/2.0 200 OK\r\nVia: v1, v2\r\nTo: <sip:a@b>;tag=x;tag=pt\r\n\r\n"
        );
    }

    #[test]
    fn last_headers_and_their_values_as_sipps() {
        let recv = "INVITE sip:a SIP/2.0\r\nv:  v1 \r\nVia: v2\r\nf: <sip:a@b>;tag=1\r\n\r\n";
        assert_eq!(
            render("X\nA: [last_via:]\nB: [last_Via.value]\nC: [last_From:.value]\nD: [last_Nope.value]\nE: [last_From::.value]", Some(recv), None),
            "X\r\nA: via: v1, v2\r\nB: v1, v2\r\nC: <sip:a@b>;tag=1\r\nD: \r\nE: \r\n\r\n"
        );
    }

    #[test]
    fn offsets_routes_vars_keys_and_last_values() {
        let recv = "SIP/2.0 200 OK\r\nTo: <sip:bob@h>;tag=1\r\nCSeq: 5 INVITE\r\n\r\n";
        assert_eq!(
            render("X [local_port+1] [branch-2] [cseq-1] [$who] [custom_port] [next_url] [last_cseq_number+1]\n[routes]", Some(recv), Some("<sip:p1;lr>")),
            "X 5071 z9hG4bK-42-7-1 4294967295 alice 7000 sip:bob@h 6\r\nRoute: <sip:p1;lr>\r\n\r\n"
        );
    }

    #[test]
    fn fields_and_authentication() {
        let mut inject = Injection::default();
        inject.add("u.csv".into(), crate::infile::InFile::parse("u.csv", "SEQUENTIAL\nalice;s3cret;[authentication username=[field0] password=[field1]]\n").unwrap());
        let lines = HashMap::from([("u.csv".to_string(), 0)]);
        let auth = AuthCtx {
            challenge: r#"Digest realm="r", nonce="n", qop="auth""#.into(),
            code: 407,
            nonce_count: 1,
            cnonce: "c".into(),
            uri: "sip:10.0.0.2:5060".into(),
            user: "default".into(),
            pass: "password".into(),
        };
        let vars = Vars::default();
        let ctx = Ctx {
            service: "svc", remote_ip: "10.0.0.2", remote_port: 5060, local_ip: "10.0.0.1", local_port: 5070,
            media_ip: IpAddr::from([10, 0, 0, 1]), media_ip_text: "10.0.0.1", media_port: 6000, rtp_port: 0, rtp_video_port: 0, crypto: None, ipv6: false, transport: "UDP", pid: 1, call_number: 1, users: None, user_id: 0, call_id: "1-1@h",
            msg_index: 0, cseq: 1, last_recv: None, remote_host: "", server_ip: None, rfc3339: false, peer_tag: None, routes: None, next_url: "", vars: &vars,
            inject: Some((&inject, &lines)), auth: Some(&auth), tdmmap: None, bye_after_peer_request: false,
        };
        let direct = Template::parse("REGISTER sip:r SIP/2.0\nFrom: <sip:[field0]@r>\n[authentication username=[field0] password=[field1]]\nContent-Length: 0", &keys()).unwrap();
        let injected = Template::parse("REGISTER sip:r SIP/2.0\nFrom: <sip:[field0]@r>\n[field2]\nContent-Length: 0", &keys()).unwrap();
        for t in [direct, injected] {
            let msg = t.render(&ctx);
            assert!(msg.contains("From: <sip:alice@r>\r\n"), "{msg}");
            let creds = sip::header(&msg, "Proxy-Authorization").expect("credentials");
            assert!(creds.starts_with("Digest username=\"alice\",realm=\"r\""), "{creds}");
            assert!(crate::auth::verify("alice", "s3cret", "REGISTER", creds, "").unwrap());
        }
    }

    #[test]
    fn a_one_line_texts_newline_is_a_crlf() {
        // SendingMessage: a newline (an attribute's \n) is a CRLF, \x0a not.
        let t = Template::parse_line("a\nb[$who]\\x0ac", &keys()).unwrap();
        assert_eq!(with_ctx(None, None, |c| t.render_line(c)), "a\r\nbalice\nc");
    }

    #[test]
    fn a_fields_line_is_read_as_sipp_reads_it() {
        let mut inject = Injection::default();
        inject.add("u.csv".into(), crate::infile::InFile::parse("u.csv", "SEQUENTIAL\na;1\nb;2\n").unwrap());
        let lines = HashMap::from([("u.csv".to_string(), 1)]);
        let render = |t: &str| {
            let t = Template::parse_line(t, &keys()).unwrap();
            with_ctx(None, None, |c| t.render_line(&Ctx { inject: Some((&inject, &lines)), server_ip: None, ..*c }))
        };
        // strtod() then (int): no line= is the call's line, -0.5 is 0,
        // past the end or before the start none.
        assert_eq!(render("[field0]|[field0 line=]|[field0 line=1.9]|[field0 line=2]|[field0 line=-1]"), "b|b|b||");
        assert_eq!(crate::log::take_deferred_fatal(), None);
        assert_eq!(render("[field0 line=1x]"), "");
        assert_eq!(crate::log::take_deferred_fatal().as_deref(), Some("Invalid line number generated: '1x'"));
        // One that renders empty, or too long for SIPp's buffer, is none.
        assert_eq!(render("[field0 line=[$nothing]]"), "");
        assert_eq!(crate::log::take_deferred_fatal().as_deref(), Some("Invalid line number generated: ''"));
        let long = "0".repeat(70);
        assert_eq!(render(&format!("[field0 line={long}]")), "");
        assert_eq!(crate::log::take_deferred_fatal(), Some(format!("Invalid line number generated: '{}'", &long[..63])));
    }

    #[test]
    fn a_file_is_inserted_as_it_is() {
        let dir = std::env::temp_dir().join(format!("sipp-rs-file-kw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // A quoted value's '\\' escapes, as SIPp's: Windows takes '/' too.
        let d = dir.to_str().unwrap().replace('\\', "/");
        std::fs::write(dir.join("alice.txt"), "SEQUENTIAL\nalice\n").unwrap();
        std::fs::write(dir.join("empty.txt"), "").unwrap();
        // The name is a message of its own; the bytes go in untouched, LF
        // and all, and the line's CRLF still follows them.
        let t = Template::parse(&format!("OPTIONS x SIP/2.0\nX-File: [file name=\"{d}/[$who].txt\"]\nX-Next: 1"), &keys()).unwrap();
        assert_eq!(with_ctx(None, None, |c| t.render(c)), "OPTIONS x SIP/2.0\r\nX-File: SEQUENTIAL\nalice\n\r\nX-Next: 1\r\n\r\n");
        // An empty file leaves its line, blank or not.
        let t = Template::parse(&format!("OPTIONS x SIP/2.0\n[file name={d}/empty.txt]\nL: [len]"), &keys()).unwrap();
        assert_eq!(with_ctx(None, None, |c| t.render(c)), "OPTIONS x SIP/2.0\r\n\r\nL:    12\r\n\r\n");
        // Bytes that are not UTF-8 go out as they are, [len] counting them.
        std::fs::write(dir.join("bin.dat"), b"\x80\xff\xc3\xa9\xf4\x8f\xbf\xa9\xe9").unwrap();
        let t = Template::parse(&format!("OPTIONS x SIP/2.0\nL: [len]\n\n[file name={d}/bin.dat]"), &keys()).unwrap();
        let sent = with_ctx(None, None, |c| t.render(c));
        assert_eq!(&*crate::raw::bytes(&sent), b"OPTIONS x SIP/2.0\r\nL:     9\r\n\r\n\x80\xff\xc3\xa9\xf4\x8f\xbf\xa9\xe9");
        assert_eq!(crate::log::take_deferred_fatal(), None);
        // SIPp's ERROR()s, at the send.
        let t = Template::parse_line(&format!("[file name={d}/none.txt]"), &keys()).unwrap();
        assert_eq!(with_ctx(None, None, |c| t.render_line(c)), "");
        let why = if cfg!(windows) { "The system cannot find the file specified." } else { "No such file or directory" };
        assert_eq!(crate::log::take_deferred_fatal(), Some(format!("Could not open '{d}/none.txt': {why}")));
        let t = Template::parse_line(&format!("[file name={d}]"), &keys()).unwrap();
        assert_eq!(with_ctx(None, None, |c| t.render_line(c)), "");
        // Windows opens no directory as a file; Linux does, and reads none.
        let dir_error = if cfg!(windows) { format!("Could not open '{d}': Access is denied.") } else { format!("Error reading '{d}': Is a directory") };
        assert_eq!(crate::log::take_deferred_fatal(), Some(dir_error));
        std::fs::remove_dir_all(&dir).unwrap();
        // Any keyword that starts with "file" is one, and needs a name.
        for kw in ["[file]", "[file name=]", "[filename x]"] {
            assert_eq!(Template::parse_line(kw, &keys()).unwrap_err(), "No name specified for 'file' keyword!");
        }
    }

    #[test]
    fn brackets_nest_and_an_unclosed_one_is_refused() {
        let syntax = |t: &str| Template::parse_line(t, &keys()).unwrap_err();
        // Not "A1[b c", nor text moved behind the next keyword (C 72d7385).
        assert_eq!(syntax("A[b [call_number] c"), "Syntax error or invalid [keyword] in scenario while parsing ''");
        assert!(syntax(&format!("A[{}[call_number]", "x".repeat(300))).starts_with("Syntax error or invalid [keyword]"));
        assert!(syntax("A[call_number").starts_with("Syntax error or invalid [keyword]"));
        assert_eq!(
            Template::parse("INVITE x SIP/2.0\nCSeq: 1 INV[ITE\nContact: [local_ip]", &keys()).unwrap_err(),
            "Syntax error or invalid [keyword] in scenario while parsing 'CSeq: 1 INV[ITE'"
        );
        assert_eq!(syntax("A[b [call_number] c]Z"), "Unsupported keyword 'b [call_number] c' in xml scenario file");
        let t = Template::parse_line("A\\x5Bb [call_number] c]Z", &keys()).unwrap();
        assert_eq!(t.lines[0], vec![Part::Lit("A[b ".into()), Part::Kw(Kw::CallNumber, 0), Part::Lit(" c]Z".into())]);
    }

    #[test]
    fn keyword_parameters_are_keywords() {
        // C ef2ca39: unquoted nested keywords, a ']' quoted in one, and a
        // parameter looked up only at the start of a word.
        let auth = |t: &str| match Template::parse_line(t, &keys()).unwrap().lines[0].clone().into_iter().find(|p| matches!(p, Part::Kw(Kw::Auth { .. }, _))) {
            Some(Part::Kw(Kw::Auth { user, pass, aka }, _)) => (user.map(|t| t.lines[0].clone()), pass.map(|t| t.lines[0].clone()), aka.map(|a| a.map(|t| t.lines[0].clone()))),
            _ => panic!("no [authentication] in {t}"),
        };
        let kw = |k: Kw| Some(vec![Part::Kw(k, 0)]);
        let lit = |s: &str| Some(vec![Part::Lit(s.into())]);
        let (user, pass, aka) = auth("A[authentication username=[call_number] password=\"[call_id]\" aka_K=[call_number]]Z");
        assert_eq!((user, pass), (kw(Kw::CallNumber), kw(Kw::CallId)));
        assert_eq!(aka, [kw(Kw::CallNumber), None, None]);
        let (user, pass, _) = auth("[authentication username=[field0 file=\"x\\\"]y\"] password=p]");
        assert_eq!(user, kw(Kw::Field { n: 0, file: Some("x\"]y".into()), line: None }));
        assert_eq!(pass, lit("p"));
        let (user, pass, _) = auth("[authentication username=[field0 file=\"password=x\"] password=[call_id]]");
        assert_eq!((user, pass), (kw(Kw::Field { n: 0, file: Some("password=x".into()), line: None }), kw(Kw::CallId)));
        let (user, pass, aka) = auth("[authentication username=\"password=x\" password=[call_id]]");
        assert_eq!((user, pass), (lit("password=x"), kw(Kw::CallId)));
        // Without aka_K, the password's text.
        assert_eq!(aka[0], kw(Kw::CallId));
    }

    #[test]
    fn method_and_errors() {
        assert_eq!(Template::parse("ACK sip:x SIP/2.0", &keys()).unwrap().method(), Some("ACK"));
        assert_eq!(Template::parse("SIP/2.0 200 OK", &keys()).unwrap().method(), None);
        assert!(Template::parse("X [tdmmap]", &keys()).is_ok());
        assert!(Template::parse("X [no_such_keyword]", &keys()).is_err());
        assert!(Template::parse("X [call_id", &keys()).is_err());
    }
}

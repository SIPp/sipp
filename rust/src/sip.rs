//! Just enough SIP parsing to match messages against a scenario.

use std::borrow::Cow;
use std::cell::RefCell;
use std::sync::Arc;

#[derive(Debug, PartialEq)]
pub enum Kind<'a> {
    Request(&'a str),
    Response(u16),
}

/// Request method or response code, from the start line. What starts
/// with "SIP/2.0" is a response, as SIPp's process_incoming() takes it,
/// with code 0 when its start line has none (see reply_code()). A
/// request's method is what comes before the first space, as SIPp reads
/// it, even past the start line: none without one.
pub fn kind(raw: &str) -> Option<Kind<'_>> {
    if raw.starts_with("SIP/2.0") {
        Some(Kind::Response(reply_code(raw)))
    } else {
        position(raw, b' ').map(|e| Kind::Request(&raw[..e]))
    }
}

/// SIPp's get_reply_code() on the start line: the number (atol()) after
/// its first word and the spaces and tabs after it; 0 for none. One out
/// of range, or negative, is u16::MAX: a code that matches nothing.
fn reply_code(raw: &str) -> u16 {
    let line = &raw[..raw.find(['\r', '\n']).unwrap_or(raw.len())];
    let rest = line.trim_start_matches(|c| c != ' ' && c != '\t').trim_start_matches([' ', '\t']);
    let (negative, rest) = match rest.as_bytes().first() {
        Some(b'-') => (true, &rest[1..]),
        Some(b'+') => (false, &rest[1..]),
        _ => (false, rest),
    };
    let digits = &rest[..rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len())];
    match digits.trim_start_matches('0') {
        "" => 0,
        _ if negative => u16::MAX,
        d => d.parse().unwrap_or(u16::MAX),
    }
}

/// Where the blank line that ends the headers begins ("\r\n\r\n"): the
/// first line feed after "\r\n\r", found with memchr(), which is faster
/// on SIP's short lines than memmem() or str's searcher.
pub fn body_start(raw: &str) -> Option<usize> {
    let b = raw.as_bytes();
    let mut from = 0;
    while let Some(i) = position(&raw[from..], b'\n').map(|i| from + i) {
        if i >= 3 && &b[i - 3..i] == b"\r\n\r" {
            return Some(i - 3);
        }
        from = i + 1;
    }
    None
}

/// The body, after the blank line; "" if there is none.
pub fn body(raw: &str) -> &str {
    body_start(raw).map_or("", |e| &raw[e + 4..])
}

/// The headers with a compact form (RFC 3261 section 7.3.3), and its
/// letter, as SIPp's internal_compact_header_name() knows them.
const COMPACT: [(&str, u8); 8] = [
    ("Call-ID", b'i'),
    ("Contact", b'm'),
    ("Content-Encoding", b'e'),
    ("Content-Length", b'l'),
    ("Content-Type", b'c'),
    ("From", b'f'),
    ("To", b't'),
    ("Via", b'v'),
];

/// A header name looked up, with the letters its lines may begin with.
struct Name<'a> {
    name: &'a str,
    first: u8,
    compact: Option<u8>,
}

impl Name<'_> {
    fn new(name: &str) -> Name<'_> {
        let compact = COMPACT.iter().find_map(|&(full, c)| full.eq_ignore_ascii_case(name).then_some(c));
        Name { name, first: name.as_bytes().first().map_or(0, u8::to_ascii_lowercase), compact }
    }

    /// Where the colon is of a line called so, as SIPp's get_header()
    /// matches it: the name, in any case, right before the colon, or
    /// the compact form's letter.
    fn colon(&self, line: &str) -> Option<usize> {
        let (b, n) = (line.as_bytes(), self.name.len());
        let first = b.first()?.to_ascii_lowercase();
        if first == self.first && b.get(n) == Some(&b':') && b[..n].eq_ignore_ascii_case(self.name.as_bytes()) {
            return Some(n);
        }
        (Some(first) == self.compact && b.get(1) == Some(&b':')).then_some(1)
    }
}

/// Where the first `byte` is: libc's memchr(), as SIP lines are short,
/// for which str's searchers take longer to set up than to search.
fn position(text: &str, byte: u8) -> Option<usize> {
    // SAFETY: memchr() reads text's own bytes, and finds one of them or none.
    let found = unsafe { libc::memchr(text.as_ptr().cast(), byte.into(), text.len()) };
    (!found.is_null()).then(|| found as usize - text.as_ptr() as usize)
}

/// The header lines after the start line, each up to its line feed (its
/// CR kept), up to the blank line that ends them, as SIPp's get_header()
/// reads them: a CRLF after a line that ends with one, not a bare line
/// feed. A header folded onto the lines after it (RFC 3261 7.3.1: they
/// begin with a space or a tab) is one line, its line breaks in it.
fn head_lines(raw: &str) -> HeadLines<'_> {
    let nl = position(raw, b'\n');
    HeadLines { rest: nl.map(|i| &raw[i + 1..]), crlf: nl.is_some_and(|i| i > 0 && raw.as_bytes()[i - 1] == b'\r') }
}

struct HeadLines<'a> {
    rest: Option<&'a str>,
    /// Whether the line before ended with a CR.
    crlf: bool,
}

impl HeadLines<'_> {
    /// The next line, without looking at whether it ends the headers.
    fn skip_line(&mut self) {
        let Some(text) = self.rest else { return };
        self.crlf = false;
        self.rest = None;
        if let Some(line) = (HeadLines { rest: Some(text), crlf: false }).next() {
            self.crlf = line.ends_with('\r');
            let after = line.len() + 1;
            self.rest = text.get(after..).filter(|_| after <= text.len());
        }
    }
}

impl<'a> Iterator for HeadLines<'a> {
    type Item = &'a str;

    #[inline]
    fn next(&mut self) -> Option<&'a str> {
        let text = self.rest?;
        let bytes = text.as_bytes();
        // Whatever comes after it.
        if self.crlf && bytes.starts_with(b"\r\n") {
            self.rest = None;
            return None;
        }
        let mut end = position(text, b'\n');
        while let Some(i) = end.filter(|&i| matches!(bytes.get(i + 1), Some(b' ' | b'\t'))) {
            end = position(&text[i + 1..], b'\n').map(|j| i + 1 + j);
        }
        let (line, after) = end.map_or((text, None), |i| (&text[..i], Some(&text[i + 1..])));
        self.crlf = line.ends_with('\r');
        self.rest = after;
        Some(line)
    }
}

/// A header line of an indexed message, by its offsets: where it begins
/// and where it ends (at its line feed); its name's first letter (lower
/// case), which most lookups stop at.
struct Head {
    start: u32,
    end: u32,
    first: u8,
}

/// The last messages indexed: their address and length ((0, 0) for none),
/// each held to keep its bytes where they are, their header lines, and
/// the next place to take.
struct Index {
    keys: [(usize, usize); INDEXED],
    msgs: [Option<Arc<str>>; INDEXED],
    heads: [Vec<Head>; INDEXED],
    next: usize,
}

/// How many messages keep their index: the one being taken, and the last
/// ones calls render theirs from.
const INDEXED: usize = 8;

thread_local! {
    static INDEX: RefCell<Index> = const {
        RefCell::new(Index { keys: [(0, 0); INDEXED], msgs: [const { None }; INDEXED], heads: [const { Vec::new() }; INDEXED], next: 0 })
    };
}

fn key(raw: &str) -> (usize, usize) {
    (raw.as_ptr() as usize, raw.len())
}

/// Index a message's header lines, which the lookups in it then find
/// without going through its lines again.
pub fn index(msg: &Arc<str>) {
    INDEX.with_borrow_mut(|ix| {
        let raw: &str = msg;
        if ix.keys.contains(&key(raw)) {
            return;
        }
        let i = ix.next;
        ix.next = (i + 1) % INDEXED;
        heads_of(raw, &mut ix.heads[i]);
        ix.keys[i] = key(raw);
        ix.msgs[i] = Some(msg.clone());
    });
}

/// The header lines of a message as head_lines() takes them, those with a
/// colon, which Name::colon() may match.
fn heads_of(raw: &str, heads: &mut Vec<Head>) {
    heads.clear();
    let base = raw.as_ptr() as usize;
    for line in head_lines(raw).filter(|line| position(line, b':').is_some()) {
        let start = line.as_ptr() as usize - base;
        heads.push(Head { start: start as u32, end: (start + line.len()) as u32, first: line.as_bytes()[0].to_ascii_lowercase() });
    }
}

/// The lines called `name`, each up to its line feed, with where its
/// colon is, to `take` in message order until it returns true: from the
/// message's index if it has one.
fn find_lines<'a>(raw: &'a str, name: &str, mut take: impl FnMut(&'a str, usize) -> bool) {
    let name = Name::new(name);
    // SIPp's get_header() looks for the next one from past where the value
    // starts: one that is empty, at a bare line feed, has it miss the line
    // after it.
    let skips = |line: &str, colon: usize| line[colon + 1..].trim_start_matches(' ').is_empty() && !line.ends_with('\r') && line.len() < raw.len() - (line.as_ptr() as usize - raw.as_ptr() as usize);
    let indexed = INDEX.with_borrow(|ix| {
        let Some(i) = ix.keys.iter().position(|&k| k == key(raw)) else {
            return false;
        };
        let mut missed = None;
        for h in ix.heads[i].iter().filter(|h| h.first == name.first || Some(h.first) == name.compact) {
            if missed.take() == Some(h.start) {
                continue;
            }
            let line = &raw[h.start as usize..h.end as usize];
            let Some(colon) = name.colon(line) else { continue };
            if take(line, colon) {
                break;
            }
            missed = skips(line, colon).then_some(h.end + 1);
        }
        true
    });
    if indexed {
        return;
    }
    let mut lines = head_lines(raw);
    while let Some(line) = lines.next() {
        let Some(colon) = name.colon(line) else { continue };
        if take(line, colon) {
            break;
        }
        if skips(line, colon) {
            lines.skip_line();
        }
    }
}

/// Every header line called `name`, whole ("Via: ..."), in message order.
#[cfg(test)]
pub fn header_lines<'a>(raw: &'a str, name: &str) -> Vec<&'a str> {
    let mut lines = Vec::new();
    find_lines(raw, name, |line, _| {
        lines.push(line.strip_suffix('\r').unwrap_or(line));
        false
    });
    lines
}

/// Value of the first header called `name`.
pub fn header<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
    let mut value = None;
    find_lines(raw, name, |line, colon| {
        value = Some(line[colon + 1..].trim_ascii());
        true
    });
    value
}

pub fn cseq_method(raw: &str) -> Option<&str> {
    header(raw, "CSeq")?.split_whitespace().nth(1)
}

/// get_cseq_value(): the number of the first "\r\nCSeq:" anywhere in the
/// message, or else of "CSEQ", "cseq" or "Cseq", as strtoul() reads it;
/// Err with SIPp's warning when there is none, or nothing after it.
pub fn cseq_value(raw: &str) -> Result<u64, String> {
    let Some(at) = ["\r\nCSeq:", "\r\nCSEQ:", "\r\ncseq:", "\r\nCseq:"].iter().find_map(|h| raw.find(h)) else {
        return Err(format!("No valid Cseq header in request {raw}"));
    };
    let value = raw[at + 7..].trim_start_matches([' ', '\t']);
    if value.is_empty() {
        return Err("No valid Cseq data in header".into());
    }
    // strtoul(value, nullptr, 10): past white space, a sign, and the
    // digits, the largest number for too many.
    let value = value.trim_start_matches([' ', '\t', '\n', '\x0b', '\x0c', '\r']);
    let (negative, digits) = match value.as_bytes().first() {
        Some(b'-') => (true, &value[1..]),
        Some(b'+') => (false, &value[1..]),
        _ => (false, value),
    };
    let mut n = 0u64;
    for d in digits.bytes().take_while(u8::is_ascii_digit) {
        match n.checked_mul(10).and_then(|n| n.checked_add(u64::from(d - b'0'))) {
            Some(m) => n = m,
            None => return Ok(u64::MAX),
        }
    }
    Ok(if negative { n.wrapping_neg() } else { n })
}

pub fn cseq_number(raw: &str) -> Option<u32> {
    header(raw, "CSeq")?.split_whitespace().next()?.parse().ok()
}

/// extract_transaction(): the branch that names the transaction, the
/// first in the Via values joined, as SIPp looks for it: the top Via's,
/// or the next one's if it has none.
pub fn top_via_branch(raw: &str) -> Option<&str> {
    let mut branch = None;
    find_lines(raw, "Via", |line, colon| {
        let value = &line[colon + 1..];
        let Some(at) = value.find(";branch=") else { return false };
        let b = &value[at + 8..];
        // Up to a ';', a ',' or isspace().
        branch = Some(b.split(|c: char| matches!(c, ';' | ',' | ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r')).next().unwrap_or(b));
        true
    });
    branch
}

/// get_header_content(): the values of every header called `name`, as
/// write_header() joins them; "" without one. Borrowed for one that is
/// on a line of its own, as most are.
pub fn header_content<'a>(raw: &'a str, name: &str) -> Cow<'a, str> {
    let (mut first, mut more) = (None, false);
    find_lines(raw, name, |line, colon| {
        more = first.is_some();
        first = first.or(Some(&line[colon + 1..]));
        more
    });
    let Some(value) = first else { return Cow::Borrowed("") };
    if !more {
        let value = value.trim_start_matches(' ').trim_end_matches([' ', '\t', '\r']);
        if !value.is_empty() && !value.bytes().any(|b| b == b'\r' || b == b'\n') && value.len() < 20000 {
            return Cow::Borrowed(value);
        }
    }
    let mut out = String::new();
    write_header(&mut out, raw, name, false);
    Cow::Owned(out)
}

/// get_header(): the values of every header called `name`, joined with
/// ", ", after the name and a colon if `with_name`; nothing without one.
/// As SIPp's: each value with its CR but before the blank line, at most
/// what its buffer holds, without its trailing blanks but the first
/// character, and no CR or line feed twice in a row.
pub fn write_header(out: &mut String, raw: &str, name: &str, with_name: bool) {
    let start = out.len();
    let base = raw.as_ptr() as usize;
    find_lines(raw, name, |line, colon| {
        if with_name && out.len() == start {
            *out += name;
            out.push(':');
        }
        // Several: the text so far without its trailing blanks, then a
        // space after the name, or a comma.
        if out.len() > start {
            let kept = out[start..].trim_end_matches([' ', '\t', '\r', '\n']).len();
            out.truncate(start + kept);
            *out += if out.ends_with(':') { " " } else { ", " };
        }
        let end = line.as_ptr() as usize - base + line.len();
        let value = match raw[end..].starts_with("\n\r\n") {
            true => line.strip_suffix('\r').unwrap_or(line),
            false => line,
        };
        *out += value[colon + 1..].trim_start_matches(' ');
        false
    });
    // MAX_HEADER_LEN * 10, its NUL included.
    let mut cut = (start + 20489).min(out.len());
    while !out.is_char_boundary(cut) {
        cut -= 1;
    }
    out.truncate(cut);
    let kept = out[start..].trim_end_matches([' ', '\t', '\r']).len().max(1.min(out.len() - start));
    out.truncate(start + kept);
    let lead = out[start..].len() - out[start..].trim_start_matches(' ').len();
    out.drain(start..start + lead);
    if out[start..].contains(['\r', '\n']) {
        let mut squeezed = String::with_capacity(out.len() - start);
        for c in out[start..].chars() {
            if !(matches!(c, '\r' | '\n') && squeezed.ends_with(c)) {
                squeezed.push(c);
            }
        }
        out.truncate(start);
        *out += &squeezed;
    }
}

/// internal_skip_lws(): past the blanks and the line breaks folding the
/// header, where its value starts; None where its line ends first.
fn skip_lws(b: &[u8], mut at: usize) -> Option<usize> {
    loop {
        while matches!(b.get(at), Some(b' ' | b'\t')) {
            at += 1;
        }
        if b.get(at) == Some(&b'\r') && b.get(at + 1) == Some(&b'\n') {
            if !matches!(b.get(at + 2), Some(b' ' | b'\t')) {
                return None;
            }
            at += 3;
            continue;
        }
        return Some(at);
    }
}

/// internal_find_header(): where the value of the first header called
/// `name` or `short` starts, from the start line on, as SIPp's
/// get_call_id() and get_peer_tag() look for it (get_header() goes by
/// other rules): none past the blank line that ends the headers, or
/// without a value; Err with its offset for a line feed without a CR
/// before it, SIPp's "Missing CR during header scan".
fn strict_value(raw: &str, name: &str, short: &str) -> Result<Option<usize>, usize> {
    let b = raw.as_bytes();
    let starts = |at: usize, n: &str| b.len() >= at + n.len() && b[at..at + n.len()].eq_ignore_ascii_case(n.as_bytes());
    let mut at = 0;
    loop {
        // The name, or else the short one.
        let len = if starts(at, name) { Some(name.len()) } else { starts(at, short).then_some(short.len()) };
        if let Some(len) = len {
            let mut t = at + len;
            while matches!(b.get(t), Some(b' ' | b'\t')) {
                t += 1;
            }
            if b.get(t) == Some(&b':') {
                return Ok(skip_lws(b, t + 1));
            }
        }
        let Some(nl) = position(&raw[at..], b'\n').map(|i| at + i) else { return Ok(None) };
        if nl == 0 || b[nl - 1] != b'\r' {
            return Err(nl);
        }
        if b.get(nl + 1) == Some(&b'\r') && b.get(nl + 2) == Some(&b'\n') {
            return Ok(None);
        }
        at = nl + 1;
    }
}

/// internal_hdrend(): where the header from `at` ends, at the CRLF that
/// does not fold it, or at the end.
fn header_end(b: &[u8], at: usize) -> usize {
    (at..b.len()).find(|&p| b[p] == b'\r' && b.get(p + 1) == Some(&b'\n') && !matches!(b.get(p + 2), Some(b' ' | b'\t'))).unwrap_or(b.len())
}

/// get_call_id(): the Call-ID, up to the CRLF that ends its header, its
/// folding and trailing blanks kept; "" when there is none, or one too
/// long for SIPp's MAX_HEADER_LEN. Err as strict_value().
pub fn call_id(raw: &str) -> Result<&str, usize> {
    let Some(at) = strict_value(raw, "Call-ID", "i")? else { return Ok("") };
    let id = &raw[at..header_end(raw.as_bytes(), at)];
    Ok(if id.len() + 1 > 2049 { "" } else { id })
}

/// internal_hdrchr(): the first `needle` in the header from `at`, before
/// the CRLF that ends it.
fn header_char(b: &[u8], mut at: usize, needle: u8) -> Option<usize> {
    if b.get(at) == Some(&b'\n') {
        return None;
    }
    loop {
        match b.get(at) {
            None => return None,
            Some(&c) if c == needle => return Some(at),
            Some(b'\n') if b[at - 1] == b'\r' && !matches!(b.get(at + 1), Some(b' ' | b'\t')) => return None,
            _ => at += 1,
        }
    }
}

/// get_peer_tag(): the tag parameter of the To header, past its
/// <addr-spec> if it has one, as SIPp reads it (None for none); Ok(None)
/// without a To header, Err as strict_value().
pub fn peer_tag(raw: &str) -> Result<Option<Option<&str>>, usize> {
    let b = raw.as_bytes();
    let Some(to) = strict_value(raw, "To", "t")? else { return Ok(None) };
    let mut at = header_char(b, to, b'>').unwrap_or(to);
    // internal_find_param(): each parameter, after a ';'.
    let tag = loop {
        let Some(p) = header_char(b, at, b';').and_then(|semi| skip_lws(b, semi + 1)).filter(|&p| p < b.len()) else { break None };
        if b[p..].len() > 3 && b[p..p + 3].eq_ignore_ascii_case(b"tag") && b[p + 3] == b'=' {
            let start = p + 4;
            let end = (start..b.len()).find(|&e| matches!(b[e], b' ' | b';' | b'\t' | b'\r' | b'\n' | 0)).unwrap_or(b.len());
            // What SIPp's buffer of MAX_HEADER_LEN takes.
            let mut end = end.min(start + 2048);
            while !raw.is_char_boundary(end) {
                end -= 1;
            }
            break Some(&raw[start..end]);
        }
        at = p;
    };
    Ok(Some(tag))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESP: &str = "SIP/2.0 200 OK\r\n\
        Via: SIP/2.0/UDP a;branch=1\r\n\
        via: SIP/2.0/UDP b;branch=2\r\n\
        t: <sip:x@y>;tag=abc;foo\r\n\
        i: 1-2@h\r\n\
        CSeq: 2 BYE\r\n\r\n\
        Via: not a header\r\n";

    #[test]
    fn a_folded_header_is_one_line() {
        let msg = "OPTIONS sip:x SIP/2.0\r\nSubject: one\r\n  two\r\n\tthree\r\nVia: a\r\nVia: b\r\n ;branch=2\r\nCSeq: 1 OPTIONS\r\n\r\nbody";
        assert_eq!(header(msg, "Subject"), Some("one\r\n  two\r\n\tthree"));
        assert_eq!(header_lines(msg, "Via"), ["Via: a", "Via: b\r\n ;branch=2"]);
        assert_eq!(header(msg, "CSeq"), Some("1 OPTIONS"));
        assert_eq!(header(msg, "two"), None);
    }

    #[test]
    fn an_index_finds_what_a_scan_finds() {
        let lines = [
            "Via: SIP/2.0/UDP a;branch=1\r\n",
            "v: SIP/2.0/UDP b\r\n",
            "V:c\r\n",
            "via : d \r\n",
            "  Via: e\r\n",
            "\tTo: <sip:x>;tag=1\r\n",
            "t: <sip:y>\r\n",
            "i: 1@h\r\n",
            "I :2@h\r\n",
            "Call-ID: 3@h\r\n",
            "CSeq: 1 INVITE\r\n",
            "Subject: one\r\n two\r\n\tthree\r\n",
            "Foo\r\n bar: x\r\n",
            "no colon here\r\n",
            ": empty name\r\n",
            "\rVia: cr\r\n",
            "\x0cTo: ff\r\n",
            "To\x0c: ff after\r\n",
            "Contact: <sip:c>\n",
            "m: <sip:m>\r\n",
            "X-Long-Header-Name: value: with colon\r\n",
            "i\r\n : folded compact\r\n",
            "\r\n",
            "\r\n ",
            "\n",
            "Content-Type: application/sdp\r\n",
        ];
        let names = ["Via", "via", "To", "Call-ID", "i", "CSeq", "Subject", "Foo", "Foo\r\n bar", "", "Contact", "X-Long-Header-Name", "Content-Type", "t", "Nope"];
        let mut seed = 12345u32;
        let mut next = |n: usize| {
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            (seed >> 16) as usize % n
        };
        for _ in 0..3000 {
            let mut msg = String::from(["INVITE sip:x SIP/2.0\r\n", "SIP/2.0 200 OK\n", ""][next(3)]);
            for _ in 0..next(12) {
                msg += lines[next(lines.len())];
            }
            msg += ["\r\n", "", "\r\nbody\r\nVia: body\r\n"][next(3)];
            let arc: Arc<str> = msg.as_str().into();
            index(&arc);
            for name in names {
                assert_eq!(header(&arc, name), header(&msg, name), "{msg:?} {name:?}");
                assert_eq!(header_lines(&arc, name), header_lines(&msg, name), "{msg:?} {name:?}");
                assert_eq!(header_content(&arc, name), header_content(&msg, name), "{msg:?} {name:?}");
                let mut joined = String::new();
                write_header(&mut joined, &msg, name, false);
                assert_eq!(header_content(&msg, name), joined, "{msg:?} {name:?}");
                assert_eq!(top_via_branch(&arc), top_via_branch(&msg), "{msg:?}");
                for with_name in [false, true] {
                    let (mut a, mut b) = (String::from("x "), String::from("x "));
                    write_header(&mut a, &arc, name, with_name);
                    write_header(&mut b, &msg, name, with_name);
                    assert_eq!(a, b, "{msg:?} {name:?}");
                }
            }
        }
    }

    #[test]
    fn headers_as_sipps_get_header_finds_them() {
        let get = |msg: &str, name: &str, with_name: bool| {
            let mut out = String::new();
            write_header(&mut out, msg, name, with_name);
            out
        };
        // The name right before its colon, or the compact form.
        assert_eq!(get("X\r\nVia : a\r\n Via: b\r\nvia:c\r\nv: d\r\n", "Via", true), "Via: c, d");
        assert_eq!(get("X\r\nc: a/b\r\nl: 0\r\n", "Content-Type", false), "a/b");
        assert_eq!(get("X\r\nVia: a\r\n", "v", false), "");
        // Only a CRLF after a CRLF ends the headers, whatever follows.
        assert_eq!(get("X\r\nA: 1\n\nA: 2\r\n\r\n A: 3\r\n", "A", false), "1, 2");
        assert_eq!(get("X\r\n\r\n\tA: 1\r\n", "A", false), "");
        // An empty value at a bare line feed misses the line after it.
        assert_eq!(get("X\r\nA:\nA: 1\r\nA: 2\r\n", "A", true), "A: 2");
        // Its CR before the end, its first character kept, and no CR or
        // line feed twice.
        assert_eq!(get("X\r\nA:\r\nB: 1\r\n", "A", false), "\r");
        assert_eq!(get("X\r\nA: 1\r\r\n  2\n\n\r\n", "A", false), "1\r\n  2");
    }

    #[test]
    fn call_id_and_peer_tag_as_sipp_finds_them() {
        // From the start line on, the value up to its CRLF.
        assert_eq!(call_id("i: a b \r\n"), Ok("a b "));
        assert_eq!(call_id("X\r\nCall-id :\r\n  a\r\n b\r\nTo: x\r\n"), Ok("a\r\n b"));
        assert_eq!(call_id("X\r\nCall-ID:\r\nTo: x\r\n"), Ok(""));
        assert_eq!(call_id("X\r\nCall-IDs: a\r\nCall-ID: b\nTo: x"), Ok("b\nTo: x"));
        // Not past the blank line, nor a line feed without its CR.
        assert_eq!(call_id("X\r\nTo: x\r\n\r\nCall-ID: a\r\n"), Ok(""));
        assert_eq!(call_id("X\r\nTo: x\nCall-ID: a\r\n"), Err(8));
        assert_eq!(call_id("\nX\r\nCall-ID: a\r\n"), Err(0));
        assert_eq!(call_id(&format!("X\r\nCall-ID: {}\r\n", "a".repeat(2049))), Ok(""));
        // The tag past the <addr-spec>, its name in any case.
        assert_eq!(peer_tag("X\r\nt: <sip:a;tag=u>;x=1; TAG=b c\r\n"), Ok(Some(Some("b"))));
        assert_eq!(peer_tag("X\r\nTo: sip:a;tag=u\r\n"), Ok(Some(Some("u"))));
        assert_eq!(peer_tag("X\r\nTo: <sip:a>\r\n ;tag=f\r\n"), Ok(Some(Some("f"))));
        assert_eq!(peer_tag("X\r\nTo: <sip:a>\r\nX: ;tag=u\r\n"), Ok(Some(None)));
        assert_eq!(peer_tag("X\r\nFrom: a\r\n\r\n"), Ok(None));
        assert_eq!(peer_tag("X\nTo: a;tag=b\r\n"), Err(1));
    }

    #[test]
    fn the_body_starts_after_the_first_blank_line() {
        for msg in ["", "\r\n\r\n", "a\r\n\r\nb\r\n\r\n", "a\n\r\n\r\n", "a\r\n\n\r\n", "a\r\r\n\r\n", "\n\n\r\n\r", "a\r\n\r\r\n\r\n", RESP] {
            assert_eq!(body_start(msg), msg.find("\r\n\r\n"), "{msg:?}");
        }
    }

    #[test]
    fn start_line() {
        assert_eq!(kind(RESP), Some(Kind::Response(200)));
        assert_eq!(kind("ACK sip:a SIP/2.0\r\n\r\n"), Some(Kind::Request("ACK")));
        assert_eq!(kind(""), None);
        // SIPp's get_reply_code(), on the start line only.
        for (msg, code) in [
            ("SIP/2.0\r\nCall-ID: b\r\n\r\n", 0),
            ("SIP/2.0\r\nX: a 486\r\n\r\n", 0),
            ("SIP/2.0 abc\r\n\r\n", 0),
            ("SIP/2.0 18\r\n\r\n", 18),
            ("SIP/2.0\t \t+200 OK\r\n\r\n", 200),
            ("SIP/2.0x 404 Not Found\r\n\r\n", 404),
            ("SIP/2.0 99999\r\n\r\n", u16::MAX),
            ("SIP/2.0 -5\r\n\r\n", u16::MAX),
        ] {
            assert_eq!(kind(msg), Some(Kind::Response(code)), "{msg:?}");
        }
    }

    #[test]
    fn headers_stop_at_body_and_accept_compact_forms() {
        assert_eq!(
            header_lines(RESP, "Via"),
            vec!["Via: SIP/2.0/UDP a;branch=1", "via: SIP/2.0/UDP b;branch=2"]
        );
        assert_eq!(header(RESP, "Call-ID"), Some("1-2@h"));
        assert_eq!(cseq_method(RESP), Some("BYE"));
        assert_eq!(peer_tag(RESP), Ok(Some(Some("abc"))));
        assert_eq!(cseq_number(RESP), Some(2));
        assert_eq!(cseq_value(RESP), Ok(2));
        // In SIPp's spellings only, anywhere, as strtoul() reads it.
        assert_eq!(cseq_value("X\r\ncSeq: 1 A\r\n\r\nb\r\nCseq: 2"), Ok(2));
        assert_eq!(cseq_value("X\r\nCSEQ:\t 12x\r\nCSeq: -1"), Ok(u64::MAX));
        assert_eq!(cseq_value("X\r\nCSeq:\r\n 7"), Ok(7));
        assert_eq!(cseq_value("X\r\nCSeq: 99999999999999999999"), Ok(u64::MAX));
        assert_eq!(cseq_value("X\r\nCSeq:  "), Err("No valid Cseq data in header".into()));
        assert_eq!(cseq_value("CSeq: 1\r\n"), Err("No valid Cseq header in request CSeq: 1\r\n".into()));
        assert_eq!(top_via_branch(RESP), Some("1"));
        assert_eq!(header_content(RESP, "Via"), "SIP/2.0/UDP a;branch=1, SIP/2.0/UDP b;branch=2");
        assert_eq!(header_content(RESP, "CSeq"), Cow::Borrowed("2 BYE"));
        assert_eq!(header_content(RESP, "Contact"), "");
        // The top Via without a branch: the next one's, as in all of them
        // joined.
        assert_eq!(top_via_branch("SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP a\r\nv: SIP/2.0/UDP b;branch=z9;x\r\n\r\n"), Some("z9"));
    }
}

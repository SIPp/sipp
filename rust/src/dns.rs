//! DNS NAPTR (RFC 3403) and SRV (RFC 2782) records, to locate SIP servers
//! (RFC 3263), as SIPp's dns.cpp: the answers come from the system
//! resolver (res_query), and are parsed here.

#[derive(Clone, Debug, PartialEq)]
pub struct Naptr {
    pub order: u16,
    pub preference: u16,
    pub flags: String,
    pub service: String,
    /// "." if there is none.
    pub replacement: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Srv {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    /// "." if the service is not available.
    pub target: String,
}

const HFIXEDSZ: usize = 12;
const QFIXEDSZ: usize = 4;
const RRFIXEDSZ: usize = 10;
const C_IN: u16 = 1;
const T_SRV: u16 = 33;
const T_NAPTR: u16 = 35;
/// The longest name dn_expand() writes, its NUL included.
const MAXDNAME: usize = 1025;
/// The longest name on the wire.
const MAXCDNAME: usize = 255;

fn get16(msg: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*msg.get(at)?, *msg.get(at + 1)?]))
}

/// dn_skipname(): the length of the name at `at`, up to its end or its
/// first compression pointer.
fn skip_name(msg: &[u8], at: usize) -> Option<usize> {
    let mut p = at;
    loop {
        let n = *msg.get(p)? as usize;
        p += 1;
        match n & 0xc0 {
            0 if n == 0 => break,
            0 => p += n,
            0xc0 => {
                p += 1;
                break;
            }
            _ => return None,
        }
    }
    (p <= msg.len()).then_some(p - at)
}

/// dn_expand(): the name at `at` in presentation format ("" for the
/// root), and its length in the message. Pointers may go anywhere in
/// the message, but not round in a loop.
fn expand_name(msg: &[u8], at: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let (mut p, mut len, mut wire, mut checked) = (at, None, 0usize, 0usize);
    loop {
        let n = *msg.get(p)? as usize;
        p += 1;
        match n & 0xc0 {
            0 if n == 0 => break,
            0 => {
                let label = msg.get(p..p + n)?;
                wire += n + 1;
                if wire + 1 > MAXCDNAME {
                    return None;
                }
                if !name.is_empty() {
                    name.push('.');
                }
                for &c in label {
                    match c {
                        b'.' | b';' | b'\\' | b'(' | b')' | b'@' | b'$' | b'"' => {
                            name.push('\\');
                            name.push(c as char);
                        }
                        0x21..=0x7e => name.push(c as char),
                        _ => name.push_str(&format!("\\{c:03}")),
                    }
                }
                p += n;
                checked += n + 1;
            }
            0xc0 => {
                let low = *msg.get(p)? as usize;
                len.get_or_insert(p + 1 - at);
                p = (n & 0x3f) << 8 | low;
                // Each pointer followed counts: a loop runs past the message.
                checked += 2;
                if checked >= msg.len() {
                    return None;
                }
            }
            _ => return None,
        }
    }
    if name.len() + 1 > MAXDNAME {
        return None;
    }
    Some((name, len.unwrap_or_else(|| p - at)))
}

/// Calls rdata(at, length) on each answer of that type in the DNS
/// message: the others, such as the CNAME that led to them, are skipped.
/// False if the message is malformed or rdata returns false.
fn answers(msg: &[u8], qtype: u16, mut rdata: impl FnMut(usize, usize) -> bool) -> bool {
    let (Some(questions), Some(count)) = (get16(msg, 4), get16(msg, 6)) else { return false };
    if msg.len() < HFIXEDSZ {
        return false;
    }
    let mut p = HFIXEDSZ;
    for _ in 0..questions {
        match skip_name(msg, p) {
            Some(n) if msg.len() - p >= n + QFIXEDSZ => p += n + QFIXEDSZ,
            _ => return false,
        }
    }
    for _ in 0..count {
        match skip_name(msg, p) {
            Some(n) if msg.len() - p >= n + RRFIXEDSZ => p += n,
            _ => return false,
        }
        let (rrtype, rrclass, rdlength) = (get16(msg, p), get16(msg, p + 2), get16(msg, p + 8));
        let (Some(rrtype), Some(rrclass), Some(rdlength)) = (rrtype, rrclass, rdlength) else { return false };
        p += RRFIXEDSZ;
        let rdlength = rdlength as usize;
        if msg.len() - p < rdlength {
            return false;
        }
        if rrtype == qtype && rrclass == C_IN && !rdata(p, rdlength) {
            return false;
        }
        p += rdlength;
    }
    true
}

/// The name at `at`, within `length` bytes: "." for the root. Its length
/// in the message.
fn rdata_name(msg: &[u8], at: usize, length: usize) -> Option<(String, usize)> {
    let (name, n) = expand_name(msg, at)?;
    (n <= length).then(|| (if name.is_empty() { ".".into() } else { name }, n))
}

/// The <character-string> at `at`, within `length` bytes. Its length in
/// the message.
fn rdata_string(msg: &[u8], at: usize, length: usize) -> Option<(String, usize)> {
    let n = *msg.get(at)? as usize;
    if length < 1 || length - 1 < n {
        return None;
    }
    Some((String::from_utf8_lossy(msg.get(at + 1..at + 1 + n)?).into_owned(), 1 + n))
}

/// The NAPTR records of the answer section of a DNS message, appended;
/// false if it is malformed.
pub fn naptr_parse(msg: &[u8], records: &mut Vec<Naptr>) -> bool {
    answers(msg, T_NAPTR, |mut p, mut length| {
        if length < 4 {
            return false;
        }
        let (Some(order), Some(preference)) = (get16(msg, p), get16(msg, p + 2)) else { return false };
        p += 4;
        length -= 4;
        let mut strings = [String::new(), String::new(), String::new()];
        for s in &mut strings {
            let Some((v, n)) = rdata_string(msg, p, length) else { return false };
            *s = v;
            p += n;
            length -= n;
        }
        let Some((replacement, _)) = rdata_name(msg, p, length) else { return false };
        let [flags, service, _regexp] = strings;
        records.push(Naptr { order, preference, flags, service, replacement });
        true
    })
}

/// The SRV records of the answer section of a DNS message, appended;
/// false if it is malformed.
pub fn srv_parse(msg: &[u8], records: &mut Vec<Srv>) -> bool {
    answers(msg, T_SRV, |p, length| {
        if length < 7 {
            return false;
        }
        let Some((target, _)) = rdata_name(msg, p + 6, length - 6) else { return false };
        let (Some(priority), Some(weight), Some(port)) = (get16(msg, p), get16(msg, p + 2), get16(msg, p + 4)) else { return false };
        records.push(Srv { priority, weight, port, target });
        true
    })
}

/// Keeps the records that lead to SRV records (flags "s") for service,
/// such as "SIP+D2U", in the order to try them: by order, then by
/// preference.
pub fn naptr_select(records: &mut Vec<Naptr>, service: &str) {
    records.retain(|r| r.flags.eq_ignore_ascii_case("s") && r.service.eq_ignore_ascii_case(service) && r.replacement != ".");
    records.sort_by_key(|r| (r.order, r.preference));
}

/// Puts records in the order to try them (RFC 2782): by priority, and in
/// a weighted random order within a priority. random(n) returns a number
/// from 0 to n, both included.
pub fn srv_order(records: &mut [Srv], random: &mut dyn FnMut(u32) -> u32) {
    records.sort_by_key(|r| r.priority);
    let mut first = 0;
    while first < records.len() {
        let last = first + records[first..].iter().take_while(|r| r.priority == records[first].priority).count();
        // Those of weight 0 first: they are picked only when the random
        // number is 0.
        records[first..last].sort_by_key(|r| r.weight != 0);
        while first < last {
            let sum = records[first..last].iter().fold(0u32, |s, r| s.wrapping_add(r.weight.into()));
            let pick = random(sum);
            let mut r = first;
            let mut running = records[r].weight as u32;
            while running < pick && r + 1 != last {
                r += 1;
                running = running.wrapping_add(records[r].weight.into());
            }
            records[first..=r].rotate_right(1);
            first += 1;
        }
    }
}

/// The SRV records of name, in the order to try them; none if the lookup
/// fails or has no answer.
pub fn srv_lookup(name: &str, random: &mut dyn FnMut(u32) -> u32) -> Vec<Srv> {
    let mut records = Vec::new();
    if !srv_parse(&sys::query(name, T_SRV), &mut records) {
        records.clear();
    }
    srv_order(&mut records, random);
    records
}

/// The SRV records to try for host over one SIP transport (RFC 3263):
/// those of the first NAPTR record of host for service that has some or,
/// if host has no NAPTR record for service, those of prefix + host. With
/// the SRV name, and whether a NAPTR record gave it.
pub fn sip_srv_lookup(host: &str, service: &str, prefix: &str, random: &mut dyn FnMut(u32) -> u32) -> (Vec<Srv>, String, bool) {
    let mut naptrs = Vec::new();
    if !naptr_parse(&sys::query(host, T_NAPTR), &mut naptrs) {
        naptrs.clear();
    }
    naptr_select(&mut naptrs, service);
    for r in &naptrs {
        let records = srv_lookup(&r.replacement, random);
        if !records.is_empty() {
            return (records, r.replacement.clone(), true);
        }
    }
    if !naptrs.is_empty() {
        // RFC 3263 4.2: "If no SRV records were found, the client
        // performs an A or AAAA record lookup of the domain name."
        return (Vec::new(), String::new(), false);
    }
    // RFC 3263 4.1: "If no NAPTR records are found, the client constructs
    // SRV queries for those transport protocols it supports". Those for
    // other transports only count as none.
    let name = format!("{prefix}{host}");
    (srv_lookup(&name, random), name, false)
}

/// Whether host is an IP address, as getaddrinfo(AI_NUMERICHOST) takes
/// it.
pub fn is_numeric_host(host: &str) -> bool {
    sys::is_numeric_host(host)
}

/// The addresses of host, in getaddrinfo()'s order (AI_PASSIVE, any
/// family), or its error: an IP address in any form it takes, or a name.
pub fn addresses(host: &str) -> Result<Vec<std::net::IpAddr>, i32> {
    sys::addresses(host)
}

#[cfg(unix)]
mod sys {
    use std::ffi::{c_char, c_int, CString};
    use std::net::IpAddr;

    // glibc has res_query in libc from 2.34, and only as __res_query in
    // libresolv before: which one there is shows at run time.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    fn res_query() -> Option<unsafe extern "C" fn(*const c_char, c_int, c_int, *mut u8, c_int) -> c_int> {
        // SAFETY: dlsym() and dlopen() with NUL-terminated names; the
        // symbols found are res_query(), whose type this is.
        unsafe {
            let mut f = libc::dlsym(libc::RTLD_DEFAULT, c"res_query".as_ptr());
            if f.is_null() {
                let lib = libc::dlopen(c"libresolv.so.2".as_ptr(), libc::RTLD_NOW);
                if !lib.is_null() {
                    f = libc::dlsym(lib, c"__res_query".as_ptr());
                }
            }
            (!f.is_null()).then(|| std::mem::transmute::<*mut libc::c_void, unsafe extern "C" fn(*const c_char, c_int, c_int, *mut u8, c_int) -> c_int>(f))
        }
    }

    // macOS: res_9_query in libresolv, which <resolv.h> calls res_query.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[link(name = "resolv")]
    extern "C" {
        #[link_name = "res_9_query"]
        fn res_9_query(dname: *const c_char, class: c_int, type_: c_int, answer: *mut u8, anslen: c_int) -> c_int;
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    fn res_query() -> Option<unsafe extern "C" fn(*const c_char, c_int, c_int, *mut u8, c_int) -> c_int> {
        Some(res_9_query)
    }

    // musl and the BSDs: in libc.
    #[cfg(not(any(all(target_os = "linux", target_env = "gnu"), target_os = "macos", target_os = "ios")))]
    extern "C" {
        #[link_name = "res_query"]
        fn libc_res_query(dname: *const c_char, class: c_int, type_: c_int, answer: *mut u8, anslen: c_int) -> c_int;
    }
    #[cfg(not(any(all(target_os = "linux", target_env = "gnu"), target_os = "macos", target_os = "ios")))]
    fn res_query() -> Option<unsafe extern "C" fn(*const c_char, c_int, c_int, *mut u8, c_int) -> c_int> {
        Some(libc_res_query)
    }

    /// The answer to a query of name, empty if there is none.
    pub fn query(name: &str, qtype: u16) -> Vec<u8> {
        let (Ok(name), Some(res_query)) = (CString::new(name), res_query()) else { return Vec::new() };
        let mut answer = vec![0u8; 65535];
        // SAFETY: a NUL-terminated name, and a buffer of the length given.
        let len = unsafe { res_query(name.as_ptr(), super::C_IN.into(), qtype.into(), answer.as_mut_ptr(), answer.len() as c_int) };
        // What did not fit is cut off: that fails to parse.
        answer.truncate(len.clamp(0, answer.len() as c_int) as usize);
        answer
    }

    pub fn addresses(host: &str) -> Result<Vec<IpAddr>, i32> {
        let Ok(host) = CString::new(host) else { return Err(libc::EAI_NONAME) };
        let mut out = Vec::new();
        // SAFETY: zeroed hints are valid; getaddrinfo() gets a
        // NUL-terminated name, each address read is of its ai_family, and
        // what it returns is freed.
        unsafe {
            let mut hints: libc::addrinfo = std::mem::zeroed();
            hints.ai_flags = libc::AI_PASSIVE;
            let mut res = std::ptr::null_mut();
            let ret = libc::getaddrinfo(host.as_ptr(), std::ptr::null(), &hints, &mut res);
            if ret != 0 {
                return Err(ret);
            }
            let mut ai = res;
            while let Some(a) = ai.as_ref() {
                let ip = match a.ai_family {
                    libc::AF_INET => Some(IpAddr::from(u32::from_be((*a.ai_addr.cast::<libc::sockaddr_in>()).sin_addr.s_addr).to_be_bytes())),
                    libc::AF_INET6 => Some(IpAddr::from((*a.ai_addr.cast::<libc::sockaddr_in6>()).sin6_addr.s6_addr)),
                    _ => None,
                };
                // One for each socket type.
                if let Some(ip) = ip.filter(|ip| !out.contains(ip)) {
                    out.push(ip);
                }
                ai = a.ai_next;
            }
            libc::freeaddrinfo(res);
        }
        Ok(out)
    }

    pub fn is_numeric_host(host: &str) -> bool {
        let Ok(host) = CString::new(host) else { return false };
        // SAFETY: zeroed hints are valid; getaddrinfo() gets a
        // NUL-terminated name, and what it returns is freed.
        unsafe {
            let mut hints: libc::addrinfo = std::mem::zeroed();
            hints.ai_flags = libc::AI_NUMERICHOST;
            let mut res = std::ptr::null_mut();
            if libc::getaddrinfo(host.as_ptr(), std::ptr::null(), &hints, &mut res) != 0 {
                return false;
            }
            libc::freeaddrinfo(res);
            true
        }
    }
}

/// No resolver to ask yet (DnsQuery on Windows): no records, so the host
/// is resolved as is.
#[cfg(not(unix))]
mod sys {
    use std::net::IpAddr;

    pub fn query(_name: &str, _qtype: u16) -> Vec<u8> {
        Vec::new()
    }

    pub fn is_numeric_host(host: &str) -> bool {
        host.parse::<std::net::IpAddr>().is_ok()
    }

    /// std's getaddrinfo(), with its error: WSAHOST_NOT_FOUND if it has none.
    pub fn addresses(host: &str) -> Result<Vec<IpAddr>, i32> {
        use std::net::ToSocketAddrs;
        let mut out: Vec<IpAddr> = Vec::new();
        for a in (host, 0).to_socket_addrs().map_err(|e| e.raw_os_error().unwrap_or(11001))? {
            if !out.contains(&a.ip()) {
                out.push(a.ip());
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// _sip._udp.example.test: a CNAME, then two SRV records whose targets
    /// are compressed. The question name is at 12, example.test at 22 and
    /// test at 30.
    const SRV_ANSWER: &[u8] = b"\x12\x34\x81\x80\x00\x01\x00\x03\x00\x00\x00\x00\
        \x04_sip\x04_udp\x07example\x04test\x00\x00\x21\x00\x01\
        \xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x06\x03foo\xc0\x16\
        \xc0\x0c\x00\x21\x00\x01\x00\x00\x00\x3c\x00\x0d\x00\x0a\x00\x3c\x13\xc4\x04sip1\xc0\x16\
        \xc0\x0c\x00\x21\x00\x01\x00\x00\x00\x3c\x00\x0d\x00\x14\x00\x00\x16\x2e\x04sip2\xc0\x1e";

    fn srv(priority: u16, weight: u16, port: u16, target: &str) -> Srv {
        Srv { priority, weight, port, target: target.into() }
    }

    #[test]
    fn srv_parse_compressed_skipping_cname() {
        let mut records = Vec::new();
        assert!(srv_parse(SRV_ANSWER, &mut records));
        assert_eq!(records, [srv(10, 60, 5060, "sip1.example.test"), srv(20, 0, 5678, "sip2.test")]);
    }

    #[test]
    fn srv_parse_truncated() {
        for len in 0..SRV_ANSWER.len() {
            assert!(!srv_parse(&SRV_ANSWER[..len], &mut Vec::new()), "{len}");
        }
    }

    #[test]
    fn srv_parse_bad_rdlength() {
        // An SRV record whose target runs past its data.
        let msg = b"\x00\x00\x81\x80\x00\x00\x00\x01\x00\x00\x00\x00\
            \x00\x00\x21\x00\x01\x00\x00\x00\x3c\x00\x08\x00\x0a\x00\x00\x13\xc4\x04sip1\x00";
        assert!(!srv_parse(msg, &mut Vec::new()));
    }

    #[test]
    fn srv_parse_root_target() {
        let msg = b"\x00\x00\x81\x80\x00\x00\x00\x01\x00\x00\x00\x00\
            \x00\x00\x21\x00\x01\x00\x00\x00\x3c\x00\x07\x00\x00\x00\x00\x00\x00\x00";
        let mut records = Vec::new();
        assert!(srv_parse(msg, &mut records));
        assert_eq!(records, [srv(0, 0, 0, ".")]);
    }

    #[test]
    fn name_pointer_loop() {
        // A target pointing at itself.
        let msg = b"\x00\x00\x81\x80\x00\x00\x00\x01\x00\x00\x00\x00\
            \x00\x00\x21\x00\x01\x00\x00\x00\x3c\x00\x08\x00\x00\x00\x00\x00\x00\xc0\x1d";
        assert!(!srv_parse(msg, &mut Vec::new()));
        assert_eq!(expand_name(b"\x03a.b\x01\\\x00", 0), Some(("a\\.b.\\\\".into(), 7)));
    }

    /// example.test: NAPTR records, their replacements compressed. The
    /// question name is at 12.
    const NAPTR_ANSWER: &[u8] = b"\x12\x34\x81\x80\x00\x01\x00\x04\x00\x00\x00\x00\
        \x07example\x04test\x00\x00\x23\x00\x01\
        \xc0\x0c\x00\x23\x00\x01\x00\x00\x00\x3c\x00\x1b\
        \x00\x14\x00\x0a\x01s\x07SIP+D2U\x00\x04_sip\x04_udp\xc0\x0c\
        \xc0\x0c\x00\x23\x00\x01\x00\x00\x00\x3c\x00\x1b\
        \x00\x0a\x00\x32\x01S\x07sip+d2t\x00\x04_sip\x04_tcp\xc0\x0c\
        \xc0\x0c\x00\x23\x00\x01\x00\x00\x00\x3c\x00\x14\
        \x00\x05\x00\x00\x00\x07SIP+D2U\x00\x03foo\xc0\x0c\
        \xc0\x0c\x00\x23\x00\x01\x00\x00\x00\x3c\x00\x15\
        \x00\x01\x00\x00\x01s\x07SIP+D2U\x05!x!y!\x00";

    #[test]
    fn naptr_parse_compressed() {
        let mut records = Vec::new();
        assert!(naptr_parse(NAPTR_ANSWER, &mut records));
        assert_eq!(records.len(), 4);
        assert_eq!((records[0].order, records[0].preference), (20, 10));
        assert_eq!((records[0].flags.as_str(), records[0].service.as_str()), ("s", "SIP+D2U"));
        assert_eq!(records[0].replacement, "_sip._udp.example.test");
        assert_eq!(records[1].replacement, "_sip._tcp.example.test");
        assert_eq!(records[2].flags, "");
        assert_eq!(records[2].replacement, "foo.example.test");
        assert_eq!(records[3].replacement, ".");
    }

    #[test]
    fn naptr_parse_truncated() {
        for len in 0..NAPTR_ANSWER.len() {
            assert!(!naptr_parse(&NAPTR_ANSWER[..len], &mut Vec::new()), "{len}");
        }
    }

    #[test]
    fn naptr_parse_bad_string() {
        // A flags string longer than the record.
        let msg = b"\x00\x00\x81\x80\x00\x00\x00\x01\x00\x00\x00\x00\
            \x00\x00\x23\x00\x01\x00\x00\x00\x3c\x00\x06\x00\x0a\x00\x0a\x05s\x00\x00\x00\x00\x00\x00";
        assert!(!naptr_parse(msg, &mut Vec::new()));
    }

    #[test]
    fn naptr_select_service() {
        let mut records = Vec::new();
        assert!(naptr_parse(NAPTR_ANSWER, &mut records));
        let (mut udp, mut tcp, mut sctp) = (records.clone(), records.clone(), records);
        naptr_select(&mut udp, "SIP+D2U");
        assert_eq!(udp.iter().map(|r| r.replacement.as_str()).collect::<Vec<_>>(), ["_sip._udp.example.test"]);
        naptr_select(&mut tcp, "SIP+D2T");
        assert_eq!(tcp.iter().map(|r| r.replacement.as_str()).collect::<Vec<_>>(), ["_sip._tcp.example.test"]);
        naptr_select(&mut sctp, "SIP+D2S");
        assert!(sctp.is_empty());
    }

    #[test]
    fn naptr_select_order() {
        let naptr = |order, preference, replacement: &str| Naptr {
            order,
            preference,
            flags: "s".into(),
            service: "SIP+D2U".into(),
            replacement: replacement.into(),
        };
        let mut records = vec![naptr(20, 1, "d"), naptr(10, 50, "c"), naptr(10, 20, "a"), naptr(10, 20, "b")];
        naptr_select(&mut records, "SIP+D2U");
        assert_eq!(records.iter().map(|r| r.replacement.as_str()).collect::<String>(), "abcd");
    }

    fn targets(records: &[Srv]) -> String {
        records.iter().map(|r| r.target.as_str()).collect()
    }

    #[test]
    fn srv_order_priority() {
        let mut records = [srv(20, 0, 1, "c"), srv(10, 0, 1, "a"), srv(30, 0, 1, "d"), srv(10, 0, 1, "b")];
        srv_order(&mut records, &mut |n| n);
        assert_eq!(targets(&records), "abcd");
    }

    #[test]
    fn srv_order_zero_weights() {
        let mut records = [srv(10, 0, 1, "a"), srv(10, 0, 1, "b"), srv(10, 0, 1, "c")];
        srv_order(&mut records, &mut |n| n);
        assert_eq!(targets(&records), "abc");
    }

    #[test]
    fn srv_order_weights() {
        let records = [srv(10, 10, 1, "a"), srv(10, 0, 1, "z"), srv(10, 20, 1, "b"), srv(5, 1, 1, "x")];
        let (mut low, mut high, mut mid) = (records.clone(), records.clone(), records);
        // The one of weight 0 only when the pick is 0.
        srv_order(&mut low, &mut |_| 0);
        assert_eq!(targets(&low), "xzab");
        srv_order(&mut high, &mut |n| n);
        assert_eq!(targets(&high), "xbaz");
        // 5 is past z (0) and within a (10); then within b (0 + 20).
        srv_order(&mut mid, &mut |n| n.min(5));
        assert_eq!(targets(&mid), "xabz");
    }

    #[test]
    fn numeric_hosts() {
        assert!(is_numeric_host("127.0.0.1"));
        assert!(is_numeric_host("::1"));
        assert!(!is_numeric_host("example.test"));
    }
}

//! POSIX extended regexps through the C library, as SIPp compiles them
//! (REG_EXTENDED): the same syntax, and leftmost-longest matching.

use std::borrow::Cow;
use std::ffi::CString;
use std::fmt;

/// The C library's POSIX regex: glibc's, or on Windows, which has none,
/// musl's (vendor/musl-regex, which build.rs compiles).
#[cfg(unix)]
mod c {
    pub use libc::{regcomp, regerror, regex_t, regexec, regfree, regmatch_t, REG_EXTENDED};
}

#[cfg(windows)]
#[allow(non_camel_case_types)]
mod c {
    use std::ffi::{c_char, c_int, c_void};

    /// vendor/musl-regex/regex.h's.
    #[repr(C)]
    pub struct regex_t {
        re_nsub: usize,
        opaque: *mut c_void,
        padding: [*mut c_void; 4],
        nsub2: usize,
        padding2: c_char,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct regmatch_t {
        pub rm_so: isize,
        pub rm_eo: isize,
    }

    pub const REG_EXTENDED: c_int = 1;

    extern "C" {
        #[link_name = "sipp_regcomp"]
        pub fn regcomp(re: *mut regex_t, pattern: *const c_char, flags: c_int) -> c_int;
        #[link_name = "sipp_regexec"]
        pub fn regexec(re: *const regex_t, text: *const c_char, n: usize, m: *mut regmatch_t, flags: c_int) -> c_int;
        #[link_name = "sipp_regfree"]
        pub fn regfree(re: *mut regex_t);
        #[link_name = "sipp_regerror"]
        pub fn regerror(rc: c_int, re: *const regex_t, buf: *mut c_char, size: usize) -> usize;
    }
}

pub struct Regex {
    re: Box<c::regex_t>,
    pattern: String,
}

// SAFETY: a compiled regex_t is only read by regexec(), which POSIX makes
// safe to call from several threads at once.
unsafe impl Send for Regex {}
unsafe impl Sync for Regex {}

/// What a C function sees of a Rust string: its bytes (raw), up to the
/// first NUL; and whether they are the string's own.
fn c_bytes(s: &str) -> (CString, bool) {
    let b = crate::raw::bytes(s);
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    (CString::new(&b[..end]).expect("no NUL left"), matches!(b, Cow::Borrowed(_)))
}

fn c_string(s: &str) -> CString {
    c_bytes(s).0
}

impl Regex {
    pub fn new(pattern: &str) -> Result<Regex, String> {
        // SAFETY: regcomp() fills the zeroed regex_t it is given.
        let mut re: Box<c::regex_t> = Box::new(unsafe { std::mem::zeroed() });
        let p = c_string(pattern);
        // SAFETY: re and p are valid for the call.
        let rc = unsafe { c::regcomp(&mut *re, p.as_ptr(), c::REG_EXTENDED) };
        if rc != 0 {
            let mut buf = [0u8; 512];
            // SAFETY: regerror() writes at most buf.len() bytes, NUL included.
            unsafe { c::regerror(rc, &*re, buf.as_mut_ptr().cast(), buf.len()) };
            let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            return Err(format!("recomp error : regular expression '{pattern}' - error '{}'", String::from_utf8_lossy(&buf[..end])));
        }
        Ok(Regex { re, pattern: pattern.to_string() })
    }

    pub fn as_str(&self) -> &str {
        &self.pattern
    }

    pub fn is_match(&self, text: &str) -> bool {
        let t = c_string(text);
        // SAFETY: a compiled regex and a NUL-terminated string; no matches asked.
        unsafe { c::regexec(&*self.re, t.as_ptr(), 0, std::ptr::null_mut(), 0) == 0 }
    }

    /// The whole match and up to nine groups, None for a group that took
    /// no part: executeRegExp()'s ten regmatch_t. The match is over the
    /// bytes, as SIPp's (in the C locale): a group may hold part of a
    /// character, which is then raw bytes.
    pub fn captures<'t>(&self, text: &'t str) -> Option<Vec<Option<Cow<'t, str>>>> {
        let (t, own) = c_bytes(text);
        let mut m = [c::regmatch_t { rm_so: -1, rm_eo: -1 }; 10];
        // SAFETY: m has room for the ten matches asked for.
        if unsafe { c::regexec(&*self.re, t.as_ptr(), m.len(), m.as_mut_ptr(), 0) } != 0 {
            return None;
        }
        let bytes = t.as_bytes();
        Some(
            m.iter()
                .map(|r| {
                    let (so, eo) = (usize::try_from(r.rm_so).ok()?, usize::try_from(r.rm_eo).ok()?);
                    // A part of the text, unless it has raw bytes or the
                    // group cuts a character.
                    Some(match text.get(so..eo).filter(|_| own) {
                        Some(g) => Cow::Borrowed(g),
                        None => Cow::Owned(crate::raw::text(&bytes[so..eo]).into_owned()),
                    })
                })
                .collect(),
        )
    }
}

/// SIPp's integers (get_long()): blanks and a sign, then decimal digits,
/// or hex ones after "0x" (a leading 0 is not octal), and nothing after
/// them. None for no digits, or more than an i64 holds.
pub fn integer(s: &str) -> Option<i64> {
    let s = s.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
    let (negative, s) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let (radix, digits) = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => (16, hex),
        None => (10, s),
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    let n = i64::from_str_radix(&format!("{}{digits}", if negative { "-" } else { "" }), radix).ok()?;
    Some(n)
}

/// The C library's strtoul(s, &end, 0) and strtod(): the number and what
/// follows it, as SIPp reads file headers and line numbers.
pub fn strtoul(s: &str) -> (u64, &str) {
    // SAFETY: a NUL-terminated string and an end pointer into it.
    #[cfg(unix)]
    return c_number(s, |p, end| unsafe { libc::strtoul(p, end, 0) as u64 });
    // Windows' unsigned long is 32 bits: SIPp's is 64 on Linux.
    #[cfg(windows)]
    return c_number(s, |p, end| unsafe { libc::strtoull(p, end, 0) as u64 });
}

pub fn strtod(s: &str) -> (f64, &str) {
    // SAFETY: as strtoul.
    c_number(s, |p, end| unsafe { libc::strtod(p, end) })
}

fn c_number<T>(s: &str, f: impl Fn(*const libc::c_char, *mut *mut libc::c_char) -> T) -> (T, &str) {
    let c = c_string(s);
    let mut end = std::ptr::null_mut();
    let v = f(c.as_ptr(), &mut end);
    // Only ASCII is consumed, so the offset is a char boundary.
    let used = end as usize - c.as_ptr() as usize;
    (v, &s[used..])
}

impl Drop for Regex {
    fn drop(&mut self) {
        // SAFETY: compiled by new(), freed once.
        unsafe { c::regfree(&mut *self.re) }
    }
}

impl fmt::Debug for Regex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Regex({:?})", self.pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::Regex;

    #[test]
    fn posix_leftmost_longest() {
        // Leftmost-first would take "a"; POSIX takes the longest.
        let re = Regex::new("a|ab").unwrap();
        assert_eq!(re.captures("xab").unwrap()[0].as_deref(), Some("ab"));
        let re = Regex::new("tag=([0-9]+)(;x)?").unwrap();
        let caps = re.captures("From: <sip:a>;tag=123").unwrap();
        assert_eq!((caps[0].as_deref(), caps[1].as_deref(), caps[2].as_deref()), (Some("tag=123"), Some("123"), None));
        // '.' matches a newline, and ^ only the start of the text.
        assert!(Regex::new("a.b").unwrap().is_match("a\nb"));
        assert!(!Regex::new("^b").unwrap().is_match("a\nb"));
        // POSIX syntax: no \d.
        assert!(!Regex::new("\\d").unwrap().is_match("1"));
        assert!(Regex::new("(").unwrap_err().starts_with("recomp error"));
    }

    #[test]
    fn matches_are_over_the_bytes() {
        let raw = |b: &[u8]| crate::raw::text(b).into_owned();
        let bytes = |s: &str| crate::raw::bytes(s).into_owned();
        // '.' is a byte, as in SIPp: part of a character, or a raw byte.
        let caps = Regex::new("^(.)(.*)$").unwrap().captures("\u{e9}t\u{e9}").unwrap();
        assert_eq!((bytes(caps[1].as_ref().unwrap()), bytes(caps[2].as_ref().unwrap())), (b"\xc3".to_vec(), b"\xa9t\xc3\xa9".to_vec()));
        let text = raw(b"From: Andr\xe9 <sip:a>;tag=\xff1");
        let caps = Regex::new("From: (Andr.) .*tag=(..)").unwrap().captures(&text).unwrap();
        assert_eq!((bytes(caps[1].as_ref().unwrap()), bytes(caps[2].as_ref().unwrap())), (b"Andr\xe9".to_vec(), b"\xff1".to_vec()));
        // A pattern's raw bytes match those bytes.
        assert!(Regex::new(&raw(b"r\xe9$")).unwrap().is_match(&raw(b"From: Andr\xe9")));
        assert!(!Regex::new(&raw(b"r\xe9$")).unwrap().is_match("Andr\u{e9}"));
        assert!(Regex::new("^Andr..$").unwrap().is_match("Andr\u{e9}"));
    }

    #[test]
    fn c_numbers() {
        use super::{integer, strtod, strtoul};
        assert_eq!((integer(" 0x10"), integer("010"), integer("-010"), integer("+7")), (Some(16), Some(10), Some(-10), Some(7)));
        assert_eq!((integer(""), integer(" "), integer("0x"), integer("5x"), integer("abc")), (None, None, None, None, None));
        assert_eq!((integer("9223372036854775807"), integer("9223372036854775808")), (Some(i64::MAX), None));
        assert_eq!(strtoul("5\r"), (5, "\r"));
        assert_eq!(strtod("1.5e3ms"), (1500.0, "ms"));
        assert_eq!(strtod(""), (0.0, ""));
    }
}

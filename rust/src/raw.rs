//! Bytes that are not UTF-8, carried through sipp-rs's Strings as SIPp
//! carries them through its char arrays: unchanged.
//!
//! Text comes in through text(), which keeps valid UTF-8 as it is and
//! makes each byte of an invalid sequence a private-use character,
//! U+10FF00 + the byte (U+10FF80..U+10FFFF: such bytes are never ASCII).
//! Those 128 characters, where they come in as UTF-8, are made such
//! bytes too, so that bytes() gives back exactly what came in. Anything
//! that goes out (the network, logs, stderr, commands) goes through
//! bytes(); len() is its length, as SIPp counts it.
//!
//! Until the first such character is made, nothing has any: bytes() and
//! len() then take the text as it is, and cost nothing.

use std::borrow::Cow;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

const BASE: u32 = 0x10FF00;

/// Whether a byte was ever made a character.
static USED: AtomicBool = AtomicBool::new(false);

/// The character that stands for `b`, a byte of 0x80 or more.
fn byte_char(b: u8) -> char {
    debug_assert!(b >= 0x80);
    USED.store(true, Relaxed);
    char::from_u32(BASE + u32::from(b)).unwrap()
}

/// The byte `c` stands for, if it stands for one.
fn byte_of(c: char) -> Option<u8> {
    let v = u32::from(c);
    (v >= BASE + 0x80).then(|| (v - BASE) as u8)
}

/// Does valid UTF-8 text hold any of the 128 characters?
fn has_byte_chars(s: &str) -> bool {
    // Their UTF-8 is F4 8F BE xx or F4 8F BF xx.
    let b = s.as_bytes();
    let mut at = 0;
    while let Some(i) = b[at..].iter().position(|&x| x == 0xF4) {
        at += i + 1;
        if b.get(at) == Some(&0x8F) && b.get(at + 1).is_some_and(|&x| x >= 0xBE) {
            return true;
        }
    }
    false
}

fn escape(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() + 16);
    for chunk in bytes.utf8_chunks() {
        let valid = chunk.valid();
        match has_byte_chars(valid) {
            true => valid.chars().for_each(|c| match byte_of(c) {
                Some(_) => c.encode_utf8(&mut [0; 4]).bytes().for_each(|b| out.push(byte_char(b))),
                None => out.push(c),
            }),
            false => out.push_str(valid),
        }
        chunk.invalid().iter().for_each(|&b| out.push(byte_char(b)));
    }
    out
}

/// Bytes as text, borrowed when they are UTF-8 (without the 128).
pub fn text(bytes: &[u8]) -> Cow<'_, str> {
    if bytes.is_ascii() {
        // SAFETY: ASCII is UTF-8.
        return Cow::Borrowed(unsafe { std::str::from_utf8_unchecked(bytes) });
    }
    match std::str::from_utf8(bytes) {
        Ok(s) if !has_byte_chars(s) => Cow::Borrowed(s),
        _ => Cow::Owned(escape(bytes)),
    }
}

/// text() of bytes owned: not copied when they are UTF-8.
pub fn text_owned(bytes: Vec<u8>) -> String {
    match String::from_utf8(bytes) {
        Ok(s) if s.is_ascii() || !has_byte_chars(&s) => s,
        Ok(s) => escape(s.as_bytes()),
        Err(e) => escape(e.as_bytes()),
    }
}

/// The bytes text() made the text from.
pub fn bytes(s: &str) -> Cow<'_, [u8]> {
    if !USED.load(Relaxed) || !s.as_bytes().contains(&0xF4) {
        return Cow::Borrowed(s.as_bytes());
    }
    let mut out = Vec::with_capacity(s.len());
    for c in s.chars() {
        match byte_of(c) {
            Some(b) => out.push(b),
            None => out.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes()),
        }
    }
    Cow::Owned(out)
}

/// The length of bytes(s).
pub fn len(s: &str) -> usize {
    if !USED.load(Relaxed) || !s.as_bytes().contains(&0xF4) {
        return s.len();
    }
    s.len() - 3 * s.chars().filter(|&c| byte_of(c).is_some()).count()
}

/// Writes bytes(s).
pub fn write(w: &mut impl Write, s: &str) -> std::io::Result<()> {
    w.write_all(&bytes(s))
}

/// eprintln!() of bytes(s).
pub fn eprintln(s: &str) {
    let mut e = std::io::stderr().lock();
    let _ = e.write_all(&bytes(s)).and_then(|()| e.write_all(b"\n"));
}

/// bytes(s) as a file name or a command's argument. Windows' take
/// Unicode: bytes that are not UTF-8 are replaced.
pub fn os(s: &str) -> std::ffi::OsString {
    #[cfg(unix)]
    return std::os::unix::ffi::OsStringExt::from_vec(bytes(s).into_owned());
    #[cfg(windows)]
    return String::from_utf8_lossy(&bytes(s)).into_owned().into();
}

/// An argument or environment value as text: its bytes as they are.
pub fn from_os(s: std::ffi::OsString) -> String {
    #[cfg(unix)]
    return text_owned(std::os::unix::ffi::OsStringExt::into_vec(s));
    #[cfg(windows)]
    return s.to_string_lossy().into_owned();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(b: &[u8]) -> String {
        let t = text(b).into_owned();
        assert_eq!(&*bytes(&t), b, "{b:x?}");
        assert_eq!(len(&t), b.len(), "{b:x?}");
        assert_eq!(text_owned(b.to_vec()), t, "{b:x?}");
        t
    }

    #[test]
    fn utf8_is_kept_as_it_is() {
        assert!(matches!(text(b"OPTIONS sip:x SIP/2.0"), Cow::Borrowed(_)));
        assert!(matches!(text("Andr\u{e9} \u{1F600}".as_bytes()), Cow::Borrowed(_)));
        assert_eq!(round_trip("Andr\u{e9}".as_bytes()), "Andr\u{e9}");
        // Near the 128, but not them.
        assert_eq!(round_trip("\u{10FF7F}\u{10FEFF}\u{10FFFF}x".as_bytes()).chars().count(), 7);
        assert!(matches!(text("\u{10FF7F}\u{FFFD}".as_bytes()), Cow::Borrowed(_)));
        assert!(matches!(bytes("Andr\u{e9}"), Cow::Borrowed(_)));
    }

    #[test]
    fn invalid_bytes_come_back_out() {
        assert_eq!(round_trip(b"Andr\xe9"), "Andr\u{10FFE9}");
        assert_eq!(round_trip(b"\x80\xff"), "\u{10FF80}\u{10FFFF}");
        // A sequence cut short, an overlong one, a surrogate, past U+10FFFF.
        round_trip(b"a\xc3");
        round_trip(b"\xc3a\xe2\x82");
        round_trip(b"\xc0\xaf\xed\xa0\x80\xf4\x90\x80\x80\xf8\x88\x80\x80\x80");
        // Valid UTF-8 between invalid bytes is kept.
        assert_eq!(round_trip(b"\xe9\xc3\xa9\xe9"), "\u{10FFE9}\u{e9}\u{10FFE9}");
        let every: Vec<u8> = (0..=255).collect();
        round_trip(&every);
        round_trip(&every.iter().rev().copied().collect::<Vec<_>>());
    }

    #[test]
    fn the_128_that_come_in_are_bytes_too() {
        // U+10FF80 and U+10FFFF as UTF-8 are 4 bytes each, which come back.
        let t = round_trip("a\u{10FF80}b\u{10FFFF}".as_bytes());
        assert_eq!(t.chars().count(), 10);
        assert_eq!(round_trip(b"\xe9\xf4\x8f\xbe\x80"), "\u{10FFE9}\u{10FFF4}\u{10FF8F}\u{10FFBE}\u{10FF80}");
        // A 4-byte sequence cut short before them.
        round_trip(b"\xf4\x8f\xf4\x8f\xbf\xbf");
    }

    #[cfg(unix)]
    #[test]
    fn os_strings_keep_the_bytes() {
        use std::os::unix::ffi::OsStrExt;
        let t = text(b"f\xe9.txt").into_owned();
        assert_eq!(os(&t).as_bytes(), b"f\xe9.txt");
        assert_eq!(from_os(os(&t)), t);
    }
}

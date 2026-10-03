//! SRTP (RFC 3711) for the AES_CM_128, AES_192_CM, AES_256_CM (RFC 6188)
//! and NULL ciphers with HMAC-SHA1-80/32, the suites SIPp offers.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use hmac::{Hmac, Mac};
use sha1::Sha1;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Suite {
    AesCm128Sha1_80,
    AesCm128Sha1_32,
    AesCm192Sha1_80,
    AesCm192Sha1_32,
    AesCm256Sha1_80,
    AesCm256Sha1_32,
    NullSha1_80,
    NullSha1_32,
}

impl Suite {
    pub fn from_name(name: &str) -> Option<Suite> {
        Some(match name {
            "AES_CM_128_HMAC_SHA1_80" => Suite::AesCm128Sha1_80,
            "AES_CM_128_HMAC_SHA1_32" => Suite::AesCm128Sha1_32,
            "AES_192_CM_HMAC_SHA1_80" => Suite::AesCm192Sha1_80,
            "AES_192_CM_HMAC_SHA1_32" => Suite::AesCm192Sha1_32,
            "AES_256_CM_HMAC_SHA1_80" => Suite::AesCm256Sha1_80,
            "AES_256_CM_HMAC_SHA1_32" => Suite::AesCm256Sha1_32,
            "NULL_HMAC_SHA1_80" => Suite::NullSha1_80,
            "NULL_HMAC_SHA1_32" => Suite::NullSha1_32,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Suite::AesCm128Sha1_80 => "AES_CM_128_HMAC_SHA1_80",
            Suite::AesCm128Sha1_32 => "AES_CM_128_HMAC_SHA1_32",
            Suite::AesCm192Sha1_80 => "AES_192_CM_HMAC_SHA1_80",
            Suite::AesCm192Sha1_32 => "AES_192_CM_HMAC_SHA1_32",
            Suite::AesCm256Sha1_80 => "AES_256_CM_HMAC_SHA1_80",
            Suite::AesCm256Sha1_32 => "AES_256_CM_HMAC_SHA1_32",
            Suite::NullSha1_80 => "NULL_HMAC_SHA1_80",
            Suite::NullSha1_32 => "NULL_HMAC_SHA1_32",
        }
    }

    fn tag_len(self) -> usize {
        if self.name().ends_with("_80") { 10 } else { 4 }
    }

    fn encrypts(self) -> bool {
        !matches!(self, Suite::NullSha1_80 | Suite::NullSha1_32)
    }

    /// The master key a new line of ours gets: as long as the AES key,
    /// the NULL cipher keeping the 128-bit one of RFC 4568.
    pub fn key_len(self) -> usize {
        match self {
            Suite::AesCm192Sha1_80 | Suite::AesCm192Sha1_32 => 24,
            Suite::AesCm256Sha1_80 | Suite::AesCm256Sha1_32 => 32,
            _ => 16,
        }
    }
}

/// The master salt, 14 bytes after the key in all suites.
pub const SALT_LEN: usize = 14;

/// AES of the key's length, as JLSRTP keys it for both the key derivation
/// and the session cipher.
/// Each boxed: an AES-256 key schedule is a third larger than an AES-128
/// one, which most keys are.
enum Aes {
    A128(Box<Aes128>),
    A192(Box<Aes192>),
    A256(Box<Aes256>),
}

impl Aes {
    fn new(key: &[u8]) -> Option<Aes> {
        Some(match key.len() {
            16 => Aes::A128(Box::new(Aes128::new(key.into()))),
            24 => Aes::A192(Box::new(Aes192::new(key.into()))),
            32 => Aes::A256(Box::new(Aes256::new(key.into()))),
            _ => return None,
        })
    }

    #[cfg(test)]
    fn encrypt_block(&self, block: &mut aes::Block) {
        self.encrypt_blocks(std::slice::from_mut(block));
    }

    fn encrypt_blocks(&self, blocks: &mut [aes::Block]) {
        match self {
            Aes::A128(k) => k.encrypt_blocks(blocks),
            Aes::A192(k) => k.encrypt_blocks(blocks),
            Aes::A256(k) => k.encrypt_blocks(blocks),
        }
    }
}

/// AES in counter mode: the keystream for `iv`, XORed into `data`. The
/// counters of up to 16 blocks, a whole RTP packet of 20 ms of G.711,
/// are encrypted at once, which AES-NI pipelines.
fn aes_cm(key: &Aes, iv: [u8; 16], data: &mut [u8]) {
    let ctr = u16::from_be_bytes([iv[14], iv[15]]);
    let mut blocks = [aes::Block::default(); 16];
    for (n, part) in data.chunks_mut(blocks.len() * 16).enumerate() {
        let blocks = &mut blocks[..part.len().div_ceil(16)];
        for (i, block) in blocks.iter_mut().enumerate() {
            block[..14].copy_from_slice(&iv[..14]);
            block[14..].copy_from_slice(&ctr.wrapping_add((n * 16 + i) as u16).to_be_bytes());
        }
        key.encrypt_blocks(blocks);
        for (b, k) in part.iter_mut().zip(blocks.iter().flatten()) {
            *b ^= k;
        }
    }
}

/// The session keys derived from a master key (RFC 3711 4.3, kdr 0), the
/// encryption key as long as the master key (RFC 6188 3).
struct Keys {
    cipher: Aes,
    salt: [u8; 14],
    /// HMAC-SHA1 keyed with the authentication key: its pads hashed once,
    /// and cloned for each packet.
    mac: Hmac<Sha1>,
}

/// `master` is the key and its salt, whose length (16, 24 or 32 bytes)
/// picks the AES, as in SIPp; None for any other.
fn derive(master: &[u8]) -> Option<Keys> {
    let key_len = master.len().checked_sub(SALT_LEN)?;
    let master_key = Aes::new(&master[..key_len])?;
    let master_salt = &master[key_len..];
    let prf = |label: u8, len: usize| -> Vec<u8> {
        // x = (label || r) XOR master_salt, right-aligned, r = 0; IV = x * 2^16.
        let mut iv = [0u8; 16];
        iv[..14].copy_from_slice(master_salt);
        iv[7] ^= label;
        let mut out = vec![0u8; len];
        aes_cm(&master_key, iv, &mut out);
        out
    };
    Some(Keys {
        cipher: Aes::new(&prf(0, key_len))?,
        salt: prf(2, 14).try_into().unwrap(),
        mac: <Hmac<Sha1> as Mac>::new_from_slice(&prf(1, 20)).expect("any key length"),
    })
}

/// One direction of an SRTP stream: its keys and rollover counter.
pub struct Context {
    suite: Suite,
    /// Boxed: an AES key schedule is a kilobyte or so, and each call's
    /// media carries several contexts, SRTP or not.
    keys: Box<Keys>,
    roc: u32,
    /// Highest sequence number seen, for guessing incoming packets' ROC.
    last_seq: Option<u16>,
}

impl Context {
    pub fn new(suite: Suite, master: &[u8]) -> Option<Context> {
        Some(Context { suite, keys: Box::new(derive(master)?), roc: 0, last_seq: None })
    }

    /// The size of its packets' authentication tag.
    pub fn tag_len(&self) -> usize {
        self.suite.tag_len()
    }

    fn header_len(p: &[u8]) -> Option<usize> {
        if p.len() < 12 {
            return None;
        }
        let mut len = 12 + 4 * (p[0] & 0x0f) as usize;
        if p[0] & 0x10 != 0 {
            let ext = p.get(len + 2..len + 4)?;
            len += 4 + 4 * u16::from_be_bytes([ext[0], ext[1]]) as usize;
        }
        (len <= p.len()).then_some(len)
    }

    fn iv(&self, ssrc: [u8; 4], index: u64) -> [u8; 16] {
        let mut iv = [0u8; 16];
        iv[..14].copy_from_slice(&self.keys.salt);
        for (i, b) in ssrc.iter().enumerate() {
            iv[4 + i] ^= b;
        }
        for (i, b) in index.to_be_bytes()[2..].iter().enumerate() {
            iv[8 + i] ^= b;
        }
        iv
    }

    /// The whole HMAC-SHA1, of which the suite's tag is the start.
    fn tag(&self, authenticated: &[u8], roc: u32) -> [u8; 20] {
        let mut mac = self.keys.mac.clone();
        mac.update(authenticated);
        mac.update(&roc.to_be_bytes());
        let mut tag = [0; 20];
        tag.copy_from_slice(&mac.finalize().into_bytes());
        tag
    }

    /// RTP to SRTP.
    #[cfg(test)]
    pub fn protect(&mut self, rtp: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        self.protect_into(rtp, &mut out).then_some(out)
    }

    /// protect() into `out`, which a caller keeps for its next packet.
    pub fn protect_into(&mut self, rtp: &[u8], out: &mut Vec<u8>) -> bool {
        let Some(hdr) = Self::header_len(rtp) else { return false };
        let seq = u16::from_be_bytes([rtp[2], rtp[3]]);
        if self.last_seq.is_some_and(|last| seq < last && last - seq > 0x8000) {
            self.roc = self.roc.wrapping_add(1);
        }
        self.last_seq = Some(seq);
        out.clear();
        out.extend_from_slice(rtp);
        if self.suite.encrypts() {
            let iv = self.iv(rtp[8..12].try_into().unwrap(), (u64::from(self.roc) << 16) | u64::from(seq));
            aes_cm(&self.keys.cipher, iv, &mut out[hdr..]);
        }
        let tag = self.tag(out, self.roc);
        out.extend_from_slice(&tag[..self.suite.tag_len()]);
        true
    }

    /// SRTP to RTP, None if the tag doesn't match.
    #[cfg(test)]
    pub fn unprotect(&mut self, srtp: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        self.unprotect_into(srtp, &mut out).then_some(out)
    }

    /// unprotect() into `out`, which a caller keeps for its next packet.
    pub fn unprotect_into(&mut self, srtp: &[u8], out: &mut Vec<u8>) -> bool {
        let tag_len = self.suite.tag_len();
        let Some(hdr) = Self::header_len(srtp) else { return false };
        if srtp.len() < hdr + tag_len {
            return false;
        }
        let (body, tag) = srtp.split_at(srtp.len() - tag_len);
        let seq = u16::from_be_bytes([body[2], body[3]]);
        // RFC 3711 Appendix A: the ROC that puts seq closest to the last one.
        let roc = match self.last_seq {
            None => self.roc,
            Some(last) if last < 0x8000 && seq > last + 0x8000 => self.roc.wrapping_sub(1),
            Some(last) if last >= 0x8000 && seq < last - 0x8000 => self.roc.wrapping_add(1),
            Some(_) => self.roc,
        };
        if self.tag(body, roc)[..tag_len] != *tag {
            return false;
        }
        if roc == self.roc.wrapping_add(1) || self.last_seq.is_none_or(|last| roc == self.roc && seq > last) {
            self.roc = roc;
            self.last_seq = Some(seq);
        }
        out.clear();
        out.extend_from_slice(body);
        if self.suite.encrypts() {
            let iv = self.iv(body[8..12].try_into().unwrap(), (u64::from(roc) << 16) | u64::from(seq));
            aes_cm(&self.keys.cipher, iv, &mut out[hdr..]);
        }
        true
    }
}

impl Suite {
    /// The same authentication without encryption, for UNENCRYPTED_SRTP.
    fn unencrypted(self) -> Suite {
        if self.tag_len() == 10 { Suite::NullSha1_80 } else { Suite::NullSha1_32 }
    }
}

/// One a=crypto line of the peer's SDP, as SIPp's parse_crypto_line()
/// reads it: what sscanf() got of "%d %24[^ ] inline:%64[^ |\r\n]".
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Line {
    /// 0 if none.
    pub tag: u32,
    pub suite: String,
    /// The inline: text, empty if none.
    pub key: String,
    /// UNENCRYPTED_SRTP among the session parameters after the key.
    pub unencrypted: bool,
}

impl Line {
    pub fn parse(line: &str) -> Line {
        let mut l = Line::default();
        let skip_ws = |s: &str| s.trim_start_matches(|c: char| c.is_ascii_whitespace()).to_string();
        let s = skip_ws(line);
        let sign = usize::from(s.starts_with(['+', '-']));
        let digits = s[sign..].bytes().take_while(u8::is_ascii_digit).count();
        let Ok(tag) = s[..sign + digits].parse::<i64>() else { return l };
        l.tag = tag as i32 as u32;
        let s = skip_ws(&s[sign + digits..]);
        let n = s.find(' ').unwrap_or(s.len());
        // A longer suite stops sscanf() before its key.
        let long = n > 24;
        let n = if long { (0..=24).rev().find(|&i| s.is_char_boundary(i)).unwrap_or(0) } else { n };
        l.suite = s[..n].to_string();
        if n == 0 || long {
            return l;
        }
        let Some(s) = skip_ws(&s[n..]).strip_prefix("inline:").map(str::to_string) else { return l };
        let n = s.find([' ', '|', '\r', '\n']).unwrap_or(s.len());
        let n = (0..=n.min(64)).rev().find(|&i| s.is_char_boundary(i)).unwrap_or(0);
        if n == 0 {
            return l;
        }
        l.key = s[..n].to_string();
        // The rest of the key-params (a lifetime, an MKI) is skipped.
        let rest = &s[n..];
        l.unencrypted = rest[rest.find([' ', '\r', '\n']).unwrap_or(rest.len())..].contains("UNENCRYPTED_SRTP");
        l
    }

    /// decode_srtp_key(): the master key and salt, a key of the suite's
    /// AES key size, else 128 bits; None with SIPp's warning otherwise.
    fn decode(&self, warnings: &mut Vec<String>) -> Option<Vec<u8>> {
        let key_len = Suite::from_name(&self.suite).map_or(16, Suite::key_len);
        // SIPp's base64Decode() stops at a character not of base64.
        let b64 = &self.key[..self.key.find(|c: char| !(c.is_ascii_alphanumeric() || c == '+' || c == '/')).unwrap_or(self.key.len())];
        let key = unbase64(b64).filter(|k| k.len() == key_len + SALT_LEN);
        if key.is_none() {
            warnings.push(format!("SRTP: ignoring the {} key {}: not a {key_len}-byte key and a 14-byte salt", self.suite, self.key));
        }
        key
    }
}

/// The primary and secondary a=crypto lines, the first two of the first
/// active m=<kind> section, as SIPp's extract_srtp_remote_info() reads
/// them; a missing one is all empty.
pub fn sdp_crypto(raw: &str, kind: &str) -> [Line; 2] {
    let mut out: [Line; 2] = Default::default();
    let Some(body) = crate::sip::body_start(raw).map(|e| &raw[e + 4..]) else { return out };
    // Most SDPs have none: one search, not a walk of their lines.
    if !body.contains("a=crypto:") {
        return out;
    }
    let (mut in_section, mut lines) = (false, 0);
    for line in body.lines() {
        if let Some(m) = line.strip_prefix("m=") {
            if in_section {
                break;
            }
            let mut f = m.split_whitespace();
            in_section = f.next() == Some(kind) && f.next().is_some_and(|p| p != "0");
        } else if let Some(c) = line.strip_prefix("a=crypto:").filter(|_| in_section && lines < 2) {
            out[lines] = Line::parse(c);
            lines += 1;
        }
    }
    out
}

/// What one of our two offered crypto lines holds.
#[derive(Debug, Clone)]
pub struct Slot {
    /// 0 if our last SDP had no line of this position.
    pub tag: u32,
    pub suite: Suite,
    /// The master key and salt.
    pub key: Vec<u8>,
    /// UNENCRYPTED_SRTP: authenticated, not encrypted.
    pub ue: bool,
    /// The suite keyword of the line in our last SDP, if any.
    pub offered: Option<Suite>,
}

impl Slot {
    /// The suite name an answer's line takes this one by: that of its
    /// keyword, else that of the cipher and hash in use, as SIPp.
    fn name(&self) -> &'static str {
        self.offered.unwrap_or(if self.ue { self.suite.unencrypted() } else { self.suite }).name()
    }
}

/// One of the two crypto attributes of JLSRTP's context for the peer's
/// SRTP: set from the peer's line of that position whose key it decodes;
/// without such a line, tag 0 (no SRTP) and no name, the rest as it was,
/// at first AES_CM_128_HMAC_SHA1_80 and a zero key.
#[derive(Debug, Clone, PartialEq)]
pub struct RxSlot {
    pub tag: u32,
    /// The cipher and hash in use.
    pub suite: Suite,
    /// The master key and salt.
    pub key: Vec<u8>,
    /// The suite name of the line.
    pub offered: String,
}

impl Default for RxSlot {
    fn default() -> RxSlot {
        RxSlot { tag: 0, suite: Suite::AesCm128Sha1_80, key: vec![0; 16 + SALT_LEN], offered: String::new() }
    }
}

impl RxSlot {
    const NONE: RxSlot = RxSlot { tag: 0, suite: Suite::AesCm128Sha1_80, key: Vec::new(), offered: String::new() };

    fn name(&self) -> &str {
        if self.offered.is_empty() { self.suite.name() } else { &self.offered }
    }
}

/// find_crypto_line(): of lines (tag, name), the one of the tag and the
/// suite, else the first of the suite; a line of tag 0 is none.
fn find_line<'a>(lines: impl Iterator<Item = (u32, &'a str)> + Clone, tag: u32, suite: &str) -> Option<usize> {
    let of_suite = |&(_, (t, name)): &(usize, (u32, &str))| t != 0 && name == suite;
    let mut all = lines.enumerate().filter(of_suite);
    all.clone().find(|&(_, (t, _))| t == tag).or_else(|| all.next()).map(|(i, _)| i)
}

/// One media type's SRTP, as SIPp's JLSRTP contexts: our two lines and
/// the peer's, the first of each in use, which a swap exchanges.
#[derive(Debug, Default)]
pub struct MediaCrypto {
    pub tx: [Option<Slot>; 2],
    pub rx: [RxSlot; 2],
}

impl MediaCrypto {
    /// Nothing of it: what a call without SRTP reads, with no key made.
    pub const NONE: MediaCrypto = MediaCrypto { tx: [None, None], rx: [RxSlot::NONE, RxSlot::NONE] };

    pub fn slot(&mut self, n: usize) -> &mut Slot {
        self.tx[n].get_or_insert(Slot { tag: 0, suite: Suite::AesCm128Sha1_80, key: vec![0; 16 + SALT_LEN], ue: false, offered: None })
    }

    pub fn tx_context(&self) -> Option<Context> {
        let s = self.tx[0].as_ref().filter(|s| s.tag != 0)?;
        Context::new(if s.ue { s.suite.unencrypted() } else { s.suite }, &s.key)
    }

    pub fn rx_context(&self) -> Option<Context> {
        let r = self.rx.first().filter(|r| r.tag != 0)?;
        Context::new(r.suite, &r.key)
    }

    /// The lines of an SDP of ours, the only ones an answer can take: for
    /// each position, whether it had a tag and the suite of its keyword.
    pub fn sent(&mut self, lines: [(bool, Option<Suite>); 2]) {
        for (n, (slot, (tag, suite))) in self.tx.iter_mut().zip(lines).enumerate() {
            if let Some(s) = slot.as_mut() {
                s.tag = if tag { n as u32 + 1 } else { 0 };
                s.offered = suite;
            }
        }
    }

    /// The peer's crypto lines of `kind`, if its primary one has a tag. An
    /// answer's line takes the line of ours of its tag and suite, else the
    /// first of its suite; none, with a warning, and we send plain RTP. A
    /// line whose key decodes sets its slot, with the suite's cipher and
    /// hash, the NULL cipher with UNENCRYPTED_SRTP, as far as SIPp knows
    /// them; any other line empties it.
    pub fn received(&mut self, lines: &[Line; 2], answer: bool, kind: &str, warnings: &mut Vec<String>) {
        if lines[0].tag == 0 {
            return;
        }
        if answer {
            let ours = self.tx.iter().map(|s| s.as_ref().map_or((0, ""), |s| (s.tag, s.name())));
            match find_line(ours, lines[0].tag, &lines[0].suite) {
                Some(1) => self.tx.swap(0, 1),
                Some(_) => {}
                None => {
                    warnings.push(format!(
                        "SRTP: the {kind} answer a=crypto:{} {} is none of the offered lines, sending plain RTP",
                        lines[0].tag as i32, lines[0].suite
                    ));
                    for s in self.tx.iter_mut().flatten() {
                        s.tag = 0;
                    }
                }
            }
        }
        for (slot, line) in self.rx.iter_mut().zip(lines) {
            let Some(key) = Some(line).filter(|l| !l.key.is_empty()).and_then(|l| l.decode(warnings)) else {
                slot.tag = 0;
                slot.offered.clear();
                continue;
            };
            slot.tag = line.tag;
            slot.offered = line.suite.clone();
            slot.key = key;
            match Suite::from_name(&line.suite) {
                // A NULL line is unencrypted with or without UNENCRYPTED_SRTP.
                Some(s) if !line.unencrypted || !s.encrypts() => slot.suite = s,
                Some(s) => slot.suite = s.unencrypted(),
                None => {}
            }
        }
    }

    /// Our answer's primary suite: the peer's secondary line takes the
    /// place of its primary one if only it is of this suite, which it
    /// tells; a warning if neither is.
    pub fn answer_with(&mut self, suite: Suite, warnings: &mut Vec<String>) -> bool {
        let line = find_line(self.rx.iter().map(|r| (r.tag, r.name())), 0, suite.name());
        match line {
            Some(1) => self.rx.swap(0, 1),
            Some(_) => {}
            None => warnings.push(format!("SRTP: answering {}, the suite of no a=crypto line taken from the offer", suite.name())),
        }
        line == Some(1)
    }
}

/// Random bytes for a new master key of `key_len` bytes and its salt.
pub fn new_master(key_len: usize) -> Vec<u8> {
    use std::io::Read;
    let mut key = vec![0u8; key_len + SALT_LEN];
    if std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut key)).is_err() {
        // ponytail: no /dev/urandom (not Linux): a time-seeded key, fine for a test tool.
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
        for (i, b) in key.iter_mut().enumerate() {
            *b = (t >> (i % 16 * 8)) as u8 ^ i as u8;
        }
    }
    key
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64, as the inline: key parameter of an SDP crypto line.
pub fn base64(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for i in 0..4 {
            out.push(if i <= chunk.len() { B64[(n >> (18 - 6 * i)) as usize & 63] as char } else { '=' });
        }
    }
    out
}

pub fn unbase64(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in text.bytes().take_while(|&c| c != b'=') {
        acc = acc << 6 | B64.iter().position(|&b| b == c)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// The peer's slots after an offer of `raw` on a new call, and the
    /// warnings about its keys.
    fn remote(raw: &str, kind: &str) -> ([RxSlot; 2], Vec<String>) {
        let (mut m, mut warnings) = (MediaCrypto::default(), Vec::new());
        m.received(&sdp_crypto(raw, kind), false, kind, &mut warnings);
        (m.rx, warnings)
    }

    fn rx(tag: u32, suite: Suite, key: &[u8], offered: &str) -> RxSlot {
        RxSlot { tag, suite, key: key.to_vec(), offered: offered.into() }
    }

    #[test]
    fn sdp_crypto_lines() {
        let key = base64(&[5u8; 30]);
        let msg = format!("SIP/2.0 200 OK\r\n\r\nv=0\r\nm=audio 6000 RTP/AVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{key}\r\na=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:{key} UNENCRYPTED_SRTP\r\na=crypto:3 NULL_HMAC_SHA1_80 inline:{key}\r\nm=video 6002 RTP/AVP 99\r\na=crypto:1 NULL_HMAC_SHA1_32 inline:{key}\r\n");
        let (audio, _) = remote(&msg, "audio");
        assert_eq!(audio, [rx(1, Suite::AesCm128Sha1_80, &[5; 30], "AES_CM_128_HMAC_SHA1_80"), rx(2, Suite::NullSha1_32, &[5; 30], "AES_CM_128_HMAC_SHA1_32")]);
        let (video, _) = remote(&msg, "video");
        assert_eq!(video, [rx(1, Suite::NullSha1_32, &[5; 30], "NULL_HMAC_SHA1_32"), RxSlot::default()]);
        assert_eq!(remote(&msg.replace("m=video 6002", "m=video 0"), "video").0, [RxSlot::default(), RxSlot::default()]);
    }

    /// What sscanf("%d %24[^ ] inline:%64[^ |\r\n]") gets of a line.
    #[test]
    fn crypto_lines_as_sscanf_reads_them() {
        let line = |tag, suite: &str, key: &str, unencrypted| Line { tag, suite: suite.into(), key: key.into(), unencrypted };
        assert_eq!(Line::parse("1 AES_CM_128_HMAC_SHA1_80 inline:abc|2^20 UNENCRYPTED_SRTP"), line(1, "AES_CM_128_HMAC_SHA1_80", "abc", true));
        assert_eq!(Line::parse(" 2  NULL_HMAC_SHA1_32   inline:xyz"), line(2, "NULL_HMAC_SHA1_32", "xyz", false));
        assert_eq!(Line::parse("x AES_CM_128_HMAC_SHA1_80 inline:abc"), Line::default());
        assert_eq!(Line::parse("-1 AES_CM_128_HMAC_SHA1_80 inline:abc").tag, u32::MAX);
        // No key: the tag and suite all the same, and no UNENCRYPTED_SRTP.
        assert_eq!(Line::parse("3 AES_CM_128_HMAC_SHA1_80 key:abc UNENCRYPTED_SRTP"), line(3, "AES_CM_128_HMAC_SHA1_80", "", false));
        assert_eq!(Line::parse("3 AES_CM_128_HMAC_SHA1_80 inline:|x"), line(3, "AES_CM_128_HMAC_SHA1_80", "", false));
        // A suite of more than 24 characters stops before its key.
        assert_eq!(Line::parse("4 AES_CM_128_HMAC_SHA1_80_XY inline:abc"), line(4, "AES_CM_128_HMAC_SHA1_80_", "", false));
        // Up to 64 characters of key, the rest skipped.
        let long = "A".repeat(70);
        assert_eq!(Line::parse(&format!("5 AES_256_CM_HMAC_SHA1_80 inline:{long}UNENCRYPTED_SRTP")).key, "A".repeat(64));
        assert!(!Line::parse(&format!("5 AES_256_CM_HMAC_SHA1_80 inline:{long}UNENCRYPTED_SRTP")).unencrypted);
    }

    #[test]
    fn base64_round_trip() {
        assert_eq!(base64(b"Man"), "TWFu");
        assert_eq!(base64(b"Ma"), "TWE=");
        assert_eq!(base64(b"M"), "TQ==");
        let key: Vec<u8> = (0..30).collect();
        assert_eq!(unbase64(&base64(&key)), Some(key));
        assert_eq!(unbase64("T!"), None);
    }

    #[test]
    fn rfc3711_b2_aes_cm_keystream() {
        let key = Aes::new(&hex("2B7E151628AED2A6ABF7158809CF4F3C")).unwrap();
        let mut ks = vec![0u8; 48];
        aes_cm(&key, hex("F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000").try_into().unwrap(), &mut ks);
        assert_eq!(ks, hex("E03EAD0935C95E80E166B16DD92B4EB4D23513162B02D0F72A43A2FE4A5F97AB41E95B3BB0A2E8DD477901E4FCA894C0"));
    }

    /// The keystream of RFC 6188 7.1 and 7.3: its first and last three
    /// blocks, of 65282 for packet index 0.
    fn rfc6188_keystream(key: &str, first: &str, last: &str) {
        let key = Aes::new(&hex(key)).unwrap();
        let mut ks = vec![0u8; 65282 * 16];
        aes_cm(&key, hex("F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000").try_into().unwrap(), &mut ks);
        assert_eq!(ks[..48], hex(first)[..]);
        assert_eq!(ks[ks.len() - 48..], hex(last)[..]);
    }

    #[test]
    fn rfc6188_7_1_aes_256_cm_keystream() {
        rfc6188_keystream(
            "57f82fe3613fd170a85ec93c40b1f0922ec4cb0dc025b58272147cc438944a98",
            "92bdd28a93c3f52511c677d08b5515a49da71b2378a854f67050756ded165bac63c4868b7096d88421b563b8c94c9a31",
            "cea518c90fd91ced9cbb18c078a547113dbc4814f4da5f00a08772b63c6a046d6eb246913062a16891433e97dd01a57f",
        );
    }

    #[test]
    fn rfc6188_7_3_aes_192_cm_keystream() {
        rfc6188_keystream(
            "eab234764e517b2d3d160d587d8c86219740f65f99b6bcf7",
            "35096cba4610028dc1b57503804ce37c5de986291dcce161d5165ec4568f5c9a474a40c77894bc17180202272a4c264d",
            "d108d1a31a00bad6367ec23eb044b415c8f57129fdeb970b59f917b257662d4ca5dab625811034e8cebdfeb6dc158dd3",
        );
    }

    /// The session keys of a master key and salt: the encryption key
    /// checked by the block it encrypts.
    fn kdf(key: &str, salt: &str, enc: &str, session_salt: &str, auth: &str) {
        let k = derive(&[hex(key), hex(salt)].concat()).unwrap();
        let mut got = [0u8; 16].into();
        k.cipher.encrypt_block(&mut got);
        let mut want = [0u8; 16].into();
        Aes::new(&hex(enc)).unwrap().encrypt_block(&mut want);
        assert_eq!(got, want, "cipher key");
        assert_eq!(k.salt.to_vec(), hex(session_salt));
        let tag = |mac: Hmac<Sha1>| mac.chain_update(b"packet").finalize().into_bytes();
        assert_eq!(tag(k.mac), tag(<Hmac<Sha1> as Mac>::new_from_slice(&hex(auth)).unwrap()), "auth key");
    }

    #[test]
    fn rfc3711_b3_key_derivation() {
        kdf(
            "E1F97A0D3E018BE0D64FA32C06DE4139",
            "0EC675AD498AFEEBB6960B3AABE6",
            "C61E7A93744F39EE10734AFE3FF7A087",
            "30CBBC08863D8C85D49DB34A9AE1",
            "CEBE321F6FF7716B6FD4AB49AF256A156D38BAA4",
        );
    }

    #[test]
    fn rfc6188_7_2_aes_256_key_derivation() {
        kdf(
            "f0f04914b513f2763a1b1fa130f10e2998f6f6e43e4309d1e622a0e332b9f1b6",
            "3b04803de51ee7c96423ab5b78d2",
            "5ba1064e30ec51613cad926c5a28ef731ec7fb397f70a960653caf06554cd8c4",
            "fa31791685ca444a9e07c6c64e93",
            "fd9c32d39ed5fbb5a9dc96b30818454d1313dc05",
        );
    }

    #[test]
    fn rfc6188_7_4_aes_192_key_derivation() {
        kdf(
            "73edc66c4fa15776fb57f9505c17136550ffda71f3e8e5f1",
            "c8522f3acd4ce86d5add78edbb11",
            "31874736a8f1143870c26e4857d8a5b2c4a354407faadabb",
            "2372b82d639b6d8503a47adc0a6c",
            "355b10973cd95b9eacf4061c7e1a7151e7cfbfcb",
        );
    }

    #[test]
    fn protect_unprotect_round_trip_and_tamper() {
        let master = [7u8; 30];
        for suite in [Suite::AesCm128Sha1_80, Suite::AesCm128Sha1_32, Suite::NullSha1_80, Suite::NullSha1_32] {
            let (mut tx, mut rx) = (Context::new(suite, &master).unwrap(), Context::new(suite, &master).unwrap());
            for seq in [65534u16, 65535, 0, 1] {
                let mut rtp = vec![0x80, 0, 0, 0, 0, 0, 0, 1, 1, 2, 3, 4];
                rtp[2..4].copy_from_slice(&seq.to_be_bytes());
                rtp.extend_from_slice(b"payload bytes");
                let srtp = tx.protect(&rtp).unwrap();
                assert_eq!(srtp.len(), rtp.len() + suite.tag_len());
                assert_eq!(srtp[12..25] != rtp[12..], suite.encrypts(), "{suite:?}");
                let mut bad = srtp.clone();
                bad[14] ^= 1;
                assert_eq!(rx.unprotect(&bad), None);
                assert_eq!(rx.unprotect(&srtp).as_deref(), Some(&rtp[..]), "{suite:?} seq {seq}");
            }
        }
    }

    /// Each suite's new key on our a=crypto line, as the peer reads it,
    /// and a packet it protects that the peer authenticates and decrypts.
    #[test]
    fn suites_round_trip_through_the_sdp() {
        for (suite, inline_len, tag_len) in [
            (Suite::AesCm128Sha1_80, 40, 10),
            (Suite::AesCm128Sha1_32, 40, 4),
            (Suite::AesCm192Sha1_80, 52, 10),
            (Suite::AesCm192Sha1_32, 52, 4),
            (Suite::AesCm256Sha1_80, 64, 10),
            (Suite::AesCm256Sha1_32, 64, 4),
        ] {
            let master = new_master(suite.key_len());
            let inline = base64(&master);
            assert_eq!(inline.len(), inline_len, "{suite:?}");
            let msg = format!("SIP/2.0 200 OK\r\n\r\nv=0\r\nm=audio 6000 RTP/SAVP 0\r\na=crypto:1 {} inline:{inline}\r\n", suite.name());
            let (remote, warnings) = remote(&msg, "audio");
            assert_eq!((remote[0].tag, remote[0].suite, &remote[0].key, &warnings), (1, suite, &master, &vec![]), "{suite:?}");
            let (mut tx, mut rx) = (Context::new(suite, &master).unwrap(), Context::new(suite, &remote[0].key).unwrap());
            for seq in 1000u16..1003 {
                let mut rtp = vec![0x80, 0, 0, 0, 0, 0, 0, 1, 0x12, 0x34, 0x56, 0x78];
                rtp[2..4].copy_from_slice(&seq.to_be_bytes());
                rtp.extend((0..160).map(|i| (i + seq) as u8));
                let srtp = tx.protect(&rtp).unwrap();
                assert_eq!(srtp.len(), 12 + 160 + tag_len);
                assert_ne!(srtp[12..172], rtp[12..]);
                let mut bad = srtp.clone();
                bad[20] ^= 1;
                assert_eq!(rx.unprotect(&bad), None);
                assert_eq!(rx.unprotect(&srtp).as_deref(), Some(&rtp[..]), "{suite:?} seq {seq}");
            }
        }
    }

    /// SIPp's srtp_sdp.rfc6188_keys_are_read_whole: 64 and 52 base64
    /// characters, and a key before its lifetime and MKI.
    #[test]
    fn rfc6188_keys_are_read_whole() {
        let msg = "SIP/2.0 200 OK\r\n\r\nv=0\r\n\
                   m=audio 12346 RTP/SAVP 0\r\n\
                   a=crypto:1 AES_256_CM_HMAC_SHA1_80 inline:QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ==\r\n\
                   a=crypto:2 AES_192_CM_HMAC_SHA1_32 inline:QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI= UNENCRYPTED_SRTP\r\n\
                   m=video 12348 RTP/SAVP 99\r\n\
                   a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0ND|2^20|1:32\r\n";
        let (audio, _) = remote(msg, "audio");
        assert_eq!(audio, [rx(1, Suite::AesCm256Sha1_80, &[b'A'; 46], "AES_256_CM_HMAC_SHA1_80"), rx(2, Suite::NullSha1_32, &[b'B'; 38], "AES_192_CM_HMAC_SHA1_32")]);
        let (video, _) = remote(msg, "video");
        assert_eq!(video, [rx(1, Suite::AesCm128Sha1_80, &[b'C'; 30], "AES_CM_128_HMAC_SHA1_80"), RxSlot::default()]);
    }

    /// SIPp's srtp_sdp.unencrypted_srtp_after_a_lifetime_and_mki, with
    /// keys of 30 bytes, the others now ignored.
    #[test]
    fn unencrypted_srtp_after_a_lifetime_and_mki() {
        let msg = "SIP/2.0 200 OK\r\n\r\nv=0\r\n\
                   m=audio 12346 RTP/SAVP 0\r\n\
                   a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB|2^20|1:32 UNENCRYPTED_SRTP\r\n\
                   a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC KDR=1 UNENCRYPTED_SRTP\r\n\
                   m=video 12348 RTP/SAVP 99\r\n\
                   a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0ND UNENCRYPTED_SRTP\r\n\
                   a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:RERERERERERERERERERERERERERERERERERERERE|1:4\r\n";
        let (audio, _) = remote(msg, "audio");
        assert_eq!((audio[0].suite, audio[1].suite), (Suite::NullSha1_80, Suite::NullSha1_32));
        let (video, _) = remote(msg, "video");
        assert_eq!(video, [rx(1, Suite::NullSha1_80, &[b'C'; 30], "AES_CM_128_HMAC_SHA1_80"), rx(2, Suite::AesCm128Sha1_32, &[b'D'; 30], "AES_CM_128_HMAC_SHA1_32")]);
    }

    /// A key not of its suite's length is ignored, with SIPp's warning; the
    /// first two lines are the primary and secondary ones all the same.
    #[test]
    fn keys_not_of_the_suite_length_are_ignored() {
        let (k128, k256) = (base64(&[1u8; 30]), base64(&[2u8; 46]));
        let odd = base64(&[3u8; 47]);
        let msg = format!(
            "SIP/2.0 200 OK\r\n\r\nv=0\r\nm=audio 6000 RTP/SAVP 0\r\n\
             a=crypto:1 AES_256_CM_HMAC_SHA1_80 inline:{k128}\r\n\
             a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:{odd}\r\n\
             a=crypto:3 AES_CM_128_HMAC_SHA1_32 inline:{k128}\r\n\
             m=video 6002 RTP/SAVP 99\r\n\
             a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{k256}\r\n\
             a=crypto:2 AES_256_CM_HMAC_SHA1_32 inline:{k256}\r\n"
        );
        let (audio, mut warnings) = remote(&msg, "audio");
        assert_eq!(audio, [RxSlot::default(), RxSlot::default()]);
        let (video, w) = remote(&msg, "video");
        warnings.extend(w);
        assert_eq!(video, [RxSlot::default(), rx(2, Suite::AesCm256Sha1_32, &[2; 46], "AES_256_CM_HMAC_SHA1_32")]);
        assert_eq!(
            warnings,
            [
                format!("SRTP: ignoring the AES_256_CM_HMAC_SHA1_80 key {k128}: not a 32-byte key and a 14-byte salt"),
                format!("SRTP: ignoring the AES_CM_128_HMAC_SHA1_80 key {}: not a 16-byte key and a 14-byte salt", &odd[..64]),
                format!("SRTP: ignoring the AES_CM_128_HMAC_SHA1_80 key {k256}: not a 16-byte key and a 14-byte salt"),
            ]
        );
    }

    const SUITES: [Suite; 8] = [
        Suite::AesCm128Sha1_80,
        Suite::AesCm128Sha1_32,
        Suite::AesCm192Sha1_80,
        Suite::AesCm192Sha1_32,
        Suite::AesCm256Sha1_80,
        Suite::AesCm256Sha1_32,
        Suite::NullSha1_80,
        Suite::NullSha1_32,
    ];

    /// An SDP of two audio lines and two video ones, each (suite, key).
    fn offer(lines: [(&str, &[u8]); 2]) -> String {
        let a = |t: usize| format!("a=crypto:{} {} inline:{}\r\n", t + 1, lines[t].0, base64(lines[t].1));
        let (a, b) = (a(0), a(1));
        format!("INVITE sip:x SIP/2.0\r\n\r\nv=0\r\nm=audio 6000 RTP/SAVP 0\r\n{a}{b}m=video 6002 RTP/SAVP 99\r\n{a}{b}")
    }

    /// A key of another length than `suite`'s.
    fn bad_key(suite: Suite) -> Vec<u8> {
        vec![9; if suite.key_len() == 16 { 32 } else { 16 } + SALT_LEN]
    }

    /// A line ignored leaves its slot empty, which no answer takes: the
    /// answer of the good line's suite takes it, first or second, and one
    /// of the ignored line's suite (if another) takes none, with a warning;
    /// for audio and video, all suites both ways.
    #[test]
    fn an_ignored_line_leaves_its_slot_empty() {
        for kind in ["audio", "video"] {
            for good in SUITES {
                for bad in SUITES {
                    let key = new_master(good.key_len());
                    let badk = bad_key(bad);
                    for bad_first in [true, false] {
                        let lines = if bad_first { [(bad.name(), &badk[..]), (good.name(), &key[..])] } else { [(good.name(), &key[..]), (bad.name(), &badk[..])] };
                        let msg = offer(lines);
                        let mut m = MediaCrypto::default();
                        let mut warnings = Vec::new();
                        m.received(&sdp_crypto(&msg, kind), false, kind, &mut warnings);
                        assert_eq!(warnings.len(), 1);
                        let good_slot = rx(if bad_first { 2 } else { 1 }, good, &key, good.name());
                        let slots = if bad_first { [RxSlot::default(), good_slot.clone()] } else { [good_slot.clone(), RxSlot::default()] };
                        assert_eq!(m.rx, slots);

                        let mut answered = MediaCrypto { rx: m.rx.clone(), ..Default::default() };
                        let mut warnings = Vec::new();
                        answered.answer_with(bad, &mut warnings);
                        assert_eq!((warnings.is_empty(), answered.rx[0].tag != 0), (bad == good, bad == good || !bad_first), "{kind} {good:?} {bad:?} {bad_first}");

                        m.answer_with(good, &mut warnings);
                        assert_eq!(m.rx[0], good_slot, "{kind} {good:?} {bad:?} {bad_first}");
                        let mut tx = Context::new(good, &key).unwrap();
                        let rtp = [&[0x80, 0, 0, 1, 0, 0, 0, 1, 1, 2, 3, 4][..], &[0x55; 160]].concat();
                        assert_eq!(m.rx_context().unwrap().unprotect(&tx.protect(&rtp).unwrap()), Some(rtp));
                    }
                }
            }
        }
    }

    /// Our lines of an SDP of ours: `lines` of (tag, suite keyword).
    fn ours(lines: &[(u32, Suite)]) -> MediaCrypto {
        let mut m = MediaCrypto::default();
        let mut sent = [(false, None); 2];
        for (i, &(tag, suite)) in lines.iter().enumerate() {
            *m.slot(i) = Slot { tag, suite, key: vec![i as u8 + 1; suite.key_len() + SALT_LEN], ue: false, offered: None };
            sent[i] = (true, Some(suite));
        }
        m.sent(sent);
        m
    }

    fn answer(tag: &str, suite: &str, key: &[u8]) -> String {
        format!("SIP/2.0 200 OK\r\n\r\nv=0\r\nm=audio 6000 RTP/SAVP 0\r\na=crypto:{tag} {suite} inline:{}\r\n", base64(key))
    }

    /// The offerer sends with its line of the answer's tag and suite, else
    /// its first line of the suite, whole names only; with none, it warns
    /// and sends plain RTP. The answer's key being ignored changes nothing.
    #[test]
    fn the_offerer_takes_the_line_of_the_answer() {
        let (s80, s32) = (Suite::AesCm128Sha1_80, Suite::AesCm128Sha1_32);
        let none = Some(0);
        for (lines, tag, suite, took) in [
            (&[(1, s80), (2, s32)][..], "1", "AES_CM_128_HMAC_SHA1_80", Some(1)),
            (&[(1, s80), (2, s32)], "1", "AES_CM_128_HMAC_SHA1_32", Some(2)),
            (&[(1, s80), (2, s32)], "2", "AES_CM_128_HMAC_SHA1_32", Some(2)),
            (&[(1, s80), (2, s32)], "2", "AES_CM_128_HMAC_SHA1_80", Some(1)),
            (&[(1, s80), (2, s80)], "2", "AES_CM_128_HMAC_SHA1_80", Some(2)),
            (&[(1, s80), (2, s80)], "1", "AES_CM_128_HMAC_SHA1_80", Some(1)),
            (&[(1, s80), (2, s80)], "3", "AES_CM_128_HMAC_SHA1_80", Some(1)),
            (&[(1, s80), (2, s32)], "1", "AES_CM_128_HMAC_SHA1_8", none),
            (&[(1, s80), (2, s32)], "1", "NULL_HMAC_SHA1_80", none),
            (&[(1, s80)], "1", "AES_CM_128_HMAC_SHA1_32", none),
            (&[(1, Suite::AesCm256Sha1_80), (2, Suite::AesCm192Sha1_32)], "1", "AES_192_CM_HMAC_SHA1_32", Some(2)),
        ] {
            for key in [vec![7; 30], vec![7; 46]] {
                let mut m = ours(lines);
                let mut warnings = Vec::new();
                m.received(&sdp_crypto(&answer(tag, suite, &key), "audio"), true, "audio", &mut warnings);
                let tx = m.tx[0].as_ref().map_or(0, |s| s.tag);
                assert_eq!(Some(tx), took, "{lines:?} {tag} {suite}");
                assert_eq!(m.tx_context().is_some(), tx != 0);
                let warned = warnings.iter().any(|w| w == &format!("SRTP: the audio answer a=crypto:{tag} {suite} is none of the offered lines, sending plain RTP"));
                assert_eq!(warned, took == none, "{lines:?} {tag} {suite} {warnings:?}");
                if tx != 0 {
                    // The line keeps its key and its name.
                    let s = m.tx[0].as_ref().unwrap();
                    assert_eq!((s.key[0], s.name()), (tx as u8, suite));
                }
            }
        }
    }

    /// Each SDP's lines replace the last one's: a line of ours not in our
    /// last SDP is not taken, nor the peer's ignored line in a new offer
    /// (its key from the last offer), and a UNENCRYPTED_SRTP keyword lasts
    /// until the next suite keyword.
    #[test]
    fn a_new_sdp_replaces_the_lines() {
        let (s80, s32) = (Suite::AesCm128Sha1_80, Suite::AesCm128Sha1_32);
        let mut m = ours(&[(1, s80), (2, s32)]);
        m.sent([(true, Some(s80)), (false, None)]);
        let mut warnings = Vec::new();
        m.received(&sdp_crypto(&answer("1", s32.name(), &[1; 30]), "audio"), true, "audio", &mut warnings);
        assert_eq!(warnings.len(), 1);
        assert!(m.tx_context().is_none());

        let (k1, k2) = ([1u8; 30], [2u8; 30]);
        let mut m = MediaCrypto::default();
        m.received(&sdp_crypto(&offer([(s80.name(), &k1), (s32.name(), &k2)]), "audio"), false, "audio", &mut Vec::new());
        m.received(&sdp_crypto(&offer([(s80.name(), &[9; 46]), (s32.name(), &k2)]), "audio"), false, "audio", &mut Vec::new());
        let mut warnings = Vec::new();
        m.answer_with(s80, &mut warnings);
        assert_eq!(warnings, ["SRTP: answering AES_CM_128_HMAC_SHA1_80, the suite of no a=crypto line taken from the offer"]);
        assert!(m.rx_context().is_none());

        let mut m = ours(&[(1, s80)]);
        m.slot(0).ue = true;
        assert_eq!(m.tx[0].as_ref().unwrap().name(), "AES_CM_128_HMAC_SHA1_80");
        m.sent([(true, None), (false, None)]);
        assert_eq!(m.tx[0].as_ref().unwrap().name(), "NULL_HMAC_SHA1_80");
    }

    /// A swap moves the whole line, its name too, on either side.
    #[test]
    fn a_swap_moves_the_names() {
        let (k1, k2) = ([1u8; 30], [2u8; 30]);
        let mut m = MediaCrypto::default();
        m.received(&sdp_crypto(&offer([("AES_CM_128_HMAC_SHA1_80", &k1), ("AES_CM_128_HMAC_SHA1_32", &k2)]), "audio"), false, "audio", &mut Vec::new());
        m.answer_with(Suite::AesCm128Sha1_32, &mut Vec::new());
        assert_eq!(m.rx, [rx(2, Suite::AesCm128Sha1_32, &k2, "AES_CM_128_HMAC_SHA1_32"), rx(1, Suite::AesCm128Sha1_80, &k1, "AES_CM_128_HMAC_SHA1_80")]);
        let mut m = ours(&[(1, Suite::AesCm128Sha1_80), (2, Suite::AesCm128Sha1_32)]);
        m.received(&sdp_crypto(&answer("1", "AES_CM_128_HMAC_SHA1_32", &k1), "audio"), true, "audio", &mut Vec::new());
        assert_eq!(m.tx.each_ref().map(|s| s.as_ref().map(|s| (s.tag, s.name()))), [Some((2, "AES_CM_128_HMAC_SHA1_32")), Some((1, "AES_CM_128_HMAC_SHA1_80"))]);
    }

    /// UNENCRYPTED_SRTP on a NULL line changes nothing, and a suite SIPp
    /// doesn't know leaves the cipher as it was, under its own name.
    #[test]
    fn null_lines_and_unknown_suites() {
        let msg = "INVITE sip:x SIP/2.0\r\n\r\nv=0\r\nm=audio 6000 RTP/SAVP 0\r\n\
                   a=crypto:1 NULL_HMAC_SHA1_32 inline:QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB UNENCRYPTED_SRTP\r\n\
                   a=crypto:2 F8_128_HMAC_SHA1_80 inline:QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC\r\n";
        let (audio, warnings) = remote(msg, "audio");
        assert!(warnings.is_empty());
        assert_eq!(audio, [rx(1, Suite::NullSha1_32, &[b'A'; 30], "NULL_HMAC_SHA1_32"), rx(2, Suite::AesCm128Sha1_80, &[b'B'; 30], "F8_128_HMAC_SHA1_80")]);
        let msg80 = msg.replace("NULL_HMAC_SHA1_32", "NULL_HMAC_SHA1_80");
        assert_eq!(remote(&msg80, "audio").0[0].suite, Suite::NullSha1_80);
        let mut m = MediaCrypto { rx: audio, ..Default::default() };
        m.answer_with(Suite::NullSha1_32, &mut Vec::new());
        assert_eq!(m.rx[0].tag, 1);
        let mut warnings = Vec::new();
        m.answer_with(Suite::AesCm128Sha1_80, &mut warnings);
        assert_eq!((m.rx[0].tag, warnings.len()), (1, 1));
    }

    /// No primary tag, no crypto lines at all: neither a key, a warning,
    /// nor a change of our line.
    #[test]
    fn no_primary_tag_no_crypto() {
        for first in ["a=crypto:0 AES_CM_128_HMAC_SHA1_80 inline:QUFB", "a=crypto:x AES_CM_128_HMAC_SHA1_80 inline:QUFB"] {
            let msg = format!("SIP/2.0 200 OK\r\n\r\nv=0\r\nm=audio 6000 RTP/SAVP 0\r\n{first}\r\na=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:QUFB\r\n");
            let mut m = ours(&[(1, Suite::AesCm128Sha1_32)]);
            let mut warnings = Vec::new();
            m.received(&sdp_crypto(&msg, "audio"), true, "audio", &mut warnings);
            assert!(warnings.is_empty());
            assert_eq!((m.rx.clone(), m.tx[0].as_ref().map(|s| s.tag)), ([RxSlot::default(), RxSlot::default()], Some(1)));
        }
    }
}

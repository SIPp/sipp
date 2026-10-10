//! Digest authentication (RFC 2617 / RFC 8760), formatted as SIPp's auth.cpp.

use md5::Md5;
use sha2::{Digest, Sha256, Sha512_256};

/// findAuthParameter(): where the value of `name` starts in `header`: the
/// name begins the header or follows a ',' or a space, outside a quoted
/// string, and has an '=' after it, spaces around it allowed. So "nonce"
/// isn't found in "cnonce", nor in realm="a, nonce=b".
fn find_param(header: &str, name: &str) -> Option<usize> {
    let b = header.as_bytes();
    let blanks = |i: usize| i + b[i..].iter().take_while(|c| matches!(c, b' ' | b'\t' | b'\r' | b'\n')).count();
    let mut quoted = false;
    let mut i = 0;
    while i < b.len() {
        if quoted && b[i] == b'\\' && i + 1 < b.len() {
            i += 2; // an escaped character
            continue;
        }
        if b[i] == b'"' {
            quoted = !quoted;
        } else if !quoted
            && (i == 0 || b[i - 1] == b',' || b[i - 1].is_ascii_whitespace())
            && b[i..].len() >= name.len()
            && b[i..i + name.len()].eq_ignore_ascii_case(name.as_bytes())
        {
            let eq = blanks(i + name.len());
            if b.get(eq) == Some(&b'=') {
                return Some(blanks(eq + 1));
            }
        }
        i += 1;
    }
    None
}

/// getAuthParameter(): `name=value` or `name="value"` in a challenge or
/// credentials header.
pub fn param(header: &str, name: &str) -> Option<String> {
    let value = &header[find_param(header, name)?..];
    Some(match value.strip_prefix('"') {
        Some(q) => q[..q.find('"').unwrap_or(q.len())].to_string(),
        None => value[..value.find([' ', ',', '"', '\r', '\n']).unwrap_or(value.len())].to_string(),
    })
}

/// nextChallenge(): the challenge after the one at `from`: past a comma,
/// outside quotes, a token followed by spaces, then by neither '=' nor
/// ',', is the next one's scheme. So the auth-int of a bare
/// qop=auth,auth-int is not.
fn next_challenge(auth: &str, from: usize) -> Option<usize> {
    let b = auth.as_bytes();
    let blank = |c: &u8| matches!(c, b' ' | b'\t' | b'\r' | b'\n');
    let mut quoted = false;
    let mut i = from;
    while i < b.len() {
        if quoted && b[i] == b'\\' && i + 1 < b.len() {
            i += 2;
            continue;
        }
        if b[i] == b'"' {
            quoted = !quoted;
        } else if b[i] == b',' && !quoted {
            let start = i + 1 + b[i + 1..].iter().take_while(|c| blank(c)).count();
            let end = start + b[start..].iter().take_while(|c| !blank(c) && !matches!(c, b'=' | b',')).count();
            let after = end + b[end..].iter().take_while(|c| blank(c)).count();
            if end > start && after > end && after < b.len() && !matches!(b[after], b'=' | b',') {
                return Some(start);
            }
        }
        i += 1;
    }
    None
}

/// selectAuthChallenge(): of the challenges in `auth` (the headers joined
/// by ", "), the first Digest one createAuthHeader() can answer; all of
/// them if none.
pub fn select_challenge(auth: &str) -> &str {
    let mut start = Some(auth.len() - auth.trim_start_matches([' ', '\t']).len());
    while let Some(s) = start {
        let next = next_challenge(auth, s);
        let challenge = &auth[s..next.unwrap_or(auth.len())];
        let b = challenge.as_bytes();
        if b.len() > 6 && b[..6].eq_ignore_ascii_case(b"Digest") && b[6].is_ascii_whitespace() {
            let algo = param(challenge, "algorithm").unwrap_or_default();
            // A -sess one has no cnonce to answer with without a qop
            if algo.is_empty()
                || algo.eq_ignore_ascii_case("AKAv1-MD5")
                || digest_algorithm(&algo).is_some_and(|(_, sess)| !sess || has_param(challenge, "qop"))
            {
                return challenge.trim_end_matches([' ', '\t', '\r', '\n', ',']);
            }
        }
        start = next;
    }
    auth
}

/// getAuthParameter()'s truth: a value that is not empty.
fn has_param(header: &str, name: &str) -> bool {
    param(header, name).is_some_and(|v| !v.is_empty())
}

#[derive(Clone, Copy, PartialEq)]
enum Hash {
    Md5,
    Sha256,
    Sha512_256,
}

/// digestAlgorithms[]: the Digest algorithms, but AKAv1-MD5, with their
/// hash. A -sess one's HA1 is of the nonce and cnonce too (RFC 7616
/// 3.4.2).
const DIGEST_ALGORITHMS: [(&str, Hash, bool); 6] = [
    ("MD5", Hash::Md5, false),
    ("MD5-sess", Hash::Md5, true),
    ("SHA-256", Hash::Sha256, false),
    ("SHA-256-sess", Hash::Sha256, true),
    ("SHA-512-256", Hash::Sha512_256, false),
    ("SHA-512-256-sess", Hash::Sha512_256, true),
];

/// digestAlgorithm(): the hash of the algorithm, and whether it is -sess.
fn digest_algorithm(name: &str) -> Option<(Hash, bool)> {
    DIGEST_ALGORITHMS.iter().find(|(n, ..)| n.eq_ignore_ascii_case(name)).map(|&(_, h, sess)| (h, sess))
}

#[derive(Clone, Copy, PartialEq)]
enum Algo {
    /// Its hash, and whether it is -sess.
    Digest(Hash, bool),
    /// RFC 3310: MD5 with the AKA RES as the password.
    AkaMd5,
}

/// The algorithm of the header, MD5 if none, and its name as it has it.
fn algo_name(header: &str) -> String {
    param(header, "algorithm").filter(|a| !a.is_empty()).unwrap_or_else(|| "MD5".into())
}

fn algo(header: &str) -> Result<(Algo, String), String> {
    let name = algo_name(header);
    if name.eq_ignore_ascii_case("AKAv1-MD5") {
        return Ok((Algo::AkaMd5, name));
    }
    match digest_algorithm(&name) {
        Some((h, sess)) => Ok((Algo::Digest(h, sess), name)),
        None => Err(format!(
            "createAuthHeader: authentication must use MD5, MD5-sess, SHA-256, SHA-256-sess, SHA-512-256, SHA-512-256-sess or AKAv1-MD5, not '{name}'"
        )),
    }
}

fn hex(algo: Algo, data: &[u8]) -> String {
    let bytes: Vec<u8> = match algo {
        Algo::Digest(Hash::Md5, _) | Algo::AkaMd5 => Md5::digest(data).to_vec(),
        Algo::Digest(Hash::Sha256, _) => Sha256::digest(data).to_vec(),
        Algo::Digest(Hash::Sha512_256, _) => Sha512_256::digest(data).to_vec(),
    };
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// [authentication]'s aka_K and aka_OP: 16 bytes each. Its aka_AMF is
/// ignored: the MAC is over the AMF of AUTN, as a USIM checks it.
#[derive(Debug, Clone)]
pub struct Aka {
    k: [u8; 16],
    op: [u8; 16],
}

impl Aka {
    pub fn from_strings(k: Option<&str>, op: Option<&str>) -> Option<Aka> {
        /// getAKAKey(): the bytes of the text, or those its hex digits
        /// after "0x" give, zero past their end.
        fn bytes<const N: usize>(s: Option<&str>) -> [u8; N] {
            let s = s.unwrap_or("");
            let b: Vec<u8> = match s.strip_prefix("0x") {
                Some(hex) => {
                    let digits: Vec<u8> = hex.bytes().take_while(u8::is_ascii_hexdigit).collect();
                    digits.chunks(2).map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap()).collect()
                }
                None => crate::raw::bytes(s).into_owned(),
            };
            std::array::from_fn(|i| b.get(i).copied().unwrap_or(0))
        }
        Some(Aka { k: bytes(Some(k?)), op: bytes(op) })
    }
}

/// createAuthHeaderAKAv1MD5(): the RES the nonce's RAND gives, once its
/// AUTN proves the network knows K.
fn aka_res(aka: &Aka, nonce: &str) -> Result<[u8; 8], String> {
    let n = crate::srtp::unbase64(nonce).unwrap_or_default();
    if n.len() < 32 {
        return Err(format!("createAuthHeaderAKAv1MD5 : Nonce is too short {} < 32 expected\n", n.len()));
    }
    let rand: [u8; 16] = n[..16].try_into().unwrap();
    let v = crate::milenage::f2345(&aka.k, &rand, &aka.op);
    let sqn: [u8; 6] = std::array::from_fn(|i| n[16 + i] ^ v.ak[i]);
    // AUTN: SQN^AK, AMF, MAC (3GPP TS 33.102 6.3.3).
    let amf: [u8; 2] = n[22..24].try_into().unwrap();
    if crate::milenage::f1(&aka.k, &rand, &sqn, &amf, &aka.op) != n[24..32] {
        return Err("createAuthHeaderAKAv1MD5 : MAC != expectedMAC -> Server might not know the secret (man-in-the-middle attack?)\n".into());
    }
    Ok(v.res)
}

/// createAuthResponse(): the response hash.
#[allow(clippy::too_many_arguments)]
fn response(a: Algo, user: &str, password: &[u8], method: &str, uri: &str, qop: &str, body: &str, realm: &str, nonce: &str, cnonce: &str, nc: &str) -> String {
    // Over the bytes, as SIPp hashes them (raw).
    let h = |s: String| hex(a, &crate::raw::bytes(&s));
    let mut ha1 = hex(a, &[&crate::raw::bytes(&format!("{user}:{realm}:")), password].concat());
    if let Algo::Digest(_, true) = a {
        ha1 = h(format!("{ha1}:{nonce}:{cnonce}"));
    }
    let auth_int = qop.to_ascii_lowercase().contains("auth-int");
    let ha2 = if auth_int {
        h(format!("{method}:{uri}:{}", hex(a, &crate::raw::bytes(body))))
    } else {
        h(format!("{method}:{uri}"))
    };
    if cnonce.is_empty() {
        h(format!("{ha1}:{nonce}:{ha2}"))
    } else {
        h(format!("{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}"))
    }
}

/// createAuthHeader(): the credentials for a challenge, without the header name.
#[allow(clippy::too_many_arguments)]
pub fn credentials(user: &str, password: &str, method: &str, uri: &str, body: &str, challenge: &str, nonce_count: u32, cnonce: &str, aka: Option<&Aka>) -> Result<String, String> {
    if !challenge.to_ascii_lowercase().contains("digest") {
        return Err("createAuthHeader: authentication must be digest".into());
    }
    let (a, algo_name) = algo(challenge)?;
    // Sloppy qop recognition, as SIPp: "auth,auth-int" means auth-int.
    let qop = param(challenge, "qop").filter(|q| !q.is_empty()).map(|q| {
        let q = q.to_ascii_lowercase();
        if q.contains("auth-int") { "auth-int".to_string() } else if q.contains("auth") { "auth".to_string() } else { q }
    });
    if let (Algo::Digest(_, true), None) = (a, &qop) {
        return Err(format!("createAuthHeader: {algo_name} needs a qop in the challenge, for a cnonce"));
    }
    let realm = param(challenge, "realm").ok_or_else(|| format!("createAuthHeader: couldn't parse realm in '{challenge}'"))?;
    let nonce = param(challenge, "nonce").ok_or("createAuthHeader: couldn't parse nonce")?;
    let mut out = format!("Digest username=\"{user}\",realm=\"{realm}\"");
    let (cnonce, nc) = match &qop {
        Some(q) => {
            let nc = format!("{nonce_count:08x}");
            out += &format!(",cnonce=\"{cnonce}\",nc={nc},qop={q}");
            (cnonce.to_string(), nc)
        }
        None => (String::new(), String::new()),
    };
    out += &format!(",uri=\"{uri}\"");
    let res;
    let password = match a {
        Algo::AkaMd5 => {
            let aka = aka.ok_or("createAuthHeader: AKAv1-MD5 authentication requires a key")?;
            res = aka_res(aka, &nonce)?;
            &res[..]
        }
        _ => &crate::raw::bytes(password),
    };
    let resp = response(a, user, password, method, uri, qop.as_deref().unwrap_or(""), body, &realm, &nonce, &cnonce, &nc);
    out += &format!(",nonce=\"{nonce}\",response=\"{resp}\",algorithm={algo_name}");
    if let Some(opaque) = param(challenge, "opaque") {
        out += &format!(",opaque=\"{opaque}\"");
    }
    Ok(out)
}

/// verifyAuthHeader(): does `auth` hold the right response for this
/// user? Err is the warning that it can't be checked.
pub fn verify(user: &str, password: &str, method: &str, auth: &str, body: &str) -> Result<bool, String> {
    if !auth.to_ascii_lowercase().contains("digest") {
        return Err(format!("verifyAuthHeader: authentication must be digest is {auth}"));
    }
    let name = algo_name(auth);
    let Some((h, sess)) = digest_algorithm(&name) else {
        return Err(format!(
            "verifyAuthHeader: authentication must use MD5, MD5-sess, SHA-256, SHA-256-sess, SHA-512-256 or SHA-512-256-sess, value is '{name}'"
        ));
    };
    let p = |n: &str| param(auth, n).unwrap_or_default();
    if sess && p("cnonce").is_empty() {
        return Ok(false); // no HA1 without a cnonce
    }
    let expected = response(Algo::Digest(h, sess), user, &crate::raw::bytes(password), method, &p("uri"), &p("qop"), body, &p("realm"), &p("nonce"), &p("cnonce"), &p("nc"));
    Ok(expected == p("response"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_skip_lookalikes() {
        let h = r#"Digest realm="sipp.test", cnonce="c1", nonce="n1", qop="auth,auth-int", algorithm=MD5"#;
        assert_eq!(param(h, "nonce").as_deref(), Some("n1"));
        assert_eq!(param(h, "qop").as_deref(), Some("auth,auth-int"));
        assert_eq!(param(h, "algorithm").as_deref(), Some("MD5"));
        assert_eq!(param(h, "opaque"), None);
    }

    #[test]
    fn params_around_spaces_outside_quotes() {
        // C 73886b2
        assert_eq!(param("Digest nonce=abc", "nonce").as_deref(), Some("abc"));
        assert_eq!(param(r#"Digest realm="r", algorithm = SHA-256"#, "algorithm").as_deref(), Some("SHA-256"));
        assert_eq!(param(r#"Digest realm= "a b""#, "realm").as_deref(), Some("a b"));
        assert_eq!(param(r#"Digest cnonce="x", nonce="y""#, "nonce").as_deref(), Some("y"));
        assert_eq!(param(r#"Digest realm="a, algorithm=SHA-256", algorithm=MD5"#, "algorithm").as_deref(), Some("MD5"));
        assert_eq!(param(r#"Digest realm="a\", nonce=bad", nonce=good"#, "nonce").as_deref(), Some("good"));
        assert_eq!(param(r#"Digest realm="opaque=x""#, "opaque"), None);
    }

    #[test]
    fn first_supported_challenge() {
        // C 98bd14a
        let cases = [
            (r#"Digest realm="a", nonce="1", algorithm=SHA-384, Digest realm="b", nonce="2", algorithm=MD5"#, r#"Digest realm="b", nonce="2", algorithm=MD5"#),
            (r#"Digest realm="a", nonce="1", qop="auth,auth-int", Digest realm="b", nonce="2", algorithm=SHA-256"#, r#"Digest realm="a", nonce="1", qop="auth,auth-int""#),
            (r#"Basic realm="x", Digest realm="a, Digest b", algorithm=AKAv2-MD5, Digest realm = "c",nonce="3""#, r#"Digest realm = "c",nonce="3""#),
            (r#"Digest realm="r", qop=auth,auth-int, nonce="n1", algorithm=MD5"#, r#"Digest realm="r", qop=auth,auth-int, nonce="n1", algorithm=MD5"#),
            (r#"Digest realm="a", algorithm=SHA-384, Digest realm="b", qop=auth, auth-int, nonce="2""#, r#"Digest realm="b", qop=auth, auth-int, nonce="2""#),
            (r#"Digest realm="a", algorithm = SHA-384, Digest realm="b", algorithm = MD5"#, r#"Digest realm="b", algorithm = MD5"#),
            // C 1d8cf95: those of RFC 7616 too, but a -sess one without a qop
            (
                r#"Digest realm="a", nonce="1", algorithm=SHA-384, Digest realm="b", nonce="2", qop="auth", algorithm=SHA-512-256-sess, Digest realm="c", nonce="3", algorithm=MD5"#,
                r#"Digest realm="b", nonce="2", qop="auth", algorithm=SHA-512-256-sess"#,
            ),
            (r#"Digest realm="a", qop="auth", algorithm=md5-sess, Digest realm="b""#, r#"Digest realm="a", qop="auth", algorithm=md5-sess"#),
            (r#"Digest realm="a", nonce="1", algorithm=MD5-sess, Digest realm="b", nonce="2", algorithm=MD5"#, r#"Digest realm="b", nonce="2", algorithm=MD5"#),
            (r#"Digest realm="a", algorithm=SHA-384, Digest realm="b", algorithm=AKAv2-MD5"#, r#"Digest realm="a", algorithm=SHA-384, Digest realm="b", algorithm=AKAv2-MD5"#),
        ];
        for (auth, selected) in cases {
            assert_eq!(select_challenge(auth), selected);
        }
    }

    #[test]
    fn sess_algorithms() {
        // C 1d8cf95
        for algo in ["MD5-sess", "SHA-256-sess", "SHA-512-256", "sha-512-256-SESS"] {
            for qop in ["auth", "auth-int", "auth,auth-int"] {
                let challenge = format!(r#"Digest realm="r", nonce="n", qop="{qop}", algorithm={algo}"#);
                let creds = credentials("testuser", "secret", "INVITE", "sip:bob@example.com", "v=0\r\n", &challenge, 1, "c1", None).unwrap();
                // The algorithm as the challenge has it
                assert!(creds.contains(&format!(",algorithm={algo}")), "{creds}");
                assert!(verify("testuser", "secret", "INVITE", &creds, "v=0\r\n").unwrap(), "{creds}");
                // auth-int covers the body
                assert_eq!(verify("testuser", "secret", "INVITE", &creds, "v=1\r\n").unwrap(), qop == "auth", "{creds}");
                assert!(!verify("testuser", "Secret", "INVITE", &creds, "v=0\r\n").unwrap(), "{creds}");
                // Not the response of the algorithm without -sess
                if let Some(at) = creds.to_ascii_lowercase().find("-sess") {
                    let other = format!("{}{}", &creds[..at], &creds[at + 5..]);
                    assert!(!verify("testuser", "secret", "INVITE", &other, "v=0\r\n").unwrap(), "{other}");
                }
            }
        }

        // A -sess one has no cnonce without a qop
        let err = credentials("testuser", "secret", "REGISTER", "sip:example.com", "", r#"Digest realm="r", nonce="n", algorithm=MD5-sess"#, 1, "c1", None).unwrap_err();
        assert_eq!(err, "createAuthHeader: MD5-sess needs a qop in the challenge, for a cnonce");
        let resp = response(Algo::Digest(Hash::Md5, true), "testuser", b"secret", "REGISTER", "sip:x", "", "", "r", "n", "", "");
        let auth = format!(r#"Digest username="testuser",realm="r",uri="sip:x",nonce="n",response="{resp}",algorithm=MD5-sess"#);
        assert!(!verify("testuser", "secret", "REGISTER", &auth, "").unwrap());
        // SHA-512-256 without a qop, as RFC 2069
        let creds = credentials("testuser", "secret", "REGISTER", "sip:example.com", "", r#"Digest realm="r", nonce="n", algorithm=SHA-512-256"#, 1, "c1", None).unwrap();
        assert!(!creds.contains("cnonce"), "{creds}");
        assert!(verify("testuser", "secret", "REGISTER", &creds, "").unwrap(), "{creds}");

        // Still none of another algorithm
        let err = credentials("testuser", "secret", "REGISTER", "sip:example.com", "", r#"Digest realm="r", nonce="n", algorithm=SHA-384"#, 1, "c1", None).unwrap_err();
        assert_eq!(err, "createAuthHeader: authentication must use MD5, MD5-sess, SHA-256, SHA-256-sess, SHA-512-256, SHA-512-256-sess or AKAv1-MD5, not 'SHA-384'");
        assert_eq!(
            verify("u", "p", "REGISTER", r#"Digest realm="r", nonce="n", response="x", algorithm=SHA-384"#, ""),
            Err("verifyAuthHeader: authentication must use MD5, MD5-sess, SHA-256, SHA-256-sess, SHA-512-256 or SHA-512-256-sess, value is 'SHA-384'".into())
        );
        assert_eq!(verify("u", "p", "REGISTER", "", ""), Err("verifyAuthHeader: authentication must be digest is ".into()));
    }

    #[test]
    fn aka_hex_keys() {
        // C 3e2a544: 3GPP TS 35.208 test set 1, whose K has 0x0A and 0x5B
        // bytes: the challenge has its RAND and AUTN, the response its RES
        // (C's test has "1efe54bb...", as its createAuthHeader() prefixes
        // the uri with "sip:").
        let aka = Aka::from_strings(Some("0x465B5CE8B199B49FAA5F0A2EE238A6BC"), Some("0xCDC202D5123E20F62B6D676AC72CB318"));
        for header in [
            r#"Digest realm="r", nonce="I1U8vpY3qJ0hiuZNrke/NVXzKLQ1d7m5Sp/6w1Tfr7M=", algorithm=AKAv1-MD5"#,
            r#"Digest realm="r", nonce = "I1U8vpY3qJ0hiuZNrke/NVXzKLQ1d7m5Sp/6w1Tfr7M=", algorithm=AKAv1-MD5"#,
        ] {
            let creds = credentials("alice", "", "REGISTER", "sip:example.com", "", header, 1, "", aka.as_ref()).unwrap();
            assert!(creds.contains(",response=\"c967d9c99f26c4da203ee73f572b5364\","), "{creds}");
        }
    }

    #[test]
    fn aka_amf_of_autn() {
        // C 3a18564: test set 1's AUTN has an AMF of 0xB9B9, whatever
        // aka_AMF is; one of 0xB9B8 doesn't match its MAC.
        let aka = Aka::from_strings(Some("0x465B5CE8B199B49FAA5F0A2EE238A6BC"), Some("0xCDC202D5123E20F62B6D676AC72CB318"));
        let header = r#"Digest realm="r", nonce="I1U8vpY3qJ0hiuZNrke/NVXzKLQ1d7m5Sp/6w1Tfr7M=", algorithm=AKAv1-MD5"#;
        assert!(credentials("alice", "", "REGISTER", "sip:example.com", "", header, 1, "", aka.as_ref()).is_ok());
        let header = header.replace("d7m5", "d7m4");
        let err = credentials("alice", "", "REGISTER", "sip:example.com", "", &header, 1, "", aka.as_ref()).unwrap_err();
        assert!(err.contains("MAC != expectedMAC"), "{err}");
    }

    #[test]
    fn rfc2617_example() {
        // RFC 2617 section 3.5, with the method and uri it uses.
        let challenge = r#"Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41""#;
        let creds = credentials("Mufasa", "Circle Of Life", "GET", "/dir/index.html", "", challenge, 1, "0a4f113b", None).unwrap();
        assert!(creds.contains(",qop=auth-int,"), "{creds}");
        let rfc_qop_auth = challenge.replace("auth,auth-int", "auth");
        let creds = credentials("Mufasa", "Circle Of Life", "GET", "/dir/index.html", "", &rfc_qop_auth, 1, "0a4f113b", None).unwrap();
        assert_eq!(creds, "Digest username=\"Mufasa\",realm=\"testrealm@host.com\",cnonce=\"0a4f113b\",nc=00000001,qop=auth,uri=\"/dir/index.html\",nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",response=\"6629fae49393a05397450978507c4ef1\",algorithm=MD5,opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"");
        assert!(verify("Mufasa", "Circle Of Life", "GET", &creds, "").unwrap());
        assert!(!verify("Mufasa", "wrong", "GET", &creds, "").unwrap());
    }

    #[test]
    fn missing_response() {
        // C 8e6055a: not the response of any password
        let header = r#"Digest username="testuser",realm="r",uri="sip:x",nonce="n",algorithm=MD5"#;
        assert!(!verify("testuser", "secret", "REGISTER", header, "").unwrap());
        assert!(!verify("testuser", "secret", "REGISTER", &format!("{header},response=\"\""), "").unwrap());
    }

    /// C 8e6055a: whether the response is to the example of RFC 7616
    /// 3.9.1, of its password and not another, and is the one computed.
    fn expect_rfc7616(name: &str, method: &str, uri: &str, nc: &str, qop: &str, body: &str, resp: &str) {
        let auth = format!(
            "Digest username=\"Mufasa\", realm=\"http-auth@example.org\", uri=\"{uri}\", algorithm={name}, \
             nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", nc={nc}, \
             cnonce=\"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ\", qop={qop}, \
             response=\"{resp}\", opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\""
        );
        assert!(verify("Mufasa", "Circle of Life", method, &auth, body).unwrap(), "{auth}");
        assert!(!verify("Mufasa", "Circle of life", method, &auth, body).unwrap(), "{auth}");
        let (a, _) = algo(&auth).unwrap();
        let computed = response(
            a, "Mufasa", b"Circle of Life", method, uri, qop, body, "http-auth@example.org",
            "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ", nc,
        );
        assert_eq!(computed, resp, "{name}");
    }

    #[test]
    fn rfc7616() {
        expect_rfc7616("MD5", "GET", "/dir/index.html", "00000001", "auth", "", "8ca523f5e9506fed4657c9700eebdbec");
        expect_rfc7616("SHA-256", "GET", "/dir/index.html", "00000001", "auth", "", "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1");
        // With auth-int, as Python's hashlib computes it
        expect_rfc7616("MD5", "INVITE", "sip:bob@example.org", "00000002", "auth-int", "v=0\r\n", "3dbb0971468cf612bdccd7dff696c5e6");
        expect_rfc7616("SHA-256", "INVITE", "sip:bob@example.org", "00000002", "auth-int", "v=0\r\n", "21468b02aafd4fe0a3d84bfddaf3618cc087adff4bb3c92d0a5f99c3035fcb9a");
        // C 1d8cf95: the other algorithms of RFC 7616, likewise
        expect_rfc7616("SHA-512-256", "GET", "/dir/index.html", "00000001", "auth", "", "430d05014cecc49cab6fbe03176d41a1da86cbfe24a16580e22aaad928d960d0");
        expect_rfc7616("MD5-sess", "GET", "/dir/index.html", "00000001", "auth", "", "e783283f46242139c486a698fec7211d");
        expect_rfc7616("SHA-256-sess", "GET", "/dir/index.html", "00000001", "auth", "", "2fd51b3a77ad75bad6afad6003e818d767133c46d9e2749e7f5232ae1ea3efd7");
        expect_rfc7616("SHA-512-256-sess", "GET", "/dir/index.html", "00000001", "auth", "", "3f2a34f923c38b0fb26dce2fdfc2ce326c23cecf86fbb1444f3e51fbbc2cb92e");
        expect_rfc7616("SHA-512-256", "INVITE", "sip:bob@example.org", "00000002", "auth-int", "v=0\r\n", "959ca26f4f77c10a9a54b19ac24811fbc7f3c7bda8eec5d8521fb4586ed10e90");
        expect_rfc7616("MD5-sess", "INVITE", "sip:bob@example.org", "00000002", "auth-int", "v=0\r\n", "11713a2ffc80446ab4c404a4a997b69c");
        expect_rfc7616("SHA-256-sess", "INVITE", "sip:bob@example.org", "00000002", "auth-int", "v=0\r\n", "2c66c095845ec6e7e158c4f689683959329e5296947f1c4930d0ffa7b93c09fd");
        expect_rfc7616("SHA-512-256-sess", "INVITE", "sip:bob@example.org", "00000002", "auth-int", "v=0\r\n", "39fcf9431af157aced94549f5fff6fea4d427a3e231c8a5557ccc7976e056b09");
    }

    #[test]
    fn rfc7616_sha512_256() {
        // C 1d8cf95: RFC 7616 3.9.2, with the username and response of
        // its erratum 4897: the RFC's are not of its inputs. verifyauth
        // doesn't read the (hashed) username.
        let auth = concat!(
            r#"Digest username="793263caabb707a56211940d90411ea4a575adeccb7e360aeb624ed06ece9b0b", "#,
            r#"realm="api@example.org", uri="/doe.json", algorithm=SHA-512-256, "#,
            r#"nonce="5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK", nc=00000001, "#,
            r#"cnonce="NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v", qop=auth, "#,
            r#"response="3798d4131c277846293534c3edc11bd8a5e4cdcbff78b05db9d95eeb1cec68a5", "#,
            r#"opaque="HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS", userhash=true"#
        );
        assert!(verify("J\u{e4}s\u{f8}n Doe", "Secret, or not?", "GET", auth, "").unwrap());
        assert!(!verify("Jason Doe", "Secret, or not?", "GET", auth, "").unwrap());
    }

    #[test]
    fn sha256_and_auth_int_round_trip() {
        let challenge = r#"Digest realm="r", nonce="abc", algorithm=SHA-256, qop="auth-int""#;
        let creds = credentials("u", "p", "REGISTER", "sip:1.2.3.4:5060", "body", challenge, 3, "ff", None).unwrap();
        assert!(creds.contains("nc=00000003") && creds.contains("algorithm=SHA-256"));
        assert!(verify("u", "p", "REGISTER", &creds, "body").unwrap());
        assert!(!verify("u", "p", "REGISTER", &creds, "other body").unwrap());
    }
}

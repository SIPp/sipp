//! SIP over WebSocket (RFC 7118): the opening handshake and the framing
//! (RFC 6455) of one connection, as SIPp's WebSocket class. It does no
//! I/O: its connection feeds it the bytes it reads from TCP or TLS, and
//! sends the bytes it gets back.

use sha1::{Digest, Sha1};

pub const OP_CONTINUATION: u8 = 0x0;
pub const OP_TEXT: u8 = 0x1;
pub const OP_BINARY: u8 = 0x2;
pub const OP_CLOSE: u8 = 0x8;
pub const OP_PING: u8 = 0x9;
pub const OP_PONG: u8 = 0xa;

/// RFC 6455 section 1.3
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// What next() found in the bytes fed, with what to send for it.
#[derive(Debug, PartialEq)]
pub enum Event {
    /// Nothing complete: feed more.
    NeedMore,
    /// The handshake is done; a server's 101 to send.
    Opened(Vec<u8>),
    /// A whole message.
    Message(Vec<u8>),
    /// A ping's pong.
    Reply(Vec<u8>),
    /// The peer closed; the echo of its close.
    Closed(Vec<u8>),
    /// A protocol error, in error(): what to send before closing (a close
    /// frame, a server's HTTP error, or nothing from a client's handshake).
    Failed(Vec<u8>),
}

pub struct WebSocket {
    server: bool,
    max_message: usize,
    open: bool,
    closed: bool,
    /// A client's Sec-WebSocket-Key.
    key: String,
    /// The bytes fed, from pos on not parsed yet.
    input: Vec<u8>,
    pos: usize,
    /// The opcode of the message in fragments, and them.
    fragmented: Option<u8>,
    fragments: Vec<u8>,
    err: String,
    /// The frames of the messages sent before the handshake was done, up
    /// to WS_HELD_MAX bytes; has it been full?
    pub held: Vec<u8>,
    pub held_full: bool,
}

fn random_bytes(buf: &mut [u8]) {
    if !crate::sys::random_bytes(buf) {
        // ponytail: as SIPp's rand() fallback; a mask needs no secrecy.
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (t >> (i % 16 * 8)) as u8 ^ i as u8;
        }
    }
}

fn trim(s: &str) -> &str {
    s.trim_matches(|c| c == ' ' || c == '\t')
}

/// The values of the `name` header lines of an HTTP head, comma-separated.
/// Its first line is the request or status line.
fn header(head: &str, name: &str) -> String {
    let mut values = String::new();
    for line in head.split("\r\n").skip(1) {
        if line.len() > name.len() && line.as_bytes()[name.len()] == b':' && line.as_bytes()[..name.len()].eq_ignore_ascii_case(name.as_bytes()) {
            if !values.is_empty() {
                values.push(',');
            }
            values.push_str(trim(&line[name.len() + 1..]));
        }
    }
    values
}

/// Is `token` in the comma-separated list, ignoring case?
fn has_token(list: &str, token: &str) -> bool {
    list.split(',').any(|t| trim(t).eq_ignore_ascii_case(token))
}

/// May a close frame carry this status code? Those of section 7.4.1 and
/// the IANA registry that are not for local use only, and those for
/// libraries, frameworks and applications (section 7.4.2).
fn valid_close_code(code: u16) -> bool {
    (1000..=1003).contains(&code) || (1007..=1014).contains(&code) || (3000..=4999).contains(&code)
}

impl WebSocket {
    /// A server waits for a client's handshake. Messages may be up to
    /// `max_message` bytes long.
    pub fn new(server: bool, max_message: usize) -> WebSocket {
        WebSocket {
            server,
            max_message,
            open: false,
            closed: false,
            key: String::new(),
            input: Vec::new(),
            pos: 0,
            fragmented: None,
            fragments: Vec::new(),
            err: String::new(),
            held: Vec::new(),
            held_full: false,
        }
    }

    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Has the connection closed or failed? Nothing more comes out.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn error(&self) -> &str {
        &self.err
    }

    pub fn accept_key(key: &str) -> String {
        crate::srtp::base64(&Sha1::digest(format!("{key}{GUID}").as_bytes()))
    }

    pub fn is_utf8(data: &[u8]) -> bool {
        // Rust's rules are RFC 3629's, as SIPp's: no overlong forms,
        // surrogates, or code points past Unicode's.
        std::str::from_utf8(data).is_ok()
    }

    pub fn encode(opcode: u8, data: &[u8], mask: Option<[u8; 4]>, fin: bool) -> Vec<u8> {
        let masked = if mask.is_some() { 0x80 } else { 0 };
        let len = data.len();
        let mut f = vec![if fin { 0x80 } else { 0 } | opcode];
        if len < 126 {
            f.push(masked | len as u8);
        } else if len < 65536 {
            f.push(masked | 126);
            f.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            f.push(masked | 127);
            f.extend_from_slice(&(len as u64).to_be_bytes());
        }
        match mask {
            Some(m) => {
                f.extend_from_slice(&m);
                f.extend(data.iter().enumerate().map(|(i, b)| b ^ m[i % 4]));
            }
            None => f.extend_from_slice(data),
        }
        f
    }

    fn make_frame(&self, opcode: u8, data: &[u8]) -> Vec<u8> {
        // A client masks all its frames, a server none (section 5.1).
        if self.server {
            return Self::encode(opcode, data, None, true);
        }
        let mut mask = [0u8; 4];
        random_bytes(&mut mask);
        Self::encode(opcode, data, Some(mask), true)
    }

    /// A message in a frame of its own: a text frame if it is UTF-8, a
    /// binary one otherwise (RFC 7118 section 5.2); masked from a client.
    pub fn frame(&self, data: &[u8]) -> Vec<u8> {
        self.make_frame(if Self::is_utf8(data) { OP_TEXT } else { OP_BINARY }, data)
    }

    /// A close frame, to end the connection.
    pub fn close_frame(&self, code: u16) -> Vec<u8> {
        self.make_frame(OP_CLOSE, &code.to_be_bytes())
    }

    /// A client's handshake: a GET of `path`, for `host`.
    pub fn request(&mut self, host: &str, path: &str) -> String {
        let mut nonce = [0u8; 16];
        random_bytes(&mut nonce);
        self.key = crate::srtp::base64(&nonce);
        // An absolute path, even if -ws_path leaves out its first '/'.
        let slash = if path.starts_with('/') { "" } else { "/" };
        format!(
            "GET {slash}{path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: sip\r\n\r\n",
            self.key
        )
    }

    pub fn feed(&mut self, data: &[u8]) {
        if self.closed {
            return;
        }
        self.input.drain(..self.pos);
        self.pos = 0;
        self.input.extend_from_slice(data);
    }

    /// Fail the connection: with a close frame once it is open, with an
    /// HTTP error from a server during the handshake (code 400 or 426).
    fn fail(&mut self, code: u16, why: String) -> Event {
        self.closed = true;
        self.err = why;
        if self.open {
            return Event::Failed(self.close_frame(code));
        }
        if !self.server {
            return Event::Failed(Vec::new());
        }
        let status = if code == 426 { "HTTP/1.1 426 Upgrade Required\r\nSec-WebSocket-Version: 13\r\n" } else { "HTTP/1.1 400 Bad Request\r\n" };
        Event::Failed(format!("{status}Content-Length: 0\r\n\r\n").into_bytes())
    }

    fn handshake(&mut self) -> Event {
        let Some(end) = self.input[self.pos..].windows(4).position(|w| w == b"\r\n\r\n").map(|e| e + self.pos) else {
            if self.input.len() - self.pos > self.max_message {
                return self.fail(400, format!("a handshake longer than {} bytes", self.max_message));
            }
            return Event::NeedMore;
        };
        let head = String::from_utf8_lossy(&self.input[self.pos..end + 2]).into_owned();
        let first = head[..head.find("\r\n").unwrap_or(head.len())].to_string();
        self.pos = end + 4;

        let upgrade = has_token(&header(&head, "Upgrade"), "websocket") && has_token(&header(&head, "Connection"), "Upgrade");
        let reply = if self.server {
            let client_key = header(&head, "Sec-WebSocket-Key");
            if !first.starts_with("GET ") || first.len() < 13 || !first.ends_with(" HTTP/1.1") {
                return self.fail(400, format!("not a GET request: '{first}'"));
            }
            if !upgrade {
                return self.fail(400, "not a WebSocket upgrade".into());
            }
            if !has_token(&header(&head, "Sec-WebSocket-Version"), "13") {
                return self.fail(426, "not WebSocket version 13".into());
            }
            if client_key.is_empty() {
                return self.fail(400, "no Sec-WebSocket-Key".into());
            }
            if !has_token(&header(&head, "Sec-WebSocket-Protocol"), "sip") {
                return self.fail(400, "the client does not offer the sip subprotocol".into());
            }
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: sip\r\n\r\n",
                Self::accept_key(&client_key)
            )
            .into_bytes()
        } else {
            if !first.starts_with("HTTP/1.1 101") || first.as_bytes().get(12).is_some_and(|&c| c != b' ') {
                return self.fail(0, format!("the server answered '{first}'"));
            }
            if !upgrade {
                return self.fail(0, "not a WebSocket upgrade".into());
            }
            if header(&head, "Sec-WebSocket-Accept") != Self::accept_key(&self.key) {
                return self.fail(0, "a wrong Sec-WebSocket-Accept".into());
            }
            if !header(&head, "Sec-WebSocket-Protocol").eq_ignore_ascii_case("sip") {
                return self.fail(0, "the server does not take the sip subprotocol".into());
            }
            Vec::new()
        };
        self.open = true;
        Event::Opened(reply)
    }

    /// A whole message: the text of a text message is UTF-8 (section 8.1).
    fn message(&mut self, opcode: u8, payload: Vec<u8>) -> Event {
        if opcode == OP_TEXT && !Self::is_utf8(&payload) {
            return self.fail(1007, "a text message that is not UTF-8".into());
        }
        Event::Message(payload)
    }

    /// The next event in the bytes fed: first the handshake, then one
    /// frame after the other (RFC 6455 section 5.2). A frame is a 2-byte
    /// header (FIN, reserved bits, opcode; MASK, length), a 16- or 64-bit
    /// extended length if the length is 126 or 127, a 4-byte mask if
    /// masked, then the payload. Data frames make up a message, alone or in
    /// fragments; control frames (close, ping, pong) come whole, even
    /// between fragments. A frame not all in yet is left for the next call;
    /// one that breaks the rules fails the connection. Called until it
    /// returns NeedMore.
    pub fn next(&mut self) -> Event {
        if self.closed {
            return Event::NeedMore;
        }
        if !self.open {
            return self.handshake();
        }

        // Frames that need nothing sent (fragments, pongs) do not return.
        loop {
            let p = &self.input[self.pos..];
            if p.len() < 2 {
                return Event::NeedMore;
            }

            // The 2-byte header
            let fin = p[0] & 0x80 != 0;
            let opcode = p[0] & 0x0f;
            let masked = p[1] & 0x80 != 0;
            let mut len = u64::from(p[1] & 0x7f);
            let mut hlen = 2;

            // No extension is negotiated, so no reserved bit may be set.
            if p[0] & 0x70 != 0 {
                return self.fail(1002, "a frame with reserved bits set".into());
            }
            // A client masks its frames, a server does not (section 5.1).
            if masked != self.server {
                let why = if self.server { "an unmasked frame from the client" } else { "a masked frame from the server" };
                return self.fail(1002, why.into());
            }
            // The extended length, in network byte order
            if len == 126 {
                if p.len() < 4 {
                    return Event::NeedMore;
                }
                len = u64::from(u16::from_be_bytes([p[2], p[3]]));
                hlen = 4;
            } else if len == 127 {
                if p.len() < 10 {
                    return Event::NeedMore;
                }
                len = u64::from_be_bytes(p[2..10].try_into().unwrap());
                hlen = 10;
            }
            // Checked before the payload is in, so that no peer makes it
            // buffer more than a message may take (section 5.5).
            if opcode >= OP_CLOSE {
                if !fin || len > 125 {
                    return self.fail(1002, "a fragmented or long control frame".into());
                }
            } else if len > (self.max_message - self.fragments.len()) as u64 {
                return self.fail(1009, format!("a message longer than {} bytes", self.max_message));
            }
            if masked {
                hlen += 4;
            }
            let len = len as usize;
            if p.len() < hlen + len {
                return Event::NeedMore;
            }

            // The payload, unmasked
            let mut data = p[hlen..hlen + len].to_vec();
            if masked {
                let mask = &p[hlen - 4..hlen];
                for (i, b) in data.iter_mut().enumerate() {
                    *b ^= mask[i % 4];
                }
            }
            self.pos += hlen + len;

            match opcode {
                OP_TEXT | OP_BINARY => {
                    // A message, whole or in its first fragment
                    if self.fragmented.is_some() {
                        return self.fail(1002, "a new message inside a fragmented one".into());
                    }
                    if fin {
                        return self.message(opcode, data);
                    }
                    self.fragmented = Some(opcode);
                    self.fragments = data;
                }
                OP_CONTINUATION => {
                    // A further fragment; the last one completes the message.
                    let Some(first) = self.fragmented else {
                        return self.fail(1002, "a continuation frame without a message".into());
                    };
                    self.fragments.extend_from_slice(&data);
                    if fin {
                        self.fragmented = None;
                        let payload = std::mem::take(&mut self.fragments);
                        return self.message(first, payload);
                    }
                }
                OP_PING => return Event::Reply(self.make_frame(OP_PONG, &data)),
                OP_PONG => {}
                OP_CLOSE => {
                    // An optional status code and UTF-8 reason (section 5.5.1)
                    if data.len() == 1 {
                        return self.fail(1002, "a close frame with a one-byte payload".into());
                    }
                    if data.len() >= 2 {
                        let code = u16::from_be_bytes([data[0], data[1]]);
                        if !valid_close_code(code) {
                            return self.fail(1002, format!("a close frame with status code {code}"));
                        }
                        if !Self::is_utf8(&data[2..]) {
                            return self.fail(1007, "a close reason that is not UTF-8".into());
                        }
                    }
                    self.closed = true;
                    // Echo its status code (section 5.5.1).
                    return Event::Closed(self.make_frame(OP_CLOSE, &data[..data.len().min(2)]));
                }
                _ => return self.fail(1002, format!("a frame of unknown opcode {opcode}")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SIPp's gtest vectors (websocket.cpp).
    fn bytes(hex: &str) -> Vec<u8> {
        (0..hex.len() / 2).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    fn cat(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    fn reply_of(e: Event) -> Vec<u8> {
        match e {
            Event::Opened(r) | Event::Reply(r) | Event::Closed(r) | Event::Failed(r) => r,
            other => panic!("no reply in {other:?}"),
        }
    }

    /// A client and a server, done with the handshake.
    fn handshake(client: &mut WebSocket, server: &mut WebSocket) {
        let req = client.request("example.com:5060", "/sip");
        assert!(req.starts_with("GET /sip HTTP/1.1\r\nHost: example.com:5060\r\n"));
        server.feed(req.as_bytes());
        let Event::Opened(reply) = server.next() else { panic!("the server did not open") };
        let text = String::from_utf8(reply.clone()).unwrap();
        assert!(text.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(text.contains("\r\nSec-WebSocket-Protocol: sip\r\n"));
        client.feed(&reply);
        assert_eq!(client.next(), Event::Opened(Vec::new()));
        assert!(client.is_open());
        assert!(server.is_open());
    }

    fn pair(max: usize) -> (WebSocket, WebSocket) {
        let (mut c, mut s) = (WebSocket::new(false, max), WebSocket::new(true, max));
        handshake(&mut c, &mut s);
        (c, s)
    }

    #[test]
    fn accept_key() {
        // RFC 6455 section 1.3
        assert_eq!(WebSocket::accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn encode() {
        // RFC 6455 section 5.7
        let mask = Some([0x37, 0xfa, 0x21, 0x3d]);
        assert_eq!(WebSocket::encode(OP_TEXT, b"Hello", None, true), bytes("810548656c6c6f"));
        assert_eq!(WebSocket::encode(OP_TEXT, b"Hello", mask, true), bytes("818537fa213d7f9f4d5158"));
        assert_eq!(WebSocket::encode(OP_TEXT, b"Hel", None, false), bytes("010348656c"));
        assert_eq!(WebSocket::encode(OP_CONTINUATION, b"lo", None, true), bytes("80026c6f"));
        for (len, head) in [(256, "827e0100"), (65536, "827f0000000000010000"), (125, "827d"), (126, "827e007e")] {
            let s = vec![b'x'; len];
            assert_eq!(WebSocket::encode(OP_BINARY, &s, None, true), cat(&[&bytes(head), &s]));
        }
    }

    #[test]
    fn utf8() {
        assert!(WebSocket::is_utf8(b"INVITE sip:a@b SIP/2.0\r\n"));
        assert!(WebSocket::is_utf8(b"caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80"));
        assert!(!WebSocket::is_utf8(b"\xff"));
        assert!(!WebSocket::is_utf8(b"\xc0\x80")); // Overlong
        assert!(!WebSocket::is_utf8(b"\xed\xa0\x80")); // Surrogate
        assert!(!WebSocket::is_utf8(b"\xf4\x90\x80\x80")); // Past U+10FFFF
        assert!(!WebSocket::is_utf8(b"\xc3")); // Cut short
        assert!(!WebSocket::is_utf8(b"\xc3("));

        let server = WebSocket::new(true, 100);
        assert_eq!(server.frame(b"A"), bytes("810141"));
        assert_eq!(server.frame(b"\xff"), bytes("8201ff"));
    }

    #[test]
    fn messages() {
        let (client, mut server) = pair(100000);
        let mut client = client;

        // Client frames are masked, each with a mask of its own.
        let f = client.frame(b"INVITE");
        assert_eq!(f.len(), 12);
        assert_eq!(&f[..2], b"\x81\x86");
        server.feed(&f);
        assert_eq!(server.next(), Event::Message(b"INVITE".to_vec()));
        assert_eq!(server.next(), Event::NeedMore);

        // Server frames are not; and one read may hold several frames.
        let f = cat(&[&server.frame(b"SIP/2.0 100"), &server.frame(b"SIP/2.0 200")]);
        assert_eq!(&f[..13], cat(&[&bytes("810b"), b"SIP/2.0 100"]).as_slice());
        client.feed(&f);
        assert_eq!(client.next(), Event::Message(b"SIP/2.0 100".to_vec()));
        assert_eq!(client.next(), Event::Message(b"SIP/2.0 200".to_vec()));

        // 16- and 64-bit lengths, a byte at a time.
        for len in [300, 70000] {
            let msg = vec![b'm'; len];
            let f = client.frame(&msg);
            for b in &f[..f.len() - 1] {
                server.feed(std::slice::from_ref(b));
                assert_eq!(server.next(), Event::NeedMore);
            }
            server.feed(&f[f.len() - 1..]);
            assert_eq!(server.next(), Event::Message(msg));
        }
    }

    #[test]
    fn fragments() {
        let (mut client, mut server) = pair(100);

        // A ping may come between the fragments of a message.
        let f = cat(&[
            &WebSocket::encode(OP_TEXT, b"INV", None, false),
            &WebSocket::encode(OP_PING, b"hi", None, true),
            &WebSocket::encode(OP_CONTINUATION, b"ITE", None, false),
            &WebSocket::encode(OP_PONG, b"", None, true),
            &WebSocket::encode(OP_CONTINUATION, b" sip", None, true),
        ]);
        client.feed(&f);
        // The pong, masked.
        let pong = reply_of(client.next());
        assert_eq!(pong.len(), 8);
        assert_eq!(&pong[..2], b"\x8a\x82");
        server.feed(&pong);
        assert_eq!(server.next(), Event::NeedMore);
        assert_eq!(client.next(), Event::Message(b"INVITE sip".to_vec()));
        assert_eq!(client.next(), Event::NeedMore);

        // A character of a text message may span fragments.
        client.feed(&cat(&[&bytes("0101c3"), &bytes("8001a9")]));
        assert_eq!(client.next(), Event::Message(b"\xc3\xa9".to_vec()));

        // Fragments no longer, in all, than a message may be.
        let half = [b'x'; 60];
        client.feed(&cat(&[&WebSocket::encode(OP_BINARY, &half, None, false), &WebSocket::encode(OP_CONTINUATION, &half, None, true)]));
        assert!(matches!(client.next(), Event::Failed(_)));
        assert_eq!(client.error(), "a message longer than 100 bytes");
        assert!(client.is_closed());
    }

    #[test]
    fn ping() {
        let (_client, mut server) = pair(100);
        server.feed(&WebSocket::encode(OP_PING, b"abc", Some([1, 2, 3, 4]), true));
        assert_eq!(server.next(), Event::Reply(cat(&[&bytes("8a03"), b"abc"])));
    }

    #[test]
    fn close() {
        let (mut client, mut server) = pair(100);
        let f = cat(&[&client.frame(b"BYE"), &client.close_frame(1000), &client.frame(b"late")]);
        server.feed(&f);
        assert_eq!(server.next(), Event::Message(b"BYE".to_vec()));
        assert_eq!(server.next(), Event::Closed(bytes("880203e8")));
        assert!(server.is_closed());
        // Nothing comes after a close.
        assert_eq!(server.next(), Event::NeedMore);
        server.feed(&f);
        assert_eq!(server.next(), Event::NeedMore);

        client.feed(&WebSocket::encode(OP_CLOSE, b"", None, true));
        let echo = reply_of(client.next());
        assert!(client.is_closed());
        assert_eq!(echo.len(), 6);
        assert_eq!(&echo[..2], b"\x88\x80");

        // Status codes of the registry and for applications, with a UTF-8
        // reason; the echo leaves out the reason.
        for close in ["880203f2", "88070fa0c3a9746521"] {
            let (mut client, _server) = pair(100);
            client.feed(&bytes(close));
            let Event::Closed(echo) = client.next() else { panic!("{close}") };
            assert_eq!(echo.len(), 8);
            assert_eq!(echo[1], 0x82);
        }
    }

    #[test]
    fn protocol_errors() {
        let tests: &[(bool, &str, &str, u16)] = &[
            (true, "810141", "an unmasked frame from the client", 1002),
            (false, "81810000000041", "a masked frame from the server", 1002),
            (false, "c10141", "a frame with reserved bits set", 1002),
            (false, "830141", "a frame of unknown opcode 3", 1002),
            (false, "800141", "a continuation frame without a message", 1002),
            (false, "01014181014142", "a new message inside a fragmented one", 1002),
            (false, "097e0080", "a fragmented or long control frame", 1002),
            (false, "0900", "a fragmented or long control frame", 1002),
            (false, "880103", "a close frame with a one-byte payload", 1002),
            (false, "880203e7", "a close frame with status code 999", 1002),
            (false, "880203ed", "a close frame with status code 1005", 1002),
            (false, "88021388", "a close frame with status code 5000", 1002),
            (false, "880303e8ff", "a close reason that is not UTF-8", 1007),
            (false, "8102c328", "a text message that is not UTF-8", 1007),
            (false, "0101c3800128", "a text message that is not UTF-8", 1007),
            (false, "817e0065", "a message longer than 100 bytes", 1009),
            (false, "817fffffffffffffffff", "a message longer than 100 bytes", 1009),
        ];
        for &(to_server, frame, error, code) in tests {
            let (mut client, mut server) = pair(100);
            let ws = if to_server { &mut server } else { &mut client };
            ws.feed(&bytes(frame));
            let Event::Failed(reply) = ws.next() else { panic!("{error}") };
            assert_eq!(ws.error(), error);
            // A close frame with the status code.
            assert!(reply.len() >= 4);
            assert_eq!(reply[0], 0x88);
            let mut status = [reply[reply.len() - 2], reply[reply.len() - 1]];
            if !to_server {
                // Unmask it.
                status[0] ^= reply[2];
                status[1] ^= reply[3];
            }
            assert_eq!(u16::from_be_bytes(status), code, "{error}");
        }
    }

    const VALID: &str = "GET / HTTP/1.1\r\nHost: h\r\nupgrade: WebSocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat\r\nSec-WebSocket-Protocol: sip\r\n\r\n";

    #[test]
    fn server_handshake() {
        let mut server = WebSocket::new(true, 1000);
        // In two parts, and with a frame right behind.
        let req = cat(&[VALID.as_bytes(), &bytes("818100000000"), b"A"]);
        server.feed(&req[..10]);
        assert_eq!(server.next(), Event::NeedMore);
        server.feed(&req[10..]);
        assert_eq!(
            server.next(),
            Event::Opened(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: sip\r\n\r\n".to_vec()
            )
        );
        assert_eq!(server.next(), Event::Message(b"A".to_vec()));

        let tests = [
            ("GET / ", "POST / ", "400", "not a GET request: 'POST / HTTP/1.1'"),
            ("WebSocket", "h2c", "400", "not a WebSocket upgrade"),
            ("keep-alive, Upgrade", "close", "400", "not a WebSocket upgrade"),
            ("Version: 13", "Version: 8", "426", "not WebSocket version 13"),
            ("Key: dGhlIHNhbXBsZSBub25jZQ==", "Key:", "400", "no Sec-WebSocket-Key"),
            ("Protocol: sip", "Protocol: sips", "400", "the client does not offer the sip subprotocol"),
        ];
        for (from, to, status, error) in tests {
            let mut server = WebSocket::new(true, 1000);
            server.feed(VALID.replacen(from, to, 1).as_bytes());
            let Event::Failed(reply) = server.next() else { panic!("{error}") };
            assert_eq!(server.error(), error);
            assert_eq!(&reply[..12], format!("HTTP/1.1 {status}").as_bytes());
            assert!(!server.is_open());
        }

        let mut server = WebSocket::new(true, 10);
        server.feed(&VALID.as_bytes()[..11]);
        assert!(matches!(server.next(), Event::Failed(_)));
        assert_eq!(server.error(), "a handshake longer than 10 bytes");
    }

    #[test]
    fn client_handshake() {
        let tests = [
            ("101 Switching Protocols", "404 Not Found", "the server answered 'HTTP/1.1 404 Not Found'"),
            ("101 Switching Protocols", "1010", "the server answered 'HTTP/1.1 1010'"),
            ("Upgrade: websocket", "Upgrade: x", "not a WebSocket upgrade"),
            ("Accept: ", "Accept: x", "a wrong Sec-WebSocket-Accept"),
            ("Protocol: sip", "Protocol: chat", "the server does not take the sip subprotocol"),
        ];
        for (from, to, error) in tests {
            let (mut client, mut server) = (WebSocket::new(false, 1000), WebSocket::new(true, 1000));
            assert!(client.request("h", "").starts_with("GET / HTTP/1.1\r\n"));
            // A path without its first '/'.
            assert!(client.request("h", "sip").starts_with("GET /sip HTTP/1.1\r\n"));
            server.feed(client.request("h", "/").as_bytes());
            let reply = String::from_utf8(reply_of(server.next())).unwrap();
            client.feed(reply.replacen(from, to, 1).as_bytes());
            assert_eq!(client.next(), Event::Failed(Vec::new()), "{error}");
            assert_eq!(client.error(), error);
            assert!(!client.is_open());
            assert!(client.is_closed());
        }
    }
}

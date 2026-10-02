//! Transports: UDP, and TCP with one connection for all calls (t1) or one
//! per call (tn).

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, ServerConfig, ServerConnection, SignatureScheme, StreamOwned};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{HashMap, VecDeque};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use crate::sys::{self, AsRawFd, RawFd};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::websocket::{Event, WebSocket};

/// SIPP_MAX_MSG_SIZE - 1: the longest WebSocket message or handshake.
const WS_MAX_MESSAGE: usize = 65535;

/// -buff_size: the send and receive buffers of every SIP socket, as
/// sipp_customize_socket() sets them.
static BUFF_SIZE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(65536);

pub fn set_buff_size(n: usize) {
    BUFF_SIZE.store(n, std::sync::atomic::Ordering::Relaxed);
}

/// sipp_customize_socket()'s buffers; like SIPp, a failure is fatal.
fn buffers(s: impl sys::AsSock) -> io::Result<()> {
    let n = BUFF_SIZE.load(std::sync::atomic::Ordering::Relaxed);
    let s = socket2::SockRef::from(&s);
    s.set_send_buffer_size(n).map_err(|e| io::Error::new(e.kind(), format!("Unable to set socket sndbuf, errno = {} ({})", e.raw_os_error().unwrap_or(0), os_error(&e))))?;
    s.set_recv_buffer_size(n).map_err(|e| io::Error::new(e.kind(), format!("Unable to set socket rcvbuf, errno = {} ({})", e.raw_os_error().unwrap_or(0), os_error(&e))))
}
/// What a WebSocket client holds for its handshake at most.
const WS_HELD_MAX: usize = 16 * 65536;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Transport {
    Udp,
    /// -t un: a UDP socket of its own for each client call.
    UdpMulti,
    /// -t ui: a UDP socket per local IP, which -ip_field picks from -inf.
    UdpPerIp,
    /// -t t1: every call shares one connection.
    TcpSingle,
    /// -t tn: one connection per call.
    TcpMulti,
    /// -t l1 / ln: the same over TLS.
    TlsSingle,
    TlsMulti,
    /// -t s1 / sn: the same over SCTP, one association per connection.
    SctpSingle,
    SctpMulti,
    /// -t w1 / wn: SIP over WebSocket (RFC 7118) on TCP; x1 / xn: on TLS.
    WsSingle,
    WsMulti,
    WssSingle,
    WssMulti,
}

impl Transport {
    pub fn name(self) -> &'static str {
        match self {
            Transport::Udp | Transport::UdpMulti | Transport::UdpPerIp => "UDP",
            Transport::TcpSingle | Transport::TcpMulti => "TCP",
            Transport::TlsSingle | Transport::TlsMulti => "TLS",
            Transport::SctpSingle | Transport::SctpMulti => "SCTP",
            Transport::WsSingle | Transport::WsMulti => "WS",
            Transport::WssSingle | Transport::WssMulti => "WSS",
        }
    }

    pub fn sctp(self) -> bool {
        matches!(self, Transport::SctpSingle | Transport::SctpMulti)
    }

    /// TLS, below a WebSocket or not.
    pub fn tls(self) -> bool {
        matches!(self, Transport::TlsSingle | Transport::TlsMulti | Transport::WssSingle | Transport::WssMulti)
    }

    pub fn ws(self) -> bool {
        matches!(self, Transport::WsSingle | Transport::WsMulti | Transport::WssSingle | Transport::WssMulti)
    }

    pub fn single(self) -> bool {
        matches!(self, Transport::TcpSingle | Transport::TlsSingle | Transport::SctpSingle | Transport::WsSingle | Transport::WssSingle)
    }

    /// tn / ln / un: each call has a connection (or socket) of its own.
    pub fn per_call(self) -> bool {
        matches!(
            self,
            Transport::TcpMulti | Transport::TlsMulti | Transport::SctpMulti | Transport::UdpMulti | Transport::UdpPerIp | Transport::WsMulti | Transport::WssMulti
        )
    }

    pub fn udp(self) -> bool {
        matches!(self, Transport::Udp | Transport::UdpMulti | Transport::UdpPerIp)
    }

    pub fn reliable(self) -> bool {
        !self.udp()
    }
}

pub type ConnId = u64;

/// strerror()'s text for an OS error, as SIPp prints it.
/// ERR_error_string_n() of an OpenSSL 3 system error.
fn openssl_system_error(e: &io::Error) -> String {
    format!("error:{:08X}:system library::{}", 0x8000_0000u32 | e.raw_os_error().unwrap_or(0) as u32, os_error(e))
}

pub fn os_error(e: &io::Error) -> String {
    let s = e.to_string();
    match s.find(" (os error ") {
        Some(i) => s[..i].to_string(),
        None => s,
    }
}

/// gai_getsockaddr() with a preference: of the addresses of `target`, the
/// first one of that family (IPv6 or not) if there is one, else the first.
pub fn resolve(target: impl ToSocketAddrs, prefer_v6: Option<bool>) -> io::Result<Option<SocketAddr>> {
    let addrs: Vec<SocketAddr> = target.to_socket_addrs()?.collect();
    Ok(addrs.iter().find(|a| Some(a.is_ipv6()) == prefer_v6).or(addrs.first()).copied())
}

/// -multihome, -heartbeat, -assocmaxret, -pathmaxret, -pmtu and
/// -gracefulclose.
#[derive(Clone, Copy, Debug)]
pub struct SctpOptions {
    pub multihome: Option<IpAddr>,
    /// Close with SHUTDOWN (true, the default) or ABORT.
    pub graceful: bool,
    pub heartbeat: u32,
    pub assocmaxret: u16,
    pub pathmaxret: u16,
    pub pmtu: u32,
}

impl Default for SctpOptions {
    fn default() -> SctpOptions {
        SctpOptions { multihome: None, graceful: true, heartbeat: 0, assocmaxret: 0, pathmaxret: 0, pmtu: 0 }
    }
}

// <linux/sctp.h>.
const IPPROTO_SCTP: i32 = 132;
const SCTP_ASSOCINFO: i32 = 1;
const SCTP_NODELAY: i32 = 3;
const SCTP_PEER_ADDR_PARAMS: i32 = 9;
const SCTP_DEFAULT_SEND_PARAM: i32 = 10;
const SCTP_SOCKOPT_BINDX_ADD: i32 = 100;
const SCTP_UNORDERED: u16 = 1;
const SPP_HB_ENABLE: u32 = 1 << 0;
const SPP_PMTUD_DISABLE: u32 = 1 << 4;

fn sctp_setsockopt(fd: RawFd, opt: i32, value: *const libc::c_void, len: usize) -> io::Result<()> {
    // SAFETY: the callers pass a buffer valid for `len` bytes.
    match unsafe { sys::setsockopt(fd, IPPROTO_SCTP, opt, value, len as sys::socklen_t) } {
        0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

impl SctpOptions {
    /// A one-to-one SCTP socket, customized as sipp_customize_socket() does.
    fn socket(&self, domain: Domain) -> io::Result<Socket> {
        let s = Socket::new(domain, Type::STREAM, Some(Protocol::from(IPPROTO_SCTP)))?;
        s.set_reuse_address(true)?;
        let fd = s.as_raw_fd();
        if self.assocmaxret > 0 {
            // struct sctp_assocparams: the association id, then asocmaxrxt.
            let mut p = [0u8; 20];
            p[4..6].copy_from_slice(&self.assocmaxret.to_ne_bytes());
            sctp_setsockopt(fd, SCTP_ASSOCINFO, p.as_ptr().cast(), p.len())?;
        }
        let on: i32 = 1;
        sctp_setsockopt(fd, SCTP_NODELAY, (&on as *const i32).cast(), 4)?;
        s.set_linger(Some(Duration::from_secs(1)))?;
        // send_sctp_nowait(): every message unordered (RFC 4168 section
        // 5.1), which struct sctp_sndrcvinfo's sinfo_flags asks for.
        let mut p = [0u8; 32];
        p[4..6].copy_from_slice(&SCTP_UNORDERED.to_ne_bytes());
        sctp_setsockopt(fd, SCTP_DEFAULT_SEND_PARAM, p.as_ptr().cast(), p.len())?;
        Ok(s)
    }

    /// set_multihome_addr(): a second local address, after the bind.
    fn multihome(&self, s: &Socket, port: u16) -> io::Result<()> {
        let Some(ip) = self.multihome else { return Ok(()) };
        let addr = socket2::SockAddr::from(SocketAddr::new(ip, port));
        sctp_setsockopt(s.as_raw_fd(), SCTP_SOCKOPT_BINDX_ADD, addr.as_ptr().cast(), addr.len() as usize)
    }

    /// sipp_sctp_peer_params(), once the association is up: for the
    /// association and all its peer addresses, which a zero spp_address
    /// asks for, as SIPp does.
    fn peer_params(&self, fd: RawFd) -> Vec<String> {
        if self.heartbeat == 0 && self.pathmaxret == 0 && self.pmtu == 0 {
            return Vec::new();
        }
        // struct sctp_paddrparams, packed: spp_address at 4, spp_hbinterval
        // at 132, spp_pathmaxrxt 136, spp_pathmtu 138, spp_flags 146.
        let mut p = [0u8; 156];
        p[132..136].copy_from_slice(&self.heartbeat.to_ne_bytes());
        p[136..138].copy_from_slice(&self.pathmaxret.to_ne_bytes());
        let mut flags = if self.heartbeat > 0 { SPP_HB_ENABLE } else { 0 };
        if self.pmtu > 0 {
            p[138..142].copy_from_slice(&self.pmtu.to_ne_bytes());
            flags |= SPP_PMTUD_DISABLE;
        }
        p[146..150].copy_from_slice(&flags.to_ne_bytes());
        match sctp_setsockopt(fd, SCTP_PEER_ADDR_PARAMS, p.as_ptr().cast(), p.len()) {
            Ok(()) => Vec::new(),
            Err(e) => vec![format!("setsockopt(SCTP_PEER_ADDR_PARAMS) failed, errno={}", e.raw_os_error().unwrap_or(0))],
        }
    }

    /// An association is up (SCTP_COMM_UP): its peer parameters, as SIPp
    /// sets them then, and without -gracefulclose, a zero linger so that
    /// closing aborts it. What failed, to warn about.
    fn up(&self, s: &TcpStream) -> Vec<String> {
        let mut warnings = Vec::new();
        if !self.graceful && socket2::SockRef::from(s).set_linger(Some(Duration::ZERO)).is_err() {
            warnings.push("Unable to set SO_LINGER option for SCTP close".into());
        }
        warnings.extend(self.peer_params(s.as_raw_fd()));
        warnings
    }
}

/// The address of a call's peer when there is no remote host: a server
/// call that a 3PCC command starts, or a 3PCC call with no SIP.
pub const NO_REMOTE: SocketAddr = SocketAddr::V4(std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0));

/// Where a call's messages go: an address, and for TCP its connection.
#[derive(Clone, Copy, Debug)]
pub struct Peer {
    pub addr: SocketAddr,
    pub conn: Option<ConnId>,
}

/// A TCP connection, or TLS over one.
enum Stream {
    Plain(TcpStream),
    Client(Box<StreamOwned<ClientConnection, TcpStream>>),
    Server(Box<StreamOwned<ServerConnection, TcpStream>>),
    /// legacy-tls: TLS 1.0 or 1.1 through OpenSSL.
    #[cfg(feature = "legacy-tls")]
    OpenSsl(Box<openssl::ssl::SslStream<TcpStream>>),
}

impl Stream {
    fn raw_fd(&self) -> RawFd {
        self.tcp().as_raw_fd()
    }

    fn tcp(&self) -> &TcpStream {
        match self {
            Stream::Plain(s) => s,
            Stream::Client(s) => s.get_ref(),
            Stream::Server(s) => s.get_ref(),
            #[cfg(feature = "legacy-tls")]
            Stream::OpenSsl(s) => s.get_ref(),
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf),
            Stream::Client(s) => s.read(buf),
            Stream::Server(s) => s.read(buf),
            #[cfg(feature = "legacy-tls")]
            Stream::OpenSsl(s) => s.read(buf),
        }
    }

    /// Sends handshake records rustls queued while reading.
    fn flush_tls(&mut self) {
        match self {
            Stream::Client(s) => while s.conn.wants_write() && s.conn.write_tls(&mut s.sock).is_ok() {},
            Stream::Server(s) => while s.conn.wants_write() && s.conn.write_tls(&mut s.sock).is_ok() {},
            _ => {}
        }
    }

    /// One go at the handshake, for handshake().
    fn handshake_step(&mut self) -> Step {
        match self {
            Stream::Plain(_) => Step::Done,
            Stream::Client(s) => rustls_step(&mut s.conn, &mut s.sock),
            Stream::Server(s) => rustls_step(&mut s.conn, &mut s.sock),
            #[cfg(feature = "legacy-tls")]
            Stream::OpenSsl(s) => crate::tls_openssl::step(s),
        }
    }

    /// A non-blocking write, as far as the socket takes it.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(buf),
            Stream::Client(s) => s.write(buf),
            Stream::Server(s) => s.write(buf),
            #[cfg(feature = "legacy-tls")]
            Stream::OpenSsl(s) => s.write(buf),
        }
    }

    /// TLS records that rustls holds, not written yet.
    fn tls_waiting(&self) -> bool {
        match self {
            Stream::Client(s) => s.conn.wants_write(),
            Stream::Server(s) => s.conn.wants_write(),
            _ => false,
        }
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match self {
            Stream::Plain(s) => s.write_all(buf),
            Stream::Client(s) => s.write_all(buf).and_then(|_| s.flush()),
            Stream::Server(s) => s.write_all(buf).and_then(|_| s.flush()),
            #[cfg(feature = "legacy-tls")]
            Stream::OpenSsl(s) => s.write_all(buf),
        }
    }
}

/// SIPp's TLS client doesn't check the server's certificate by default.
#[derive(Debug)]
struct AnyCertificate(Arc<CryptoProvider>);

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(&self, _: &CertificateDer, _: &[CertificateDer], _: &ServerName, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, msg: &[u8], cert: &CertificateDer, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(msg, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, msg: &[u8], cert: &CertificateDer, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(msg, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// TLS settings: a server needs -tls_cert and -tls_key, a client may go
/// without.
pub struct Tls {
    backend: Backend,
    handshake_timeout: Duration,
}

enum Backend {
    Rustls { client: Arc<ClientConfig>, server: Arc<ServerConfig> },
    /// legacy-tls: -tls_version 1.0 or 1.1.
    #[cfg(feature = "legacy-tls")]
    OpenSsl(crate::tls_openssl::Contexts),
}

/// -tls_ca, -tls_crl, -tls_version and -tls_handshake_timeout.
#[derive(Default, Clone)]
pub struct TlsOptions {
    pub ca: Option<String>,
    pub crl: Option<String>,
    /// 1.2 or 1.3; None negotiates.
    pub version: Option<f64>,
    /// Zero: no limit.
    pub handshake_timeout: Duration,
}

/// A TLS handshake that failed, which connect() warned about, and the
/// errno SIPp is left with then.
#[derive(Debug)]
pub struct HandshakeFailed(pub i32);

impl std::fmt::Display for HandshakeFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("TLS handshake failed")
    }
}

impl std::error::Error for HandshakeFailed {}

/// -max_socket leaves no room for a call socket, and there is none to share.
#[derive(Debug)]
pub struct NoCallSocket;

impl std::fmt::Display for NoCallSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("Could not find an existing call socket to re-use!")
    }
}

impl std::error::Error for NoCallSocket {}

/// The errno of a connect() whose TLS handshake failed.
pub fn handshake_failed(e: &io::Error) -> Option<i32> {
    e.get_ref().and_then(|e| e.downcast_ref::<HandshakeFailed>()).map(|h| h.0)
}

/// Where a handshake step left it: done, waiting for the socket (POLLIN
/// or POLLOUT), or failed with SIPp's SSL_error_string() and the errno.
pub(crate) enum Step {
    Done,
    Wait(sys::c_short),
    Failed(String, i32),
}

/// A message's bytes as text, those that are not UTF-8 kept (raw), in
/// the Arc<str> its call keeps.
fn text_of(bytes: &[u8]) -> Arc<str> {
    crate::raw::text(bytes).into()
}

/// Windows keeps a closed connection's addresses in TIME_WAIT for minutes
/// and fails a new connect with the same ones (WSAEADDRINUSE), where Linux
/// reuses them on loopback. As SIPp ignores a failed bind to -p, the
/// connection is then made again from any port, keeping what waits for
/// it. True if it is.
fn redial(conn: &mut Conn, e: &io::Error) -> bool {
    if !cfg!(windows) || !conn.from_port || e.raw_os_error() != Some(sys::EADDRINUSE) || !matches!(conn.stream, Stream::Plain(_)) {
        return false;
    }
    let dial = || -> io::Result<TcpStream> {
        let sock = Socket::new(Domain::for_address(conn.peer), Type::STREAM, Some(Protocol::TCP))?;
        sock.bind(&SocketAddr::new(conn.local.ip(), 0).into())?;
        sock.set_nonblocking(true)?;
        buffers(&sock)?;
        sock.set_tcp_nodelay(true)?;
        match sock.connect(&conn.peer.into()) {
            Err(e) if e.raw_os_error() != Some(sys::EINPROGRESS) => return Err(e),
            _ => {}
        }
        Ok(sock.into())
    };
    let Ok(tcp) = dial() else { return false };
    conn.local = tcp.local_addr().unwrap_or(conn.local);
    conn.stream = Stream::Plain(tcp);
    conn.from_port = false;
    true
}

/// A write on a socket whose connect is still in progress: EAGAIN on
/// Linux, but WSAENOTCONN on Windows, where the handshake waits for it too.
fn connecting(e: &io::Error) -> bool {
    cfg!(windows) && e.kind() == ErrorKind::NotConnected
}

/// rustls' handshake step: as far as the socket lets it go.
fn rustls_step<D>(conn: &mut rustls::ConnectionCommon<D>, sock: &mut TcpStream) -> Step {
    while conn.is_handshaking() {
        match conn.complete_io(sock) {
            Ok(_) => continue,
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted || connecting(&e) => {
                return Step::Wait(if conn.wants_write() { sys::POLLOUT } else { sys::POLLIN });
            }
            // SSL_ERROR_SYSCALL's strerror(), or OpenSSL's SSL_ERROR_SSL
            // (for a peer that hangs up too).
            Err(e) => {
                let why = match e.raw_os_error() {
                    Some(_) => os_error(&e),
                    None => "SSL protocol error. SSL I/O function returned SSL_ERROR_SSL".into(),
                };
                return Step::Failed(why, e.raw_os_error().unwrap_or(0));
            }
        }
    }
    while conn.wants_write() && conn.write_tls(sock).is_ok() {}
    Step::Done
}

/// ssl_handshake(): SSL_accept() or SSL_connect() until the handshake is
/// done, for at most `timeout` in all (zero: no limit), handling nothing
/// else meanwhile, as SIPp. Fails with SIPp's warning, and its errno.
fn handshake(stream: &mut Stream, timeout: Duration, accepting: bool) -> Result<(), (String, i32)> {
    let name = if accepting { "SSL_accept" } else { "SSL_connect" };
    let start = Instant::now();
    loop {
        let events = match stream.handshake_step() {
            Step::Done => return Ok(()),
            Step::Wait(events) => events,
            Step::Failed(why, errno) => return Err((format!("Error in {name}: {why}"), errno)),
        };
        let elapsed = start.elapsed();
        if !timeout.is_zero() && elapsed >= timeout {
            return Err((format!("Error in {name}: no handshake within {} ms", timeout.as_millis()), sys::EAGAIN));
        }
        let wait = if timeout.is_zero() { -1 } else { (timeout - elapsed).as_millis().max(1) as i32 };
        let mut pfd = sys::pollfd { fd: stream.raw_fd(), events, revents: 0 };
        // SAFETY: one pollfd, which outlives the call.
        unsafe { sys::poll(&mut pfd, 1, wait) };
        // A connect that failed: Windows' writes then only tell that the
        // socket is not connected (see connecting()), its error does.
        if cfg!(windows) && pfd.revents & (sys::POLLERR | sys::POLLHUP) != 0 {
            if let Some(Err(e)) = connect_state(stream.raw_fd(), true) {
                return Err((format!("Error in {name}: {}", os_error(&e)), e.raw_os_error().unwrap_or(0)));
            }
        }
    }
}

/// A client's server side without a certificate: no handshake succeeds.
#[derive(Debug)]
struct NoCertificate;

impl rustls::server::ResolvesServerCert for NoCertificate {
    fn resolve(&self, _: rustls::server::ClientHello) -> Option<Arc<rustls::sign::CertifiedKey>> {
        None
    }
}

/// With -tls_ca, SIPp's OpenSSL checks the server's chain, not its name
/// (it connects to addresses).
#[derive(Debug)]
struct ChainOnly(Arc<rustls::client::WebPkiServerVerifier>, Trusted);

impl ServerCertVerifier for ChainOnly {
    fn verify_server_cert(&self, end: &CertificateDer, chain: &[CertificateDer], name: &ServerName, ocsp: &[u8], now: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        match self.0.verify_server_cert(end, chain, name, ocsp, now) {
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName | rustls::CertificateError::NotValidForNameContext { .. })) => {
                Ok(ServerCertVerified::assertion())
            }
            Err(e) if self.1.holds(end, &e) => Ok(ServerCertVerified::assertion()),
            other => other,
        }
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(m, c, d)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(m, c, d)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

/// The -tls_ca certificates. OpenSSL takes a peer's certificate that the
/// file holds itself, as a self-signed one with CA:TRUE, which webpki
/// refuses as an end entity.
#[derive(Debug, Clone)]
struct Trusted(Vec<CertificateDer<'static>>);

impl Trusted {
    fn holds(&self, end: &CertificateDer, e: &rustls::Error) -> bool {
        matches!(e, rustls::Error::InvalidCertificate(rustls::CertificateError::Other(_))) && self.0.iter().any(|c| c.as_ref() == end.as_ref())
    }
}

/// With -tls_ca, a server's check of the client's certificate.
#[derive(Debug)]
struct ClientChain(Arc<dyn rustls::server::danger::ClientCertVerifier>, Trusted);

impl rustls::server::danger::ClientCertVerifier for ClientChain {
    fn offer_client_auth(&self) -> bool {
        self.0.offer_client_auth()
    }
    fn client_auth_mandatory(&self) -> bool {
        self.0.client_auth_mandatory()
    }
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        self.0.root_hint_subjects()
    }
    fn verify_client_cert(&self, end: &CertificateDer, chain: &[CertificateDer], now: UnixTime) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        match self.0.verify_client_cert(end, chain, now) {
            Err(e) if self.1.holds(end, &e) => Ok(rustls::server::danger::ClientCertVerified::assertion()),
            other => other,
        }
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(m, c, d)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(m, c, d)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

impl Tls {
    /// TLS_init_context(): our certificate and key (`ours`, None for a
    /// client without them), and verification with -tls_ca and -tls_crl.
    pub fn new(ours: Option<(&str, &str)>, server: bool, opts: &TlsOptions) -> Result<Tls, String> {
        if opts.ca.is_none() && opts.crl.is_some() {
            return Err("-tls_crl needs -tls_ca: the CRL is checked against its CA".into());
        }
        // legacy-tls: OpenSSL does 1.0 and 1.1, which rustls can't.
        #[cfg(feature = "legacy-tls")]
        if matches!(opts.version, Some(v) if v == 1.0 || v == 1.1) {
            let contexts = crate::tls_openssl::Contexts::new(ours, server, opts)?;
            return Ok(Tls { backend: Backend::OpenSsl(contexts), handshake_timeout: opts.handshake_timeout });
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let versions: &[&rustls::SupportedProtocolVersion] = match opts.version {
            None | Some(0.0) => rustls::DEFAULT_VERSIONS,
            Some(1.2) => &[&rustls::version::TLS12],
            Some(1.3) => &[&rustls::version::TLS13],
            Some(v) if v == 1.0 || v == 1.1 => return Err(format!("Old TLS version {v:.1} is no longer supported (build with --features legacy-tls)")),
            Some(v) => return Err(format!("Unrecognized TLS version: {v:.1}")),
        };
        let load_certs = |path: &str| -> Result<Vec<CertificateDer<'static>>, String> {
            CertificateDer::pem_file_iter(path)
                .map_err(|e| format!("TLS certificate {path}: {e}"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("TLS certificate {path}: {e}"))
        };
        let mut trusted = Trusted(Vec::new());
        let (roots, crls) = match (&opts.ca, &opts.crl) {
            (None, _) => (None, Vec::new()),
            (Some(ca), crl) => {
                let mut roots = rustls::RootCertStore::empty();
                trusted.0 = load_certs(ca)?;
                for c in trusted.0.clone() {
                    roots.add(c).map_err(|e| format!("TLS CA {ca}: {e}"))?;
                }
                let crls = match crl {
                    Some(path) => rustls::pki_types::CertificateRevocationListDer::pem_file_iter(path)
                        .map_err(|e| format!("TLS_init_context: Unable to load CRL file ({path}): {e}"))?
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|e| format!("TLS_init_context: Unable to load CRL file ({path}): {e}"))?,
                    None => Vec::new(),
                };
                (Some(Arc::new(roots)), crls)
            }
        };
        let builder = ClientConfig::builder_with_provider(provider.clone()).with_protocol_versions(versions).map_err(|e| e.to_string())?;
        let builder = match &roots {
            Some(roots) => {
                let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(roots.clone(), provider.clone())
                    .with_crls(crls.clone())
                    .build()
                    .map_err(|e| e.to_string())?;
                builder.dangerous().with_custom_certificate_verifier(Arc::new(ChainOnly(verifier, trusted.clone())))
            }
            None => builder.dangerous().with_custom_certificate_verifier(Arc::new(AnyCertificate(provider.clone()))),
        };
        // use_certificate(), in OpenSSL's words: the chain, then the key.
        const NO_KEY: &str = "TLS_init_context: SSL_CTX_use_PrivateKey_file failed";
        let ours = match ours {
            Some((cert, key)) => {
                let chain_failed = |why: String| format!("TLS_init_context: SSL_CTX_use_certificate_chain_file failed: {why}");
                let certs = match CertificateDer::pem_file_iter(cert) {
                    Err(rustls::pki_types::pem::Error::Io(e)) => Err(chain_failed(openssl_system_error(&e))),
                    Ok(iter) => iter.collect::<Result<Vec<_>, _>>().ok().filter(|c| !c.is_empty()).ok_or_else(|| chain_failed("error:0480006C:PEM routines::no start line".into())),
                    Err(_) => Err(chain_failed("error:0480006C:PEM routines::no start line".into())),
                }?;
                Some((certs, PrivateKeyDer::from_pem_file(key).map_err(|_| NO_KEY.to_string())?))
            }
            None => None,
        };
        let mut client = match &ours {
            Some((certs, k)) => builder.with_client_auth_cert(certs.clone(), k.clone_key()).map_err(|_| NO_KEY.to_string())?,
            None => builder.with_no_client_auth(),
        };
        client.key_log = Arc::new(rustls::KeyLogFile::new());
        // SIPp's OpenSSL client resumes no session: its server, which checks
        // client certificates with no session id context, fails one.
        client.resumption = rustls::client::Resumption::disabled();
        // A client accepts connections on its main socket too, with the
        // same certificate (SIPp's server SSL_CTX); without one, their
        // handshakes fail, as SIPp's SSL_accept() does.
        if server && ours.is_none() {
            return Err(NO_KEY.to_string());
        }
        let builder = ServerConfig::builder_with_provider(provider.clone()).with_protocol_versions(versions).map_err(|e| e.to_string())?;
        // With a CA, SIPp's server wants the client's certificate.
        let builder = match &roots {
            Some(roots) => builder.with_client_cert_verifier(Arc::new(ClientChain(
                rustls::server::WebPkiClientVerifier::builder_with_provider(roots.clone(), provider).with_crls(crls).build().map_err(|e| e.to_string())?,
                trusted,
            ))),
            None => builder.with_no_client_auth(),
        };
        let mut config = match ours {
            Some((certs, key)) => builder.with_single_cert(certs, key).map_err(|_| NO_KEY.to_string())?,
            None => builder.with_cert_resolver(Arc::new(NoCertificate)),
        };
        config.key_log = Arc::new(rustls::KeyLogFile::new());
        let server = Arc::new(config);
        Ok(Tls { backend: Backend::Rustls { client: Arc::new(client), server }, handshake_timeout: opts.handshake_timeout })
    }

    /// TLS over `tcp`, a connection to `to` or accepted (None), once its
    /// handshake is done; else SIPp's warning, and its errno.
    fn stream(&self, tcp: TcpStream, to: Option<IpAddr>) -> Result<Stream, (String, i32)> {
        let failed = |e: String| (e, 0);
        let mut stream = match (&self.backend, to) {
            (Backend::Rustls { client, .. }, Some(ip)) => {
                let conn = ClientConnection::new(client.clone(), ServerName::IpAddress(ip.into())).map_err(|e| failed(e.to_string()))?;
                Stream::Client(Box::new(StreamOwned::new(conn, tcp)))
            }
            (Backend::Rustls { server, .. }, None) => {
                Stream::Server(Box::new(StreamOwned::new(ServerConnection::new(server.clone()).map_err(|e| failed(e.to_string()))?, tcp)))
            }
            #[cfg(feature = "legacy-tls")]
            (Backend::OpenSsl(c), _) => Stream::OpenSsl(Box::new(c.stream(tcp, to.is_none()).map_err(failed)?)),
        };
        handshake(&mut stream, self.handshake_timeout, to.is_none())?;
        Ok(stream)
    }
}

struct Conn {
    stream: Stream,
    buf: Vec<u8>,
    peer: SocketAddr,
    local: SocketAddr,
    /// A server's, from its listener: the peer's to end.
    accepted: bool,
    /// A -t tn/ln/sn/wn client's call connection: the calls on it, which
    /// -max_socket makes more than one; and whether a <setdest> made it,
    /// which no other call shares.
    users: usize,
    changed_dest: bool,
    /// A TCP connect still in progress, and what was sent meanwhile: SIPp
    /// connects without waiting, and buffers until the socket is writable.
    connecting: bool,
    pending: Vec<String>,
    /// Made from -p: from another port if Windows refuses that (redial()).
    from_port: bool,
    /// The WebSocket of a WS or WSS connection.
    ws: Option<WebSocket>,
    /// A WebSocket's bytes that wait for the socket: its handshake, its
    /// replies, the frames held until it opened. Each is kept whole, with
    /// how much of the first the socket took, for a new connection to
    /// send it whole.
    out: VecDeque<Vec<u8>>,
    out_taken: usize,
    /// The pong to the last ping that came while `out` waited.
    pong: Vec<u8>,
    /// Its close frame, or a server's handshake error, to send once it ends.
    ws_close: Vec<u8>,
    /// When its handshake started, for -ws_handshake_timeout.
    ws_since: Option<Instant>,
}

impl Conn {
    /// Writes `msgs` whole: over SCTP one message each (RFC 4168 section
    /// 5.1), else all at once, and what the socket does not take waits.
    // ponytail: SCTP writes block; its messages cannot be split.
    fn write_msgs(&mut self, msgs: &[&str], sctp: bool) -> io::Result<()> {
        if !sctp {
            return self.queue(crate::raw::bytes(&msgs.concat()).to_vec());
        }
        let _ = self.stream.tcp().set_nonblocking(false);
        let r = msgs.iter().try_for_each(|m| self.stream.write_all(&crate::raw::bytes(m)));
        let _ = self.stream.tcp().set_nonblocking(true);
        r
    }

    /// Sends `data` after what waits, as far as the socket takes it; the
    /// rest waits for the poll to flush it, as SIPp's congested socket
    /// buffers it. A blocking write would deadlock two peers that both
    /// write more than the other reads.
    fn queue(&mut self, data: Vec<u8>) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        if self.waiting() {
            self.out.push_back(data);
            return self.flush_out();
        }
        let sent = match self.stream.write(&data) {
            Ok(0) => return Err(io::Error::from_raw_os_error(sys::EPIPE)),
            Ok(n) => n,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => 0,
            Err(e) => return Err(e),
        };
        self.stream.flush_tls();
        if sent < data.len() {
            self.out.push_back(data);
            self.out_taken = sent;
        }
        Ok(())
    }

    /// Does something wait to be written?
    fn waiting(&self) -> bool {
        !self.out.is_empty() || !self.pong.is_empty() || self.stream.tls_waiting()
    }

    /// flush(): what waits, as far as the socket takes it, then the pong.
    fn flush_out(&mut self) -> io::Result<()> {
        loop {
            self.stream.flush_tls();
            let Some(first) = self.out.front() else {
                if self.pong.is_empty() {
                    return Ok(());
                }
                self.out.push_back(std::mem::take(&mut self.pong));
                continue;
            };
            match self.stream.write(&first[self.out_taken..]) {
                Ok(0) => return Err(io::Error::from_raw_os_error(sys::EPIPE)),
                Ok(n) => {
                    self.out_taken += n;
                    if self.out_taken == first.len() {
                        self.out.pop_front();
                        self.out_taken = 0;
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(()),
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// ws_reply(): a WebSocket's own frame, or a server's handshake answer,
    /// now unless other data waits. An error is not a SIP message's: the
    /// reads find out whether the connection is gone.
    fn ws_reply(&mut self, reply: &[u8]) {
        let mut sent = 0;
        if !self.waiting() {
            match self.stream.write(reply) {
                Ok(n) => sent = n,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(_) => return,
            }
            self.stream.flush_tls();
        }
        // Whole, as write() does: when some went, nothing waited before.
        if sent < reply.len() {
            self.out.push_back(reply.to_vec());
            self.out_taken = sent;
        }
    }

    /// What it did not take, for a new connection: the messages buffered
    /// while it connected, or a WebSocket's frames (those in its output,
    /// each whole, once its handshake was done, and then those held).
    fn unsent(self) -> Unsent {
        let mut frames = Vec::new();
        if let Some(ws) = &self.ws {
            if ws.is_open() {
                frames = self.out.iter().flatten().copied().collect();
            }
            frames.extend_from_slice(&ws.held);
        }
        Unsent { msgs: self.pending, frames }
    }
}

/// What a failed connection did not take, which its reconnection sends.
#[derive(Default)]
pub struct Unsent {
    msgs: Vec<String>,
    frames: Vec<u8>,
}

impl Unsent {
    fn is_empty(&self) -> bool {
        self.msgs.is_empty() && self.frames.is_empty()
    }

    fn append(&mut self, mut more: Unsent) {
        self.msgs.append(&mut more.msgs);
        self.frames.append(&mut more.frames);
    }
}

/// The local address a connection to `to` goes out from.
#[cfg(windows)]
fn route_source(to: SocketAddr) -> Option<IpAddr> {
    let any: SocketAddr = if to.is_ipv4() { (std::net::Ipv4Addr::UNSPECIFIED, 0).into() } else { (std::net::Ipv6Addr::UNSPECIFIED, 0).into() };
    let s = UdpSocket::bind(any).ok()?;
    s.connect(to).ok()?;
    Some(s.local_addr().ok()?.ip())
}

/// Where a non-blocking connect stands: None while it is in progress.
/// Its error is only taken (and so cleared) with `take`.
pub fn connect_state(fd: RawFd, take: bool) -> Option<io::Result<()>> {
    let mut pfd = sys::pollfd { fd, events: sys::POLLOUT, revents: 0 };
    // SAFETY: one pollfd, which outlives the call.
    if unsafe { sys::poll(&mut pfd, 1, 0) } <= 0 {
        return None;
    }
    if pfd.revents & (sys::POLLERR | sys::POLLHUP) == 0 {
        return Some(Ok(()));
    }
    let mut err: libc::c_int = sys::ECONNREFUSED;
    if take {
        let mut len = std::mem::size_of::<libc::c_int>() as sys::socklen_t;
        // SAFETY: SO_ERROR writes one int, which `err` and `len` describe.
        unsafe { sys::getsockopt(fd, sys::SOL_SOCKET, sys::SO_ERROR, (&mut err as *mut libc::c_int).cast(), &mut len) };
        // A hang-up without an error is a peer that closed at once, after
        // the connect: its read tells (Windows' poll says so with POLLHUP).
        if err == 0 {
            return Some(Ok(()));
        }
    }
    Some(Err(io::Error::from_raw_os_error(err)))
}

/// A connection that ended: closed, or reset by the peer when we had
/// accepted it, which ends it the same way as nothing reconnects it.
#[derive(Clone, Copy, Debug)]
pub struct Closed {
    pub conn: ConnId,
    pub reset: bool,
    pub accepted: bool,
}

pub struct Received {
    pub msg: Arc<str>,
    pub from: Peer,
}

pub struct Net {
    pub transport: Transport,
    udp: Option<UdpSocket>,
    /// The main socket of a reliable transport, bound, until listen().
    main: Option<Socket>,
    listener: Option<TcpListener>,
    conns: HashMap<ConnId, Conn>,
    /// Connections the peer closed since the engine last looked.
    pub closed: Vec<Closed>,
    /// Connections that failed (a reset, a broken pipe), with SIPp's words
    /// for it: SIPp reconnects those, or ends.
    pub resets: Vec<(ConnId, String)>,
    /// What those connections had buffered, as SIPp's ss_out stays with
    /// the socket for its reconnection.
    unsent: HashMap<ConnId, Unsent>,
    /// -reconnect_close false: a client connection that failed keeps the
    /// scenario messages written to it until it is made again (keep()).
    pub keep: bool,
    /// The failed send was kept so: Some(whether it is traced as sent
    /// now, as a WebSocket's frame is).
    pub kept: Option<bool>,
    next_conn: ConnId,
    /// The one connection of a -t t1 client.
    shared: Option<ConnId>,
    bind_ip: IpAddr,
    /// The port a -t t1/l1/w1/s1 connection is bound to: -p (the main
    /// socket's, SCTP's with or without it), which listen() then takes
    /// from a reconnection.
    pub bind_port: u16,
    pub tls: Option<Tls>,
    /// -t un / ui: the calls' UDP sockets and how many calls use each.
    udp_calls: HashMap<ConnId, (UdpSocket, usize)>,
    /// -t ui: the socket of each local IP, kept for the run.
    per_ip: HashMap<IpAddr, ConnId>,
    /// -max_socket: past this many call sockets, calls share them in turn.
    pub max_sockets: usize,
    /// The control, stdin and 3PCC sockets, for the open sockets count.
    pub other_sockets: usize,
    next_shared: usize,
    sctp: SctpOptions,
    /// What SIPp would only warn about, for the engine to log.
    pub warnings: Vec<String>,
    /// Messages buffered while connecting, now written whole: SIPp's
    /// flush() traces them as sent only then.
    pub written: Vec<String>,
    /// SIPp's TRACE_MSG() notes, for the -trace_msg file.
    pub traces: Vec<String>,
    /// The screen's "errors (send/recv/cong)": the writes and reads that
    /// failed, as SIPp's write_error() and read_error() count them.
    pub send_errors: u64,
    /// The failed send was never attempted, and is not traced as failed.
    pub held_back: bool,
    pub recv_errors: u64,
    /// -ws_path, and -ws_handshake_timeout (zero: no limit).
    pub ws_path: String,
    pub ws_timeout: Duration,
    /// The Host of a WebSocket client's handshake: the remote host SIPp
    /// calls, and its port; else, or for a call that went elsewhere, the
    /// address it connects to.
    pub ws_host: Option<String>,
    /// -max_recv_loops: the datagrams one poll reads at most.
    pub recv_loops: usize,
    /// The address the UDP socket or the main socket is bound to.
    local: Option<SocketAddr>,
}

/// A whole SIP message at the start of `buf`: its length, or None while
/// more bytes are needed. Keep-alive CRLFs before it are skipped.
fn frame(buf: &[u8]) -> Option<(usize, usize)> {
    let start = buf.iter().position(|&b| b != b'\r' && b != b'\n')?;
    let head_end = buf[start..].windows(4).position(|w| w == b"\r\n\r\n")? + start + 4;
    let head = String::from_utf8_lossy(&buf[start..head_end]);
    let len = head
        .split("\r\n")
        .filter_map(|l| l.split_once(':'))
        .find(|(n, _)| n.trim().eq_ignore_ascii_case("Content-Length") || n.trim().eq_ignore_ascii_case("l"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    (buf.len() >= head_end + len).then_some((start, head_end + len))
}

impl Net {
    /// Binds the local socket: UDP, or for TCP, TLS, WebSocket and SCTP
    /// SIPp's main socket, in any mode, which listen() makes a listener:
    /// a server's at once.
    pub fn bind(transport: Transport, local: SocketAddr, server: bool, tls: Option<Tls>, sctp: SctpOptions) -> io::Result<Net> {
        let mut net = Net { tls, ..Net::unbound(transport, local, sctp) };
        match transport {
            Transport::Udp | Transport::UdpMulti | Transport::UdpPerIp => {
                let s = UdpSocket::bind(local)?;
                s.set_nonblocking(true)?;
                buffers(&s)?;
                net.local = s.local_addr().ok();
                net.udp = Some(s);
            }
            t => {
                let s = match t.sctp() {
                    true => sctp.socket(Domain::for_address(local))?,
                    false => Socket::new(Domain::for_address(local), Type::STREAM, Some(Protocol::TCP))?,
                };
                // SO_REUSEADDR, as sipp_customize_socket() and std's
                // TcpListener::bind() set it; not on Windows, where it
                // would let another socket take the port.
                #[cfg(unix)]
                s.set_reuse_address(true)?;
                s.bind(&local.into())?;
                if t.sctp() {
                    if let Err(e) = sctp.multihome(&s, s.local_addr()?.as_socket().map_or(0, |a| a.port())) {
                        net.warnings.push(format!("Can't bind to multihome address, errno='{}'", e.raw_os_error().unwrap_or(0)));
                    }
                }
                buffers(&s)?;
                // Known once bound: each message's keywords ask for it.
                net.local = s.local_addr()?.as_socket();
                net.main = Some(s);
                if server {
                    net.listen()?;
                }
            }
        }
        Ok(net)
    }

    /// listen() on the main socket, which SIPp does once a -t t1/l1/s1/w1
    /// client's connection is made (from its port, see bind_port): its
    /// connections are then accepted, in any mode.
    pub fn listen(&mut self) -> io::Result<()> {
        let Some(s) = self.main.take() else { return Ok(()) };
        s.listen(100)?;
        let l: TcpListener = s.into();
        l.set_nonblocking(true)?;
        self.listener = Some(l);
        Ok(())
    }

    /// open_connections()'s main_socket->close() when the single
    /// connection fails with a reconnection left: nothing listens.
    pub fn close_main(&mut self) {
        self.main = None;
    }

    /// No socket yet: what a setup that failed shows.
    pub fn unbound(transport: Transport, local: SocketAddr, sctp: SctpOptions) -> Net {
        Net {
            transport,
            udp: None,
            main: None,
            listener: None,
            conns: HashMap::new(),
            closed: Vec::new(),
            resets: Vec::new(),
            next_conn: 1,
            shared: None,
            bind_ip: local.ip(),
            bind_port: 0,
            tls: None,
            udp_calls: HashMap::new(),
            recv_loops: 1000,
            local: None,
            per_ip: HashMap::new(),
            max_sockets: 50000,
            other_sockets: 0,
            next_shared: 0,
            sctp,
            warnings: Vec::new(),
            written: Vec::new(),
            traces: Vec::new(),
            send_errors: 0,
            held_back: false,
            recv_errors: 0,
            ws_path: "/".into(),
            ws_timeout: Duration::from_secs(10),
            ws_host: None,
            unsent: HashMap::new(),
            keep: false,
            kept: None,
        }
    }

    /// -bind_to_device: the main socket takes that interface only, as
    /// Linux alone can.
    #[cfg(not(target_os = "linux"))]
    pub fn bind_device(&self, _name: &str) -> io::Result<()> {
        Err(io::Error::from(ErrorKind::Unsupported))
    }

    #[cfg(target_os = "linux")]
    pub fn bind_device(&self, name: &str) -> io::Result<()> {
        let fd = match (&self.udp, &self.main, &self.listener) {
            (Some(u), _, _) => u.as_raw_fd(),
            (_, Some(s), _) => s.as_raw_fd(),
            (_, _, Some(l)) => l.as_raw_fd(),
            _ => return Ok(()),
        };
        // SAFETY: the name's bytes are valid for their length.
        let r = unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_BINDTODEVICE, name.as_ptr().cast(), name.len() as libc::socklen_t) };
        if r == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local
    }

    /// SIPp's pollnfds: the UDP socket or TCP listener, connections, and
    /// the control and stdin sockets.
    pub fn open_sockets(&self) -> usize {
        1 + self.conns.len() + self.udp_calls.len() + self.other_sockets
    }

    /// The local port a call's messages show in [local_port]: for a -t
    /// tn/ln/sn client's connection or a call's UDP socket, its own; else
    /// SIPp's main port, even where a -t t1 client connects from another.
    pub fn local_port(&self, peer: &Peer, default: u16) -> u16 {
        let Some(c) = peer.conn else { return default };
        if let Some((u, _)) = self.udp_calls.get(&c) {
            return u.local_addr().map_or(default, |a| a.port());
        }
        match self.conns.get(&c) {
            Some(conn) if !self.transport.single() && !conn.accepted => conn.local.port(),
            _ => default,
        }
    }

    /// [server_ip]: the local address of the socket a call uses.
    pub fn local_ip(&self, peer: &Peer) -> Option<IpAddr> {
        if let Some(c) = peer.conn {
            if let Some((u, _)) = self.udp_calls.get(&c) {
                return u.local_addr().ok().map(|a| a.ip());
            }
            if let Some(conn) = self.conns.get(&c) {
                return Some(conn.local.ip());
            }
        }
        self.local_addr().map(|a| a.ip())
    }

    /// connect_socket_if_needed() for UDP: a -t un call's socket on an
    /// ephemeral port (shared once -max_socket are open), or -t ui's for
    /// `ip`, on our port.
    pub fn udp_call_socket(&mut self, ip: Option<IpAddr>) -> io::Result<Option<ConnId>> {
        let main = self.udp.as_ref().and_then(|u| u.local_addr().ok());
        let port = main.map_or(0, |a| a.port());
        if let Some(ip) = ip {
            // The main socket is the first IP's, as SIPp binds it there.
            if main.is_some_and(|m| m.ip() == ip) {
                return Ok(None);
            }
            if let Some(&id) = self.per_ip.get(&ip) {
                self.udp_calls.get_mut(&id).unwrap().1 += 1;
                return Ok(Some(id));
            }
            let id = self.new_udp(SocketAddr::new(ip, port))?;
            // The map holds it too, so it outlives its calls.
            self.udp_calls.get_mut(&id).unwrap().1 += 1;
            self.per_ip.insert(ip, id);
            return Ok(Some(id));
        }
        // Only call sockets count, not the main, control or stdin ones.
        if self.udp_calls.len() >= self.max_sockets {
            if self.udp_calls.is_empty() {
                return Err(io::Error::other(NoCallSocket));
            }
            let mut ids: Vec<ConnId> = self.udp_calls.keys().copied().collect();
            ids.sort_unstable();
            let id = ids[self.next_shared % ids.len()];
            self.next_shared += 1;
            self.udp_calls.get_mut(&id).unwrap().1 += 1;
            return Ok(Some(id));
        }
        self.new_udp(SocketAddr::new(self.bind_ip, 0)).map(Some)
    }

    /// A -t ui server listens on every IP of the file too.
    pub fn listen_on(&mut self, ips: &[IpAddr]) -> io::Result<()> {
        for &ip in ips {
            self.udp_call_socket(Some(ip))?;
        }
        Ok(())
    }

    fn new_udp(&mut self, at: SocketAddr) -> io::Result<ConnId> {
        let s = UdpSocket::bind(at)?;
        s.set_nonblocking(true)?;
        buffers(&s)?;
        let id = self.next_conn;
        self.next_conn += 1;
        self.udp_calls.insert(id, (s, 1));
        Ok(id)
    }

    /// For a TCP client call: the connection to use, opening it if needed.
    pub fn connect(&mut self, to: SocketAddr) -> io::Result<Option<ConnId>> {
        // new_sipp_call_socket(): past -max_socket call connections, a call
        // shares one in turn, not one a <setdest> made.
        if self.transport.per_call() && !self.transport.udp() && self.call_conns().count() >= self.max_sockets {
            let mut ids: Vec<ConnId> = self.call_conns().filter(|(_, c)| !c.changed_dest).map(|(&id, _)| id).collect();
            if ids.is_empty() {
                return Err(io::Error::other(NoCallSocket));
            }
            ids.sort_unstable();
            let id = ids[self.next_shared % ids.len()];
            self.next_shared += 1;
            self.conns.get_mut(&id).unwrap().users += 1;
            return Ok(Some(id));
        }
        self.connect_host(to, false)
    }

    /// A call's hold on another call's connection (-t tn/ln/sn/wn), which
    /// close() lets go of: true if it is one.
    pub fn hold(&mut self, conn: ConnId) -> bool {
        match self.conns.get_mut(&conn).filter(|c| c.users > 0) {
            Some(c) => {
                c.users += 1;
                true
            }
            None => false,
        }
    }

    /// The call connections of a -t tn/ln/sn/wn client.
    fn call_conns(&self) -> impl Iterator<Item = (&ConnId, &Conn)> {
        self.conns.iter().filter(|(_, c)| c.users > 0)
    }

    /// Is the connection still there (its socket's ss_fd not -1)?
    pub fn is_open(&self, conn: ConnId) -> bool {
        self.conns.contains_key(&conn)
    }

    /// How many calls use a connection.
    pub fn users(&self, conn: ConnId) -> usize {
        self.conns.get(&conn).map_or(0, |c| c.users)
    }

    /// reconnect(): a call connection made again for the calls that were
    /// on it, whatever -max_socket says.
    pub fn reconnect_call(&mut self, to: SocketAddr, users: usize) -> io::Result<Option<ConnId>> {
        let id = self.connect_host(to, false)?;
        if let Some(c) = id.and_then(|id| self.conns.get_mut(&id)) {
            c.users = users.max(1);
        }
        Ok(id)
    }

    /// connect() for a call that <setdest> sent elsewhere.
    pub fn connect_elsewhere(&mut self, to: SocketAddr) -> io::Result<Option<ConnId>> {
        self.connect_host(to, true)
    }

    fn connect_host(&mut self, to: SocketAddr, changed_dest: bool) -> io::Result<Option<ConnId>> {
        let warned = self.warnings.len();
        match self.dial(to, changed_dest, true) {
            // A TLS connection's handshake is done here: from another
            // port, without the first try's warning, as redial() does for
            // the others.
            Err(e) if cfg!(windows) && e.get_ref().and_then(|e| e.downcast_ref::<HandshakeFailed>()).is_some_and(|h| h.0 == sys::EADDRINUSE) => {
                self.warnings.truncate(warned);
                self.dial(to, changed_dest, false)
            }
            r => r,
        }
    }

    /// connect_host(), from -p (if `from_port`) or any port.
    fn dial(&mut self, to: SocketAddr, changed_dest: bool, from_port: bool) -> io::Result<Option<ConnId>> {
        match self.transport {
            Transport::Udp | Transport::UdpPerIp => Ok(None),
            Transport::UdpMulti => self.udp_call_socket(None),
            // The one connection, even once the peer closed it: SIPp's
            // tcp_multiplex stays, invalid, for a send's EPIPE to reset it.
            t if t.single() && self.shared.is_some() => Ok(self.shared),
            t => {
                let sock = match t.sctp() {
                    true => self.sctp.socket(Domain::for_address(to))?,
                    false => Socket::new(Domain::for_address(to), Type::STREAM, Some(Protocol::TCP))?,
                };
                // Windows gives no local address of a socket bound to the
                // unspecified one until its connect is done: the address
                // the connect takes, as a UDP socket's route tells.
                #[cfg(windows)]
                let bind_ip = match self.bind_ip.is_unspecified() {
                    true => route_source(to).unwrap_or(self.bind_ip),
                    false => self.bind_ip,
                };
                #[cfg(not(windows))]
                let bind_ip = self.bind_ip;
                // A failed bind is warned about, as SIPp does, and the
                // connection goes on: from any port of our address (SIPp
                // leaves the address to the kernel, which -i then doesn't
                // name), or unbound when that fails too.
                let bind_to = |port: u16| sock.bind(&SocketAddr::new(bind_ip, port).into());
                let to_port = from_port && self.bind_port != 0 && sock.set_reuse_address(true).is_ok();
                let bound = match bind_to(if to_port { self.bind_port } else { 0 }) {
                    Ok(()) => to_port,
                    Err(e) => {
                        self.warnings.push(format!("Unable to bind socket {} before connecting it, errno = {} ({})", sock.as_raw_fd(), e.raw_os_error().unwrap_or(0), os_error(&e)));
                        if to_port {
                            let _ = bind_to(0);
                        }
                        false
                    }
                };
                if t.sctp() {
                    let port = sock.local_addr()?.as_socket().map_or(0, |a| a.port());
                    if let Err(e) = self.sctp.multihome(&sock, port) {
                        self.warnings.push(format!("Can't bind to multihome address, errno='{}'", e.raw_os_error().unwrap_or(0)));
                    }
                }
                // As SIPp: a TCP, TLS or SCTP connect in progress counts as
                // done, its failure showing on the socket later (a TLS one
                // in the handshake that follows). What the calls send waits
                // for it (SCTP_CONNECTING), the association's options too.
                let mut connecting = false;
                sock.set_nonblocking(true)?;
                buffers(&sock)?;
                // Before the connect: Windows takes no option on a socket
                // whose connect (refused on loopback, at once) failed.
                if !t.sctp() {
                    sock.set_tcp_nodelay(true)?;
                }
                match sock.connect(&to.into()) {
                    Ok(()) => {}
                    Err(e) if e.raw_os_error() == Some(sys::EINPROGRESS) => connecting = !t.tls(),
                    Err(e) => return Err(e),
                }
                let tcp: TcpStream = sock.into();
                if t.sctp() && !connecting {
                    let w = self.sctp.up(&tcp);
                    self.warnings.extend(w);
                }
                tcp.set_nonblocking(true)?;
                let stream = match &self.tls {
                    Some(tls) if t.tls() => tls.stream(tcp, Some(to.ip())).map_err(|(warning, errno)| {
                        self.warnings.push(warning);
                        io::Error::other(HandshakeFailed(errno))
                    })?,
                    _ => Stream::Plain(tcp),
                };
                let id = self.add(stream, false, Some(to))?;
                let host = match &self.ws_host {
                    Some(h) if !changed_dest => h.clone(),
                    _ => to.to_string(),
                };
                if let Some(c) = self.conns.get_mut(&id) {
                    c.connecting = connecting;
                    c.from_port = bound && !t.sctp();
                    if !t.single() {
                        (c.users, c.changed_dest) = (1, changed_dest);
                    }
                    // ws_connect(): the handshake first, which the SIP
                    // messages wait for.
                    if t.ws() {
                        let mut ws = WebSocket::new(false, WS_MAX_MESSAGE);
                        let request = ws.request(&host, &self.ws_path);
                        self.traces.push(format!("WebSocket handshake on socket {}:\n\n{request}", c.stream.raw_fd()));
                        c.out = VecDeque::from([request.into_bytes()]);
                        c.ws = Some(ws);
                        c.ws_since = Some(Instant::now());
                    }
                }
                if t.single() {
                    self.shared = Some(id);
                }
                Ok(Some(id))
            }
        }
    }

    /// A connection, to `to` when it may still be connecting.
    /// What a connection that failed had buffered.
    pub fn take_unsent(&mut self, conn: ConnId) -> Unsent {
        self.unsent.remove(&conn).unwrap_or_default()
    }

    /// Keeps what a connection that failed did not take, for its
    /// reconnection.
    fn stash(&mut self, id: ConnId, conn: Conn) {
        let unsent = conn.unsent();
        if !unsent.is_empty() {
            self.unsent.entry(id).or_default().append(unsent);
        }
    }

    /// The messages a failed connection had buffered, now for its
    /// reconnection, which writes them once it is made: a WebSocket's
    /// once its handshake is done (resume_calls()).
    pub fn requeue(&mut self, conn: ConnId, unsent: Unsent) {
        let Some(c) = self.conns.get_mut(&conn) else { return };
        if let Some(ws) = c.ws.as_mut() {
            ws.held.splice(0..0, unsent.frames);
        }
        if !unsent.msgs.is_empty() {
            c.pending.splice(0..0, unsent.msgs);
            // The poll writes them once it can; an SCTP association is
            // up already only when its connect was, and the next send
            // writes them then.
            c.connecting |= !self.transport.sctp();
        }
    }

    /// all_written(): did the connection take all that was written to it,
    /// nothing waiting, and is it up? A UDP socket always does.
    pub fn all_written(&self, conn: Option<ConnId>) -> bool {
        let Some(id) = conn else { return self.transport.udp() };
        match self.conns.get(&id) {
            Some(c) => c.pending.is_empty() && !c.waiting() && c.ws.as_ref().is_none_or(|ws| ws.held.is_empty()),
            None => self.udp_calls.contains_key(&id),
        }
    }

    /// A shared connection that failed to open: there, but invalid.
    pub fn invalidate_shared(&mut self) {
        self.shared = Some(self.next_conn);
        self.next_conn += 1;
    }

    /// reset_connection()'s reconnect(): the shared connection anew. A
    /// failure leaves the old one there, invalid.
    pub fn reconnect(&mut self, to: SocketAddr) -> io::Result<Option<ConnId>> {
        let old = self.shared.take();
        self.connect(to).inspect_err(|_| self.shared = old)
    }

    fn add(&mut self, stream: Stream, accepted: bool, to: Option<SocketAddr>) -> io::Result<ConnId> {
        let id = self.next_conn;
        self.next_conn += 1;
        let peer = match to {
            Some(to) => to,
            None => stream.tcp().peer_addr()?,
        };
        let local = stream.tcp().local_addr()?;
        // A server waits for the client's WebSocket handshake.
        let ws = (self.transport.ws() && accepted).then(|| WebSocket::new(true, WS_MAX_MESSAGE));
        let ws_since = ws.as_ref().map(|_| Instant::now());
        let conn = Conn {
            stream,
            buf: Vec::new(),
            peer,
            local,
            accepted,
            users: 0,
            changed_dest: false,
            connecting: false,
            pending: Vec::new(),
            from_port: false,
            ws,
            out: VecDeque::new(),
            out_taken: 0,
            pong: Vec::new(),
            ws_close: Vec::new(),
            ws_since,
        };
        self.conns.insert(id, conn);
        Ok(id)
    }

    /// Closes a connection, as a -t tn client does when its call ends; a
    /// UDP call socket once no call uses it.
    pub fn close(&mut self, conn: ConnId) {
        if let Some((_, users)) = self.udp_calls.get_mut(&conn) {
            *users -= 1;
            if *users == 0 {
                self.udp_calls.remove(&conn);
            }
            return;
        }
        // A call connection that other calls share stays for them.
        if let Some(c) = self.conns.get_mut(&conn).filter(|c| c.users > 1) {
            c.users -= 1;
            return;
        }
        // A WebSocket ends with a close frame, or with the one it has yet
        // to send, unless something is in its way.
        if let Some(mut c) = self.conns.remove(&conn) {
            if let Some(ws) = c.ws.as_ref().filter(|_| !c.waiting()) {
                let frame = if ws.is_open() && !ws.is_closed() { ws.close_frame(1000) } else { std::mem::take(&mut c.ws_close) };
                if !frame.is_empty() {
                    let _ = c.stream.write(&frame);
                    c.stream.flush_tls();
                }
            }
            // invalidate(): a TCP or WS connection is shut down, a FIN
            // for the peer's unread data, not the reset that closing
            // with it would send.
            if let (Stream::Plain(s), false) = (&c.stream, self.transport.sctp()) {
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
        }
    }

    /// The traffic loop's end: SIPp closes its sockets, the last opened
    /// first.
    pub fn close_all(&mut self) {
        let mut ids: Vec<ConnId> = self.conns.keys().copied().collect();
        ids.sort_unstable_by(|a, b| b.cmp(a));
        for id in ids {
            self.close(id);
        }
    }

    /// Sends `msg`; a failed write on a connection ends it, as in SIPp,
    /// and the error is returned as SIPp's WARNING_NO() prints it. False
    /// for a message buffered while connecting, which is in `written`
    /// once it is. A scenario message (`keep`, SIPp's WS_KEEP) that a
    /// client connection fails to take waits for its reconnection with
    /// -reconnect_close false, `kept` telling.
    pub fn send(&mut self, msg: &str, to: &Peer, keep: bool) -> Result<bool, String> {
        let wire = crate::raw::bytes(msg);
        if let Some((u, _)) = to.conn.and_then(|c| self.udp_calls.get(&c)) {
            let _ = u.send_to(&wire, to.addr);
            return Ok(true);
        }
        match (&self.udp, to.conn) {
            // UDP: a failed send is a lost packet, which retransmission covers.
            (Some(u), _) => {
                let _ = u.send_to(&wire, to.addr);
            }
            (None, Some(c)) => {
                let failed = match self.conns.get_mut(&c) {
                    // A WebSocket sends each message in a frame, held until
                    // the server takes the handshake, and traced now.
                    Some(conn) if conn.ws.is_some() => {
                        let ws = conn.ws.as_mut().unwrap();
                        let frame = ws.frame(&wire);
                        if !ws.is_open() {
                            // Up to a bound: with no -ws_handshake_timeout, a
                            // server that never answers would make it grow
                            // without end. The message is then not sent, as
                            // when the connection is full.
                            if ws.held.len() + frame.len() > WS_HELD_MAX {
                                if !ws.held_full {
                                    self.warnings.push(format!(
                                        "No WebSocket handshake answer yet, and {} bytes wait for it: not sending more on this {} connection",
                                        ws.held.len(),
                                        self.transport.name()
                                    ));
                                    ws.held_full = true;
                                }
                                self.held_back = true;
                                let e = io::Error::from_raw_os_error(sys::ENOBUFS);
                                return Err(format!("errno = {} ({})", sys::ENOBUFS, os_error(&e)));
                            }
                            ws.held.extend_from_slice(&frame);
                            return Ok(true);
                        }
                        // What waits goes first, then the pong; kept, should
                        // the connection fail, for a new one.
                        let mut data: Vec<u8> = conn.out.iter().flatten().skip(conn.out_taken).copied().collect();
                        data.extend_from_slice(&conn.pong);
                        data.extend_from_slice(&frame);
                        // What the socket does not take waits, whole, in
                        // its output; a failure leaves the output as it was.
                        let sent = match conn.stream.write(&data) {
                            Ok(0) => Err(io::Error::from_raw_os_error(sys::EPIPE)),
                            Ok(n) => Ok(n),
                            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => Ok(0),
                            Err(e) => Err(e),
                        };
                        match sent {
                            Ok(n) => {
                                conn.stream.flush_tls();
                                conn.pong.clear();
                                conn.out = VecDeque::new();
                                conn.out_taken = 0;
                                if n < data.len() {
                                    conn.out.push_back(data);
                                    conn.out_taken = n;
                                }
                                None
                            }
                            Err(e) => Some(e),
                        }
                    }
                    // Still connecting (or failed to, which the poll finds):
                    // buffered, as SIPp's congested socket.
                    Some(conn) if conn.connecting && !matches!(connect_state(conn.stream.raw_fd(), false), Some(Ok(()))) => {
                        conn.pending.push(msg.to_string());
                        return Ok(false);
                    }
                    Some(conn) => {
                        if conn.connecting && self.transport.sctp() {
                            self.warnings.extend(self.sctp.up(conn.stream.tcp()));
                        }
                        conn.connecting = false;
                        let pending = std::mem::take(&mut conn.pending);
                        let mut msgs: Vec<&str> = pending.iter().map(String::as_str).collect();
                        msgs.push(msg);
                        let r = conn.write_msgs(&msgs, self.transport.sctp()).err();
                        match r {
                            None => self.written.extend(pending),
                            // For the reconnection, should the error reset it.
                            Some(_) => conn.pending = pending,
                        }
                        r
                    }
                    // SIPp writes to the closed socket, and gets EPIPE; over
                    // TLS, one we accepted only warns, with what OpenSSL
                    // has for it.
                    None => {
                        self.warnings.push(format!("Returning EPIPE on invalid socket: {:p} (-1)", self as *const Net));
                        if self.transport.tls() && self.closed.iter().any(|x| x.conn == c && x.accepted) {
                            self.send_errors += 1;
                            self.warnings.push(format!("Unable to send {} message: No error", self.transport.name()));
                            return Err(format!("errno = {} ({})", sys::EPIPE, os_error(&io::Error::from_raw_os_error(sys::EPIPE))));
                        }
                        Some(io::Error::from_raw_os_error(sys::EPIPE))
                    }
                };
                if let Some(e) = failed {
                    self.send_errors += 1;
                    let conn = self.conns.remove(&c);
                    // One the poll that read this call's message found closed
                    // is still the peer's, whose close the engine has yet to
                    // see.
                    let gone = self.closed.iter().any(|x| x.conn == c && x.accepted);
                    let accepted = conn.as_ref().map_or(gone, |c| c.accepted);
                    let tcp = !self.transport.tls() && !self.transport.sctp();
                    // SIPp's write error paths. A connection we accepted is
                    // the peer's to end, closed or reset: its calls end, as
                    // when the peer closes it. (Windows' broken pipe is
                    // WSAECONNABORTED.)
                    if accepted && tcp && matches!(e.kind(), ErrorKind::BrokenPipe | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted) {
                        if !gone {
                            self.closed.push(Closed { conn: c, reset: false, accepted });
                        }
                    } else if let Some(why) = write_reset(&e, self.transport, accepted) {
                        // What was buffered before this message waits for
                        // the reconnection; this one failed, but for keep():
                        // then it waits too, a WebSocket's frame traced now.
                        if let Some(conn) = conn {
                            self.stash(c, conn);
                        }
                        if keep && self.keep && !accepted {
                            let unsent = self.unsent.entry(c).or_default();
                            match self.transport.ws() {
                                true => unsent.frames.extend(WebSocket::new(false, WS_MAX_MESSAGE).frame(&wire)),
                                false => unsent.msgs.push(msg.to_string()),
                            }
                            self.kept = Some(self.transport.ws());
                        }
                        // Reset once, as SIPp's sockets_pending_reset.
                        match self.resets.iter().any(|(id, _)| *id == c) {
                            true => self.warnings.push(why),
                            false => self.resets.push((c, why)),
                        }
                    } else {
                        self.warnings.push(format!("Unable to send {} message: {}", self.transport.name(), os_error(&e)));
                        self.closed.push(Closed { conn: c, reset: false, accepted });
                    }
                    return Err(format!("errno = {} ({})", e.raw_os_error().unwrap_or(0), os_error(&e)));
                }
            }
            (None, None) => {}
        }
        Ok(true)
    }

    /// check_ws_handshakes(): drop the connections whose WebSocket
    /// handshake took too long. A server's client sent no request: it goes.
    /// A client got no answer: its connection failed, and is made again if
    /// -max_reconnect allows, as when a TCP one fails.
    fn check_ws_handshakes(&mut self) {
        if self.ws_timeout.is_zero() {
            return;
        }
        let timeout = self.ws_timeout;
        let expired: Vec<ConnId> = self.conns.iter().filter(|(_, c)| c.ws_since.is_some_and(|t| t.elapsed() >= timeout)).map(|(&id, _)| id).collect();
        for id in expired {
            let conn = self.conns.remove(&id).unwrap();
            if conn.accepted {
                self.warnings.push(format!("No WebSocket handshake request within {} ms, closing the {} connection", timeout.as_millis(), self.transport.name()));
                self.closed.push(Closed { conn: id, reset: false, accepted: true });
            } else {
                // drop_connection(): a reset.
                let _ = socket2::SockRef::from(conn.stream.tcp()).set_linger(Some(Duration::ZERO));
                self.resets.push((id, format!("No WebSocket handshake answer within {} ms", timeout.as_millis())));
            }
        }
    }

    /// Everything that arrived, waiting up to a millisecond when idle.
    #[cfg(test)]
    pub fn poll(&mut self, buf: &mut [u8]) -> Vec<Received> {
        let mut out = Vec::new();
        self.poll_into(buf, &mut out);
        out
    }

    /// poll() onto `out`, which is empty: what is there, else what comes
    /// within a millisecond, read as it comes, as SIPp's epoll_wait() and
    /// the reads after it: before what else the loop does.
    pub fn poll_into(&mut self, buf: &mut [u8], out: &mut Vec<Received>) {
        if self.read_into(buf, out, true) {
            self.read_into(buf, out, false);
        }
    }

    /// What there is to read, and with `wait` a wait for more when there
    /// is none, which it tells.
    fn read_into(&mut self, buf: &mut [u8], out: &mut Vec<Received>, wait: bool) -> bool {
        if let Some(u) = &self.udp {
            while out.len() < self.recv_loops {
                let Ok((n, src)) = u.recv_from(buf) else { break };
                out.push(Received { msg: text_of(&buf[..n]), from: Peer { addr: src, conn: None } });
            }
            for (&id, (s, _)) in &self.udp_calls {
                while let Ok((n, src)) = s.recv_from(buf) {
                    out.push(Received { msg: text_of(&buf[..n]), from: Peer { addr: src, conn: Some(id) } });
                }
            }
            if !out.is_empty() || !wait {
                return false;
            }
            if self.udp_calls.is_empty() {
                wait_one_readable(u.as_raw_fd());
            } else {
                let mut fds = vec![u.as_raw_fd()];
                fds.extend(self.udp_calls.values().map(|(s, _)| s.as_raw_fd()));
                wait_readable(&fds);
            }
            return true;
        }
        self.check_ws_handshakes();
        if let Some(l) = &self.listener {
            let mut accepted = Vec::new();
            while let Ok((stream, _)) = l.accept() {
                accepted.push(stream);
            }
            for s in accepted {
                if s.set_nonblocking(true).is_ok() && buffers(&s).is_ok() {
                    if self.transport.sctp() {
                        let w = self.sctp.up(&s);
                        self.warnings.extend(w);
                    } else {
                        let _ = s.set_nodelay(true);
                    }
                    let stream = match &self.tls {
                        Some(tls) => match tls.stream(s, None) {
                            Ok(s) => s,
                            // Only this peer failed: drop it, and keep
                            // serving the others.
                            Err((warning, _)) => {
                                self.warnings.push(warning);
                                continue;
                            }
                        },
                        None => Stream::Plain(s),
                    };
                    let _ = self.add(stream, true, None);
                }
            }
        }
        let (mut closed, mut resets) = (Vec::new(), Vec::new());
        let sctp = self.transport.sctp();
        for (&id, conn) in self.conns.iter_mut() {
            let accepted = conn.accepted;
            if conn.connecting {
                match connect_state(conn.stream.raw_fd(), true) {
                    None => continue,
                    Some(Ok(())) => {
                        conn.connecting = false;
                        if sctp {
                            self.warnings.extend(self.sctp.up(conn.stream.tcp()));
                        }
                        let pending = std::mem::take(&mut conn.pending);
                        let msgs: Vec<&str> = pending.iter().map(String::as_str).collect();
                        let r = conn.write_msgs(&msgs, sctp);
                        conn.pending = pending;
                        if let Err(e) = r {
                            self.send_errors += 1;
                            match write_reset(&e, self.transport, accepted) {
                                Some(why) => resets.push((id, why)),
                                None => {
                                    self.warnings.push(format!("Unable to send {} message: {}", self.transport.name(), os_error(&e)));
                                    closed.push(Closed { conn: id, reset: false, accepted });
                                }
                            }
                            continue;
                        }
                        self.written.append(&mut conn.pending);
                    }
                    Some(Err(e)) if redial(conn, &e) => continue,
                    // SIPp flushes what a connection buffered, which fails:
                    // refused, it is reset, and the buffer waits for the
                    // reconnection. With nothing buffered, it fails on its
                    // read. An SCTP association fails on its read too, of
                    // the notification that it could not start, SIPp
                    // writing nothing before it is up. A WebSocket's
                    // handshake waits from the start.
                    Some(Err(e)) if !sctp && !conn.pending.is_empty() || !conn.out.is_empty() => {
                        self.send_errors += 1;
                        match write_reset(&e, self.transport, accepted) {
                            Some(why) => resets.push((id, why)),
                            None => {
                                self.warnings.push(format!("Unable to send {} message: {}", self.transport.name(), os_error(&e)));
                                closed.push(Closed { conn: id, reset: false, accepted });
                            }
                        }
                        continue;
                    }
                    Some(Err(e)) => {
                        self.recv_errors += 1;
                        resets.push((id, format!("Error on TCP connection, remote peer probably closed the socket: {}", os_error(&e))));
                        continue;
                    }
                }
            }
            if conn.ws.is_some() || !conn.out.is_empty() {
                if let Err(e) = conn.flush_out() {
                    self.send_errors += 1;
                    match write_error(&e, accepted, self.transport, &mut self.warnings) {
                        Ok(()) => {}
                        Err(Some(why)) => {
                            resets.push((id, why));
                            continue;
                        }
                        Err(None) => {
                            closed.push(Closed { conn: id, reset: false, accepted });
                            continue;
                        }
                    }
                }
                // A WebSocket that closed reads no more. Once the messages
                // before are processed and what they sent is out, it sends
                // its close, and ends as a connection the peer closes.
                if conn.ws.as_ref().is_some_and(|w| w.is_closed()) {
                    if !conn.waiting() {
                        let close = std::mem::take(&mut conn.ws_close);
                        if !close.is_empty() {
                            let _ = conn.stream.write(&close);
                            conn.stream.flush_tls();
                        }
                        closed.push(Closed { conn: id, reset: false, accepted });
                    }
                    continue;
                }
            }
            loop {
                match conn.stream.read(buf) {
                    Ok(0) => {
                        closed.push(Closed { conn: id, reset: false, accepted });
                        break;
                    }
                    Ok(n) if conn.ws.is_some() => {
                        ws_read(conn, &buf[..n], id, self.transport, out, &mut self.warnings, &mut self.traces);
                        if conn.ws.as_ref().is_some_and(|w| w.is_closed()) {
                            break;
                        }
                    }
                    Ok(n) => conn.buf.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    // A TLS close without its close_notify is a close.
                    Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                        closed.push(Closed { conn: id, reset: false, accepted });
                        break;
                    }
                    // A connection we accepted has none to make again: a
                    // reset ends it as a close does.
                    Err(e) if accepted && e.raw_os_error() == Some(sys::ECONNRESET) => {
                        closed.push(Closed { conn: id, reset: true, accepted });
                        break;
                    }
                    Err(e) => {
                        self.recv_errors += 1;
                        resets.push((id, format!("Error on TCP connection, remote peer probably closed the socket: {}", os_error(&e))));
                        break;
                    }
                }
            }
            conn.stream.flush_tls();
            while let Some((start, end)) = frame(&conn.buf) {
                let msg = text_of(&conn.buf[start..end]);
                conn.buf.drain(..end);
                out.push(Received { msg, from: Peer { addr: conn.peer, conn: Some(id) } });
            }
        }
        for c in closed {
            // Invalid, but with its output, for a reconnection that a
            // write to it asks for (-reconnect_close false).
            let conn = self.conns.remove(&c.conn);
            if let Some(conn) = conn.filter(|_| self.keep && !c.accepted) {
                self.stash(c.conn, conn);
            }
            self.closed.push(c);
        }
        for (id, why) in resets {
            if let Some(c) = self.conns.remove(&id) {
                self.stash(id, c);
            }
            self.resets.push((id, why));
        }
        // A WebSocket that closed ends in the next poll, once what waits is
        // out: the poll waits for its socket to take it.
        let ending = self.conns.values().any(|c| c.ws.as_ref().is_some_and(|w| w.is_closed()) && !c.waiting());
        if !out.is_empty() || ending || !wait {
            return false;
        }
        let mut fds: Vec<(RawFd, sys::c_short)> =
            self.conns.values().map(|c| (c.stream.raw_fd(), if c.ws.is_some() && c.waiting() || !c.out.is_empty() { sys::POLLIN | sys::POLLOUT } else { sys::POLLIN })).collect();
        fds.extend(self.listener.as_ref().map(|l| (l.as_raw_fd(), sys::POLLIN)));
        wait_io(&fds);
        true
    }
}

/// write_error(): a connection gone, or one that could not be made (what
/// was buffered while connecting, flushed once it is refused), is reset,
/// in read_error()'s words but for a broken pipe. Not over TLS, but for
/// a client's connection.
fn write_reset(e: &io::Error, transport: Transport, accepted: bool) -> Option<String> {
    if transport.tls() && accepted {
        return None;
    }
    match e.raw_os_error()? {
        sys::EPIPE => Some("Broken pipe on TCP connection, remote peer probably closed the socket".into()),
        sys::ECONNRESET | sys::ECONNREFUSED | sys::ENOTCONN => Some(format!("Error on TCP connection, remote peer probably closed the socket: {}", os_error(e))),
        _ => None,
    }
}

/// write_error() for a WebSocket's flush: Ok for what may wait, else the
/// connection ends, reset with SIPp's words (Some) or closed (None).
/// Any other error is only warned about: the reads find out whether the
/// connection is gone.
fn write_error(e: &io::Error, accepted: bool, transport: Transport, warnings: &mut Vec<String>) -> Result<(), Option<String>> {
    // Windows' broken pipe is WSAECONNABORTED.
    let pipe = matches!(e.kind(), ErrorKind::BrokenPipe | ErrorKind::ConnectionAborted);
    if !transport.tls() && (pipe || e.kind() == ErrorKind::ConnectionReset && accepted) {
        // A connection we accepted is the peer's to end: its calls end.
        if accepted {
            return Err(None);
        }
        return Err(Some("Broken pipe on TCP connection, remote peer probably closed the socket".into()));
    }
    // A TLS client's is reset as TCP's is.
    if let (true, false, Some(why)) = (transport.tls(), accepted, write_reset(e, transport, accepted)) {
        return Err(Some(why));
    }
    warnings.push(format!("Unable to send {} message: {}", transport.name(), os_error(e)));
    Ok(())
}

/// ws_empty(): the SIP messages out of what a WebSocket connection read,
/// and the answers to its handshake and control frames.
fn ws_read(conn: &mut Conn, data: &[u8], id: ConnId, transport: Transport, out: &mut Vec<Received>, warnings: &mut Vec<String>, traces: &mut Vec<String>) {
    let Some(ws) = conn.ws.as_mut() else { return };
    ws.feed(data);
    loop {
        let ws = conn.ws.as_mut().unwrap();
        let reply = match ws.next() {
            Event::NeedMore => break,
            Event::Opened(reply) => {
                traces.push(format!("WebSocket open on socket {}\n", conn.stream.raw_fd()));
                conn.ws_since = None;
                let held = std::mem::take(&mut ws.held);
                conn.ws_reply(&reply);
                if !held.is_empty() {
                    conn.out.push_back(held);
                }
                continue;
            }
            // Each is one SIP message (RFC 7118 section 5.2).
            Event::Message(payload) => {
                if !payload.is_empty() {
                    out.push(Received { msg: text_of(&payload), from: Peer { addr: conn.peer, conn: Some(id) } });
                }
                continue;
            }
            // While other data waits, only the last ping gets its pong
            // (section 5.5.3), after that data: a peer that pings and does
            // not read fills no memory.
            Event::Reply(pong) if conn.waiting() => {
                conn.pong = pong;
                continue;
            }
            Event::Reply(pong) => pong,
            Event::Failed(reply) => {
                warnings.push(format!("WebSocket error, closing the {} connection: {}", transport.name(), conn.ws.as_ref().unwrap().error()));
                conn.ws_close = reply;
                continue;
            }
            Event::Closed(reply) => {
                conn.ws_close = reply;
                continue;
            }
        };
        conn.ws_reply(&reply);
    }
}

/// Waits up to a millisecond for one of `fds` to be readable, so that an
/// idle loop still paces timers and media. poll(2) wakes as soon as a
/// message arrives; SO_RCVTIMEO would too, but the kernel rounds its
/// timeout up to a scheduler tick (10 ms here), which made media late.
fn wait_readable(fds: &[RawFd]) {
    wait_io(&fds.iter().map(|&fd| (fd, sys::POLLIN)).collect::<Vec<_>>());
}

/// wait_readable() for some events of each fd.
fn wait_io(fds: &[(RawFd, sys::c_short)]) {
    let mut polled: Vec<sys::pollfd> = fds.iter().map(|&(fd, events)| sys::pollfd { fd, events, revents: 0 }).collect();
    // SAFETY: the pointer and length describe `polled`, which outlives the call.
    unsafe { sys::poll(polled.as_mut_ptr(), polled.len() as sys::nfds_t, 1) };
}

/// wait_readable() on the one SIP socket most runs have, without the
/// lists: the main loop's idle passes made two allocations each.
fn wait_one_readable(fd: RawFd) {
    let mut polled = sys::pollfd { fd, events: sys::POLLIN, revents: 0 };
    // SAFETY: one pollfd of ours.
    unsafe { sys::poll(&mut polled, 1, 1) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_by_content_length() {
        let two = b"\r\nA x SIP/2.0\r\nContent-Length: 3\r\n\r\nabcB y SIP/2.0\r\nl: 0\r\n\r\n";
        assert_eq!(frame(two), Some((2, 39)));
        assert_eq!(frame(&two[39..]), Some((0, 21)));
        assert_eq!(frame(b"A x SIP/2.0\r\nContent-Length: 3\r\n\r\nab"), None);
        assert_eq!(frame(b"A x SIP/2.0\r\n"), None);
    }

    #[test]
    fn max_socket_counts_call_sockets_only() {
        let mut net = Net::bind(Transport::UdpMulti, "127.0.0.1:0".parse().unwrap(), false, None, SctpOptions::default()).unwrap();
        // -max_socket 2 with control and stdin sockets: two call
        // sockets, then shared in turn.
        net.max_sockets = 2;
        net.other_sockets = 2;
        let first = net.udp_call_socket(None).unwrap();
        let second = net.udp_call_socket(None).unwrap();
        assert_ne!(first, second);
        assert_eq!(net.udp_call_socket(None).unwrap(), first);
        assert_eq!(net.udp_call_socket(None).unwrap(), second);
        assert_eq!(net.open_sockets(), 5);
        // -max_socket 0 leaves no room for one, as SIPp.
        net.max_sockets = 0;
        net.udp_calls.clear();
        let e = net.udp_call_socket(None).unwrap_err();
        assert_eq!(e.to_string(), "Could not find an existing call socket to re-use!");
    }

    #[test]
    fn a_reply_on_a_connection_the_peer_just_closed_is_no_reset() {
        let mut server = Net::bind(Transport::TcpSingle, "127.0.0.1:0".parse().unwrap(), true, None, SctpOptions::default()).unwrap();
        let mut client = TcpStream::connect(server.local_addr().unwrap()).unwrap();
        client.write_all(b"OPTIONS sip:x SIP/2.0\r\nContent-Length: 0\r\n\r\n").unwrap();
        drop(client);
        // The message and the close in one poll: the answer goes after it.
        let mut buf = [0u8; 4096];
        let mut got = Vec::new();
        for _ in 0..500 {
            got.extend(server.poll(&mut buf));
            if !server.closed.is_empty() {
                break;
            }
        }
        let from = got[0].from;
        assert!(server.send("SIP/2.0 200 OK\r\n\r\n", &from, true).is_err());
        assert!(server.resets.is_empty(), "{:?}", server.resets);
        assert_eq!(server.closed.len(), 1);
    }

    #[test]
    fn a_held_call_connection_stays_until_its_last_user_goes() {
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let to = server.local_addr().unwrap();
        let mut net = Net::bind(Transport::TcpMulti, "127.0.0.1:0".parse().unwrap(), false, None, SctpOptions::default()).unwrap();
        let conn = net.connect(to).unwrap().unwrap();
        // Another call holds it for a response: its own call's end leaves
        // it open, the holder's closes it.
        assert!(net.hold(conn));
        net.close(conn);
        assert!(net.is_open(conn));
        net.close(conn);
        assert!(!net.is_open(conn));
        assert!(!net.hold(conn));
    }

    #[test]
    fn max_socket_shares_tcp_call_connections() {
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let to = server.local_addr().unwrap();
        let mut net = Net::bind(Transport::TcpMulti, "127.0.0.1:0".parse().unwrap(), false, None, SctpOptions::default()).unwrap();
        net.max_sockets = 2;
        let first = net.connect(to).unwrap().unwrap();
        let second = net.connect(to).unwrap().unwrap();
        assert_ne!(first, second);
        // Then shared in turn, each closed with the last of its calls.
        assert_eq!(net.connect(to).unwrap(), Some(first));
        assert_eq!((net.users(first), net.users(second)), (2, 1));
        net.close(first);
        assert_eq!(net.users(first), 1);
        net.close(first);
        assert_eq!(net.users(first), 0);
        // A <setdest>'s is its call's alone.
        let elsewhere = net.connect_elsewhere(to).unwrap().unwrap();
        net.close(second);
        net.max_sockets = 1;
        assert_eq!(net.connect(to).unwrap_err().to_string(), "Could not find an existing call socket to re-use!");
        assert_eq!(net.users(elsewhere), 1);
    }

    /// A port nothing listens on, on the loopback.
    /// The system's words for ECONNREFUSED.
    fn refused() -> String {
        os_error(&io::Error::from_raw_os_error(sys::ECONNREFUSED))
    }

    fn closed_port() -> SocketAddr {
        TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
    }

    /// Polls until the connection's refusal shows, as SIPp's poll loop.
    fn poll_until(net: &mut Net, done: impl Fn(&Net) -> bool) {
        let mut buf = [0u8; 4096];
        // Windows refuses a connect to a closed port after its retries, a
        // second or more.
        let end = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while std::time::Instant::now() < end {
            net.poll(&mut buf);
            if done(net) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        panic!("the refusal never showed");
    }

    #[test]
    fn a_refused_connect_shows_on_the_shared_connections_flush() {
        let mut net = Net::bind(Transport::TcpSingle, "127.0.0.1:0".parse().unwrap(), false, None, SctpOptions::default()).unwrap();
        let to = closed_port();
        // Connected without waiting, as SIPp's connect(); what a call
        // sends meanwhile is buffered.
        let conn = net.connect(to).unwrap().unwrap();
        assert_eq!(net.send("INVITE x SIP/2.0\r\n\r\n", &Peer { addr: to, conn: Some(conn) }, true), Ok(false));
        poll_until(&mut net, |n| !n.resets.is_empty());
        assert_eq!(net.resets, vec![(conn, format!("Error on TCP connection, remote peer probably closed the socket: {}", refused()))]);
        assert!(net.warnings.is_empty(), "{:?}", net.warnings);
        // SIPp flushes what waits first: a send error.
        assert_eq!((net.send_errors, net.recv_errors), (1, 0));
        // Past a peer's close, the invalid socket stays for a send's EPIPE;
        // reset_connection() makes a new one.
        assert_eq!(net.connect(to).unwrap(), Some(conn));
        let fresh = net.reconnect(to).unwrap().unwrap();
        assert_ne!(fresh, conn);
    }

    #[test]
    fn a_calls_refused_connect_resets_it_keeping_its_buffered_send() {
        let mut net = Net::bind(Transport::TcpMulti, "127.0.0.1:0".parse().unwrap(), false, None, SctpOptions::default()).unwrap();
        let to = closed_port();
        let conn = net.connect(to).unwrap().unwrap();
        let invite = "INVITE x SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(net.send(invite, &Peer { addr: to, conn: Some(conn) }, true), Ok(false));
        poll_until(&mut net, |n| !n.resets.is_empty());
        // write_error(): refused, the flush resets it.
        assert_eq!(net.resets, vec![(conn, format!("Error on TCP connection, remote peer probably closed the socket: {}", refused()))]);
        assert!(net.warnings.is_empty() && net.closed.is_empty(), "{:?}", net.warnings);
        assert_eq!((net.send_errors, net.recv_errors), (1, 0));
        // Never written, so never traced as sent; it goes on the next
        // connection, once there is one.
        assert!(net.written.is_empty());
        let unsent = net.take_unsent(conn);
        assert_eq!(unsent.msgs, [invite]);
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let to = server.local_addr().unwrap();
        let fresh = net.connect(to).unwrap().unwrap();
        net.requeue(fresh, unsent);
        let (mut s, _) = server.accept().unwrap();
        poll_until(&mut net, |n| !n.written.is_empty());
        assert_eq!(net.written, [invite]);
        let mut got = vec![0u8; invite.len()];
        s.read_exact(&mut got).unwrap();
        assert_eq!(got, invite.as_bytes());
    }

    #[test]
    fn sending_more_than_the_peer_reads_does_not_block() {
        let mut net = Net::bind(Transport::TcpSingle, "127.0.0.1:0".parse().unwrap(), false, None, SctpOptions::default()).unwrap();
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let to = server.local_addr().unwrap();
        let conn = net.connect(to).unwrap().unwrap();
        let (mut s, _) = server.accept().unwrap();
        poll_until(&mut net, |n| !n.conns[&conn].connecting);
        // Both peers writing more than the other reads blocked SIPp for
        // good, in a blocking write. The reader starts after the sends.
        let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watchdog = finished.clone();
        std::thread::spawn(move || {
            for _ in 0..300 {
                std::thread::sleep(Duration::from_millis(100));
                if watchdog.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
            }
            eprintln!("a send blocked");
            std::process::abort();
        });
        let msg = format!("MESSAGE sip:x SIP/2.0\r\nContent-Length: 60000\r\n\r\n{}", "x".repeat(60000));
        let peer = Peer { addr: to, conn: Some(conn) };
        for _ in 0..300 {
            assert_eq!(net.send(&msg, &peer, false), Ok(true));
        }
        finished.store(true, std::sync::atomic::Ordering::Relaxed);
        let total = 300 * msg.len();
        let reader = std::thread::spawn(move || {
            let (mut n, mut buf) = (0, vec![0u8; 65536]);
            while n < total {
                n += s.read(&mut buf).unwrap();
            }
            n
        });
        let mut buf = [0u8; 4096];
        let end = std::time::Instant::now() + Duration::from_secs(20);
        while !reader.is_finished() && std::time::Instant::now() < end {
            net.poll(&mut buf);
        }
        assert!(reader.is_finished(), "the queue never drained");
        assert_eq!(reader.join().unwrap(), total);
    }

    // Windows resets a close with unread data whatever the shutdown.
    #[cfg(unix)]
    #[test]
    fn closing_with_unread_data_ends_the_connection_cleanly() {
        let mut net = Net::bind(Transport::TcpSingle, "127.0.0.1:0".parse().unwrap(), false, None, SctpOptions::default()).unwrap();
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let to = server.local_addr().unwrap();
        net.connect(to).unwrap().unwrap();
        let (mut s, _) = server.accept().unwrap();
        s.write_all(b"unread").unwrap();
        // The data is there before the close, which would reset the peer.
        std::thread::sleep(std::time::Duration::from_millis(100));
        net.close_all();
        let mut got = Vec::new();
        s.read_to_end(&mut got).unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn a_closed_connection_keeps_scenario_messages_for_its_reconnection() {
        let mut net = Net::bind(Transport::TcpSingle, "127.0.0.1:0".parse().unwrap(), false, None, SctpOptions::default()).unwrap();
        net.keep = true;
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let to = server.local_addr().unwrap();
        let conn = net.connect(to).unwrap().unwrap();
        drop(server.accept().unwrap());
        poll_until(&mut net, |n| !n.closed.is_empty());
        let peer = Peer { addr: to, conn: Some(conn) };
        // Our own message fails; a scenario message waits, as sent.
        assert!(net.send("SIP/2.0 200 OK\r\n\r\n", &peer, false).is_err());
        assert_eq!(net.kept, None);
        let bye = "BYE x SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        assert!(net.send(bye, &peer, true).is_err());
        assert_eq!(net.kept.take(), Some(false));
        // One reset for both.
        assert_eq!(net.resets.len(), 1);
        let unsent = net.take_unsent(conn);
        assert_eq!(unsent.msgs, [bye]);
        let fresh = net.reconnect(to).unwrap().unwrap();
        net.requeue(fresh, unsent);
        assert!(!net.all_written(Some(fresh)));
        let (mut s, _) = server.accept().unwrap();
        poll_until(&mut net, |n| !n.written.is_empty());
        assert_eq!(net.written, [bye]);
        let mut got = vec![0u8; bye.len()];
        s.read_exact(&mut got).unwrap();
        assert_eq!(got, bye.as_bytes());
        assert!(net.all_written(Some(fresh)));
    }

    /// Polls both until `done`.
    fn poll_both(a: &mut Net, b: &mut Net, mut done: impl FnMut(Vec<Received>, Vec<Received>) -> bool) {
        let mut buf = [0u8; 65536];
        for _ in 0..2000 {
            let (x, y) = (a.poll(&mut buf), b.poll(&mut buf));
            if done(x, y) {
                return;
            }
        }
        panic!("never done");
    }

    #[test]
    fn sip_over_websocket() {
        let mut server = Net::bind(Transport::WsSingle, "127.0.0.1:0".parse().unwrap(), true, None, SctpOptions::default()).unwrap();
        let to = server.local_addr().unwrap();
        let mut client = Net::bind(Transport::WsSingle, "127.0.0.1:0".parse().unwrap(), false, None, SctpOptions::default()).unwrap();
        client.ws_path = "sip".into();
        let conn = client.connect(to).unwrap().unwrap();
        assert!(client.traces[0].starts_with("WebSocket handshake on socket "), "{:?}", client.traces);
        assert!(client.traces[0].contains(&format!(":\n\nGET /sip HTTP/1.1\r\nHost: {to}\r\n")));
        // Held until the handshake is done, and traced now.
        let invite = "INVITE sip:x SIP/2.0\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(client.send(invite, &Peer { addr: to, conn: Some(conn) }, true), Ok(true));
        let mut from = None;
        poll_both(&mut client, &mut server, |_, got| {
            from = got.first().map(|r| r.from);
            got.first().is_some_and(|r| *r.msg == *invite)
        });
        // A server's answer, then the client's close ends it at the server.
        let from = from.unwrap();
        assert_eq!(server.send("SIP/2.0 200 OK\r\n\r\n", &from, true), Ok(true));
        poll_both(&mut client, &mut server, |got, _| got.first().is_some_and(|r| &*r.msg == "SIP/2.0 200 OK\r\n\r\n"));
        client.close(conn);
        poll_until(&mut server, |n| !n.closed.is_empty());
        assert_eq!(server.closed[0].conn, from.conn.unwrap());
        assert!(server.warnings.is_empty(), "{:?}", server.warnings);
    }

    /// The kernel may have no SCTP (its module not loaded): no test then.
    fn sctp_available() -> bool {
        Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::from(IPPROTO_SCTP))).is_ok()
    }

    #[test]
    fn a_refused_sctp_connect_shows_later() {
        if !sctp_available() {
            return;
        }
        // Over -t s1 and sn alike: a read error, of the notification that
        // the association could not start, what waits kept for the next.
        for t in [Transport::SctpSingle, Transport::SctpMulti] {
            let mut net = Net::bind(t, "127.0.0.1:0".parse().unwrap(), false, None, SctpOptions::default()).unwrap();
            let to = closed_port();
            let conn = net.connect(to).unwrap().unwrap();
            assert_eq!(net.send("INVITE x SIP/2.0\r\n\r\n", &Peer { addr: to, conn: Some(conn) }, true), Ok(false));
            poll_until(&mut net, |n| !n.resets.is_empty());
            assert_eq!(net.resets, vec![(conn, format!("Error on TCP connection, remote peer probably closed the socket: {}", refused()))]);
            assert_eq!((net.send_errors, net.recv_errors), (0, 1));
            assert_eq!(net.take_unsent(conn).msgs.len(), 1);
        }
    }

    /// getsockopt() of SCTP option `opt`, `buf` its argument and result.
    fn sctp_getsockopt(fd: RawFd, opt: i32, buf: &mut [u8]) {
        let mut len = buf.len() as sys::socklen_t;
        // SAFETY: `buf` is valid for `len` bytes.
        assert_eq!(unsafe { sys::getsockopt(fd, IPPROTO_SCTP, opt, buf.as_mut_ptr().cast(), &mut len) }, 0);
    }

    #[test]
    fn an_sctp_association_as_sipp_sets_it_up() {
        if !sctp_available() {
            return;
        }
        let mut server = Net::bind(Transport::SctpMulti, "127.0.0.1:0".parse().unwrap(), true, None, SctpOptions::default()).unwrap();
        let to = server.local_addr().unwrap();
        let options = SctpOptions { heartbeat: 2000, pathmaxret: 3, pmtu: 1400, graceful: false, ..SctpOptions::default() };
        let mut client = Net::bind(Transport::SctpMulti, "127.0.0.1:0".parse().unwrap(), false, None, options).unwrap();
        let conn = client.connect(to).unwrap().unwrap();
        // Sent (or buffered until the association is up) a message each.
        let (a, b) = ("A x SIP/2.0\r\nl: 0\r\n\r\n", "B y SIP/2.0\r\nl: 0\r\n\r\n");
        let peer = Peer { addr: to, conn: Some(conn) };
        assert!(client.send(a, &peer, true).is_ok() && client.send(b, &peer, true).is_ok());
        let mut got = Vec::new();
        poll_both(&mut client, &mut server, |_, r| {
            got.extend(r.into_iter().map(|r| r.msg.to_string()));
            got.len() == 2
        });
        assert_eq!(got, [a, b]);
        let fd = client.conns[&conn].stream.raw_fd();
        // Unordered, as send_sctp_nowait() sends them.
        let mut sndrcv = [0u8; 32];
        sctp_getsockopt(fd, SCTP_DEFAULT_SEND_PARAM, &mut sndrcv);
        assert_eq!(u16::from_ne_bytes([sndrcv[4], sndrcv[5]]), SCTP_UNORDERED);
        // The peer's address has -heartbeat, -pathmaxret and -pmtu.
        let mut p = [0u8; 156];
        let addr = socket2::SockAddr::from(to);
        // SAFETY: the address is valid for its length.
        p[4..4 + addr.len() as usize].copy_from_slice(unsafe { std::slice::from_raw_parts(addr.as_ptr().cast::<u8>(), addr.len() as usize) });
        sctp_getsockopt(fd, SCTP_PEER_ADDR_PARAMS, &mut p);
        assert_eq!(u32::from_ne_bytes(p[132..136].try_into().unwrap()), 2000);
        assert_eq!(u16::from_ne_bytes(p[136..138].try_into().unwrap()), 3);
        assert_eq!(u32::from_ne_bytes(p[138..142].try_into().unwrap()), 1400);
        // Without -gracefulclose, the close aborts: the server's end of
        // it, which it accepted, just closes.
        client.close(conn);
        poll_until(&mut server, |n| !n.closed.is_empty());
        assert!(server.closed[0].reset);
        assert!(server.resets.is_empty(), "{:?}", server.resets);
        assert!(client.warnings.is_empty() && server.warnings.is_empty(), "{:?} {:?}", client.warnings, server.warnings);
        // -pmtu alone is set too.
        let options = SctpOptions { pmtu: 1300, ..SctpOptions::default() };
        let mut client = Net::bind(Transport::SctpMulti, "127.0.0.1:0".parse().unwrap(), false, None, options).unwrap();
        let conn = client.connect(to).unwrap().unwrap();
        assert!(client.send(a, &Peer { addr: to, conn: Some(conn) }, true).is_ok());
        poll_both(&mut client, &mut server, |_, r| !r.is_empty());
        sctp_getsockopt(client.conns[&conn].stream.raw_fd(), SCTP_PEER_ADDR_PARAMS, &mut p);
        assert_eq!(u32::from_ne_bytes(p[138..142].try_into().unwrap()), 1300);
    }

}

//! legacy-tls: -tls_version 1.0 and 1.1 through OpenSSL, as SIPp has
//! them; rustls has neither, and keeps every other version.

use crate::net::{os_error, Step, TlsOptions};
use openssl::ssl::{ErrorCode, Ssl, SslContext, SslContextBuilder, SslFiletype, SslMethod, SslOptions, SslStream, SslVerifyMode, SslVersion};
use openssl::x509::store::X509Lookup;
use openssl::x509::verify::X509VerifyFlags;
use std::io::Write;
use std::net::TcpStream;

/// SIPp's client and server SSL_CTX.
pub struct Contexts {
    client: SslContext,
    server: SslContext,
}

impl Contexts {
    /// TLS_init_context() for -tls_version 1.0 or 1.1, with what net::Tls
    /// does for rustls: a client presents our certificate when there is
    /// one, -tls_ca has the peer's chain checked, -tls_crl its revocation.
    pub fn new(ours: Option<(&str, &str)>, server: bool, opts: &TlsOptions) -> Result<Contexts, String> {
        let context = |accepting: bool| -> Result<SslContext, String> {
            let mut b = SslContextBuilder::new(if accepting { SslMethod::tls_server() } else { SslMethod::tls_client() }).map_err(|e| e.to_string())?;
            let v = Some(if opts.version == Some(1.0) { SslVersion::TLS1 } else { SslVersion::TLS1_1 });
            b.set_min_proto_version(v).and_then(|_| b.set_max_proto_version(v)).map_err(|e| e.to_string())?;
            // OpenSSL 3 refuses TLS 1.0 and 1.1 at its default security level.
            b.set_security_level(0);
            // A close without close_notify is a close, as with rustls.
            b.set_options(SslOptions::IGNORE_UNEXPECTED_EOF);
            if let Some(ca) = &opts.ca {
                b.set_ca_file(ca).map_err(|e| format!("TLS CA {ca}: {e}"))?;
                if let Some(crl) = &opts.crl {
                    let store = b.cert_store_mut();
                    store
                        .add_lookup(X509Lookup::file())
                        .and_then(|l| l.load_crl_file(crl, SslFiletype::PEM))
                        .and_then(|_| store.set_flags(X509VerifyFlags::CRL_CHECK | X509VerifyFlags::CRL_CHECK_ALL))
                        .map_err(|_| format!("TLS_init_context: Unable to load CRL file ({crl})"))?;
                }
                b.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
            }
            if let Some((cert, key)) = ours {
                b.set_certificate_chain_file(cert)
                    .map_err(|e| format!("TLS_init_context: SSL_CTX_use_certificate_chain_file failed: {}", e.errors().first().map_or(String::new(), |e| e.to_string())))?;
                b.set_private_key_file(key, SslFiletype::PEM).map_err(|_| "TLS_init_context: SSL_CTX_use_PrivateKey_file failed".to_string())?;
            } else if server {
                return Err("TLS_init_context: SSL_CTX_use_PrivateKey_file failed".into());
            }
            if let Some(path) = std::env::var_os("SSLKEYLOGFILE").filter(|p| !p.is_empty()) {
                b.set_keylog_callback(move |_, line| {
                    let file = std::fs::OpenOptions::new().append(true).create(true).open(&path);
                    let _ = file.and_then(|mut f| writeln!(f, "{line}"));
                });
            }
            Ok(b.build())
        };
        // A client accepts connections on its main socket too: without
        // a certificate, their handshakes fail, as in SIPp.
        Ok(Contexts { client: context(false)?, server: context(true)? })
    }

    /// A stream over `tcp` whose handshake step() is to do.
    pub fn stream(&self, tcp: TcpStream, accepting: bool) -> Result<SslStream<TcpStream>, String> {
        let mut ssl = Ssl::new(if accepting { &self.server } else { &self.client }).map_err(|e| e.to_string())?;
        if accepting {
            ssl.set_accept_state();
        } else {
            ssl.set_connect_state();
        }
        SslStream::new(ssl, tcp).map_err(|e| e.to_string())
    }
}

/// One SSL_do_handshake(), failing with SIPp's SSL_error_string().
pub fn step(s: &mut SslStream<TcpStream>) -> Step {
    let Err(e) = s.do_handshake() else { return Step::Done };
    let errno = e.io_error().and_then(|e| e.raw_os_error()).unwrap_or(0);
    let why = match (e.code(), e.io_error()) {
        (ErrorCode::WANT_READ, _) => return Step::Wait(libc::POLLIN),
        (ErrorCode::WANT_WRITE, _) => return Step::Wait(libc::POLLOUT),
        (ErrorCode::ZERO_RETURN, _) => "SSL connection has been closed. SSL returned: SSL_ERROR_ZERO_RETURN".into(),
        (ErrorCode::SSL, _) => "SSL protocol error. SSL I/O function returned SSL_ERROR_SSL".into(),
        (ErrorCode::SYSCALL, Some(io)) => os_error(io),
        (ErrorCode::SYSCALL, None) => "Non-recoverable I/O error occurred. SSL I/O function returned SSL_ERROR_SYSCALL".into(),
        _ => "Unknown SSL Error.".into(),
    };
    Step::Failed(why, errno)
}

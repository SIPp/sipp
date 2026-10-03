//! RTP: streaming a file or a pattern to the peer (rtp_stream), and
//! -rtp_echo.

use crate::srtp;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// -srtpcheck_debug's rtp_echo logs, debugrefileaudio_<time>.log and
/// debugrefilevideo_<time>.log: one of each for the process, as SIPp's,
/// which the first echo's start opens and the end of the run closes.
pub mod echo_debug {
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
    use std::sync::Mutex;

    /// -srtpcheck_debug
    pub static ON: AtomicBool = AtomicBool::new(false);
    static FILES: Mutex<[super::DebugFile; 2]> = Mutex::new([(None, false), (None, false)]);

    fn name(video: bool) -> &'static str {
        if video { "video" } else { "audio" }
    }

    /// rtpstream_rtpecho_start*(): opens the file if it isn't; the echo
    /// starts without it.
    pub fn start(video: bool) {
        if ON.load(Relaxed) {
            let (file, warned) = &mut FILES.lock().unwrap()[video as usize];
            if file.is_none() {
                let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
                *file = super::create_debug(&format!("debugrefile{}_{secs}.log", name(video)), warned).ok();
            }
        }
        print(video, &format!("rtpstream_rtpecho_start{} reached...\n", name(video)));
    }

    /// rtpstream_rtpecho_update*(): the file as it is.
    pub fn update(video: bool) {
        print(video, &format!("rtpstream_rtpecho_update{} reached...\n", name(video)));
    }

    /// rtpstream_rtpecho_stop*(): the file stays open for the other
    /// calls' echoes.
    pub fn stop(video: bool) {
        print(video, &format!("rtpstream_rtpecho_stop{} reached...\n", name(video)));
    }

    pub fn is_open(video: bool) -> bool {
        ON.load(Relaxed) && FILES.lock().unwrap()[video as usize].0.is_some()
    }

    pub fn print(video: bool, text: &str) {
        if let Some(f) = FILES.lock().unwrap()[video as usize].0.as_mut() {
            let _ = f.write_all(text.as_bytes());
        }
    }
}

/// -srtpcheck_debug's SRTP parameter dumps, debug{l,r}srtp{a,v}file_{uac,uas}:
/// the crypto lines of each SDP we send, and of each the peer sends, as
/// SIPp's SrtpDebugFile: one of each for the process, which its first
/// dump creates.
pub mod srtp_debug {
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
    use std::sync::Mutex;

    /// SIPp's sendMode: the main scenario sends first.
    pub static CLIENT: AtomicBool = AtomicBool::new(true);
    /// By ours or the peer's, and by audio or video.
    static FILES: Mutex<[[super::DebugFile; 2]; 2]> = Mutex::new([[(None, false), (None, false)], [(None, false), (None, false)]]);

    /// SrtpInfoParams: a media's two crypto lines, of which the primary
    /// one has a tag.
    #[derive(Default)]
    pub struct Params {
        pub tags: [i32; 2],
        pub suites: [String; 2],
        pub keys: [String; 2],
        pub unencrypted: [bool; 2],
    }

    /// printCrypto(), to the file of `remote` (the peer's) or ours.
    pub fn dump(remote: bool, video: bool, p: &Params) {
        if !super::echo_debug::ON.load(Relaxed) {
            return;
        }
        let mut files = FILES.lock().unwrap();
        let (file, warned) = &mut files[remote as usize][video as usize];
        if file.is_none() {
            let (w, t) = (if remote { 'r' } else { 'l' }, if video { 'v' } else { 'a' });
            let role = if CLIENT.load(Relaxed) { "uac" } else { "uas" };
            *file = super::create_debug(&format!("debug{w}srtp{t}file_{role}"), warned).ok();
        }
        let Some(f) = file.as_mut() else { return };
        let _ = write!(
            f,
            "found                     : 1\n\
             primary_cryptotag         : {}\n\
             secondary_cryptotag       : {}\n\
             primary_cryptosuite       : {}\n\
             secondary_cryptosuite     : {}\n\
             primary_cryptokeyparams   : {}\n\
             secondary_cryptokeyparams : {}\n\
             primary_unencrypted_srtp  : {}\n\
             secondary_unencrypted_srtp: {}\n",
            p.tags[0],
            p.tags[1],
            p.suites[0],
            p.suites[1],
            p.keys[0],
            p.keys[1],
            u8::from(p.unencrypted[0]),
            u8::from(p.unencrypted[1]),
        );
    }
}

/// -srtpcheck_debug's srtpctxdebugfile_uac (or _uas): each call's account
/// of its SRTP, SIPp's logSrtpInfo(). As SIPp's fopen("w"), each call
/// makes the file anew as it starts and writes it through a buffer of
/// stdio's, flushed when full and at the call's end: the calls write over
/// each other from the start of the file, as SIPp's do.
pub mod srtpctx_debug {
    use std::fmt::Write as _;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

    /// The files made, for their order at the end of the run.
    static MADE: AtomicU64 = AtomicU64::new(0);

    pub struct File {
        file: std::fs::File,
        /// glibc's buffer: st_blksize bytes, written only when full.
        buf: Vec<u8>,
        line: String,
        /// SIPp's sendMode is client, else server.
        pub client: bool,
        /// The order it was made in.
        pub seq: u64,
    }

    impl File {
        pub fn create(client: bool) -> std::io::Result<File> {
            File::at(std::path::Path::new(if client { "srtpctxdebugfile_uac" } else { "srtpctxdebugfile_uas" }), client)
        }

        fn at(path: &std::path::Path, client: bool) -> std::io::Result<File> {
            let file = std::fs::File::create(path)?;
            let size = crate::sys::stdio_buffer_size(&file);
            Ok(File { file, buf: Vec::with_capacity(size), line: String::new(), client, seq: MADE.fetch_add(1, Relaxed) })
        }

        /// A line, or more, of text.
        pub fn line(&mut self, args: std::fmt::Arguments) {
            let mut text = std::mem::take(&mut self.line);
            text.clear();
            let _ = text.write_fmt(args);
            self.put(&crate::raw::bytes(&text));
            self.line = text;
        }

        /// _IO_new_file_xsputn(): the buffer filled, written when full,
        /// whole buffers of what is left written as they are, the rest
        /// kept.
        fn put(&mut self, mut data: &[u8]) {
            let size = self.buf.capacity();
            let n = data.len().min(size - self.buf.len());
            self.buf.extend_from_slice(&data[..n]);
            data = &data[n..];
            if data.is_empty() {
                return;
            }
            self.flush();
            let whole = data.len() - data.len() % size;
            let _ = self.file.write_all(&data[..whole]);
            self.buf.extend_from_slice(&data[whole..]);
        }

        fn flush(&mut self) {
            let _ = self.file.write_all(&self.buf);
            self.buf.clear();
        }

        /// The call's contexts for sending and receiving, as SIPp names
        /// them, and its sendMode.
        pub fn tx(&self) -> &'static str {
            if self.client { "(a) TX-UAC" } else { "(d) TX-UAS" }
        }

        pub fn rx(&self) -> &'static str {
            if self.client { "(b) RX-UAC" } else { "(c) RX-UAS" }
        }

        /// The role a context is named for, in SIPp's startSrtp().
        pub fn role(&self) -> &'static str {
            if self.client { "UAC" } else { "UAS" }
        }

        pub fn mode(&self) -> &'static str {
            if self.client { "CLIENT" } else { "SERVER" }
        }
    }

    /// fclose(): what is left in the buffer is written.
    impl Drop for File {
        fn drop(&mut self) {
            self.flush();
        }
    }

    fn find(s: &[u8], pat: &[u8], from: usize) -> Option<usize> {
        s.get(from..)?.windows(pat.len()).position(|w| w == pat).map(|i| i + from)
    }

    /// sscanf("%d") of a port's text, 0 if none.
    fn port_of(s: &[u8]) -> i32 {
        let s = &s[s.iter().take_while(|c| c.is_ascii_whitespace()).count()..];
        let sign = usize::from(s.first().is_some_and(|&c| c == b'+' || c == b'-'));
        let digits = s[sign..].iter().take_while(|c| c.is_ascii_digit()).count();
        std::str::from_utf8(&s[..sign + digits]).ok().and_then(|n| n.parse::<i64>().ok()).map_or(0, |n| n as i32)
    }

    /// extract_srtp_remote_info()'s account of an SDP: its first active
    /// audio and video m= lines, and whether the first two a=crypto lines
    /// of their sections have UNENCRYPTED_SRTP, found as SIPp finds them.
    pub fn remote_info(f: &mut File, msg: &str) {
        let body = match (msg.find("\r\n\r\n"), msg.find("\n\n")) {
            (Some(e), _) => &msg[e + 4..],
            (None, Some(e)) => &msg[e + 2..],
            (None, None) => "",
        };
        if body.is_empty() {
            return;
        }
        let sdp = body.as_bytes();
        for (kind, name) in [("audio", "AUDIO"), ("video", "VIDEO")] {
            let prefix = format!("\nm={kind}");
            let prefix = prefix.as_bytes();
            // The first m= line of the kind, or the second one if the first
            // has port 0; where its port ends.
            let mut end = None;
            let mut exists = false;
            for (n, which) in ["first", "second"].into_iter().enumerate() {
                let Some(at) = find(sdp, prefix, end.unwrap_or(0)) else {
                    f.line(format_args!("NO {which} {kind} m-line found...\n"));
                    break;
                };
                end = find(sdp, b" ", at + prefix.len() + 1);
                let Some(e) = end else {
                    f.line(format_args!("invalid formatting encountered:  missing whitespace after {which} {kind} m-line port...\n"));
                    break;
                };
                let port = port_of(&sdp[at + prefix.len() + 1..e]);
                if port != 0 {
                    f.line(format_args!("found {which} ACTIVE {kind} m-line with NON-ZERO port [{port}]...\n"));
                    exists = true;
                    break;
                }
                f.line(format_args!("found {which} INACTIVE {kind} m-line (e.g. with ZERO port)...\n"));
                if n == 1 {
                    break;
                }
            }
            let Some(from) = end.filter(|_| exists) else { continue };
            // Only its media section's crypto lines.
            let limit = find(sdp, b"\nm=", from).unwrap_or(usize::MAX);
            let mut line = find(sdp, b"\na=crypto:", from);
            for which in ["PRIMARY", "SECONDARY"] {
                let Some(at) = line.filter(|&at| at < limit) else { break };
                let eol = find(sdp, b"\n", at + 1);
                if let Some(eol) = eol {
                    match crate::srtp::Line::parse(&body[at + 10..eol]).unencrypted {
                        true => f.line(format_args!("Call::received_sdp():  Detected UNENCRYPTED_SRTP token for {which} {name}\n")),
                        false => f.line(format_args!("Call::received_sdp():  No UNENCRYPTED_SRTP token detected for {which} {name}\n")),
                    }
                }
                line = eol.and_then(|eol| find(sdp, b"\na=crypto:", eol));
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Two calls' files, as two FILEs of fopen("w"): each writes from
        /// the start as its buffer fills or it closes.
        #[test]
        fn calls_write_over_each_other() {
            let path = std::env::temp_dir().join(format!("sipp-rs-srtpctx-{}", std::process::id()));
            let mut a = File::at(&path, true).unwrap();
            let size = a.buf.capacity();
            a.line(format_args!("aaaaaaaaaa"));
            let mut b = File::at(&path, true).unwrap();
            b.line(format_args!("bbbbb"));
            assert_eq!(std::fs::read(&path).unwrap(), b"");
            drop(a);
            assert_eq!(std::fs::read(&path).unwrap(), b"aaaaaaaaaa");
            drop(b);
            assert_eq!(std::fs::read(&path).unwrap(), b"bbbbbaaaaa");
            // A full buffer goes out, and whole buffers of what is left.
            let mut c = File::at(&path, true).unwrap();
            c.line(format_args!("{}", "c".repeat(2 * size + 3)));
            assert_eq!(std::fs::read(&path).unwrap().len(), 2 * size);
            drop(c);
            assert_eq!(std::fs::read(&path).unwrap(), "c".repeat(2 * size + 3).as_bytes());
            let _ = std::fs::remove_file(&path);
        }

        fn info(sdp: &str) -> String {
            let path = std::env::temp_dir().join(format!("sipp-rs-srtpctx-info-{}", std::process::id()));
            let mut f = File::at(&path, true).unwrap();
            remote_info(&mut f, &format!("SIP/2.0 200 OK\r\n\r\n{sdp}"));
            drop(f);
            let text = std::fs::read_to_string(&path).unwrap();
            let _ = std::fs::remove_file(&path);
            text
        }

        #[test]
        fn remote_info_as_sipp_finds_it() {
            let key = "inline:MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkw";
            assert_eq!(
                info(&format!("v=0\r\nm=audio 0 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 {key}\r\nm=audio 6000 RTP/SAVP 0\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 {key}\r\na=crypto:2 AES_CM_128_HMAC_SHA1_32 {key} UNENCRYPTED_SRTP\r\nm=video 6002 RTP/SAVP 99\r\n")),
                "found first INACTIVE audio m-line (e.g. with ZERO port)...\n\
                 found second ACTIVE audio m-line with NON-ZERO port [6000]...\n\
                 Call::received_sdp():  No UNENCRYPTED_SRTP token detected for PRIMARY AUDIO\n\
                 Call::received_sdp():  Detected UNENCRYPTED_SRTP token for SECONDARY AUDIO\n\
                 found first ACTIVE video m-line with NON-ZERO port [6002]...\n"
            );
            assert_eq!(info("v=0\r\nm=audio 0 RTP/AVP 0\r\n"), "found first INACTIVE audio m-line (e.g. with ZERO port)...\nNO second audio m-line found...\nNO first video m-line found...\n");
            assert_eq!(info("v=0\r\nm=audio"), "invalid formatting encountered:  missing whitespace after first audio m-line port...\nNO first video m-line found...\n");
        }
    }
}

/// A debug file, and whether it was warned about.
type DebugFile = (Option<std::fs::File>, bool);

/// SIPp's DebugFile::open(): a debug file, created anew; one that can't
/// be is warned about the first time (`warned`), as a warning deferred to
/// the engine's log, and the run goes on without it.
fn create_debug(name: &str, warned: &mut bool) -> io::Result<std::fs::File> {
    std::fs::File::create(name).inspect_err(|e| {
        if !std::mem::replace(warned, true) {
            crate::log::defer_warning(debug_warning(name, e));
        }
    })
}

fn debug_warning(name: &str, e: &io::Error) -> String {
    format!("Unable to create debug file '{name}', errno = {} ({})", e.raw_os_error().unwrap_or(0), crate::net::os_error(e))
}

/// -rtpcheck_debug's debugafile and debugvfile, SIPp's: what the playback
/// threads do with the calls' rtp_stream audio and video (the packets
/// they send and what came back after each, its comparison and the RTP
/// check's verdicts), and the threads' starts and ends. An rtp_stream of
/// the kind opens its file as SIPp caches what it plays: a file as the
/// scenario loads, a pattern as it plays; the end of the run closes it.
/// Nothing is formatted without the option, nor for a kind without its
/// file.
pub mod rtp_debug {
    use std::fs::File;
    use std::io::{BufWriter, Write};
    use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
    use std::sync::Mutex;

    /// -rtpcheck_debug
    pub static ON: AtomicBool = AtomicBool::new(false);
    /// Either file is open: the playback threads log.
    static OPEN: AtomicBool = AtomicBool::new(false);
    /// Audio and video: each file, and whether it was warned about.
    static FILES: [Mutex<(Option<BufWriter<File>>, bool)>; 2] = [Mutex::new((None, false)), Mutex::new((None, false))];

    /// Whether there is anything to log to, checked before anything is.
    #[inline]
    pub fn on() -> bool {
        OPEN.load(Relaxed)
    }

    /// rtpstream_cache_file(): the file of an rtp_stream's kind (video for
    /// H264), if it isn't open; the warning, once, when it can't be.
    pub fn open(video: bool) -> Option<String> {
        if !ON.load(Relaxed) {
            return None;
        }
        let (file, warned) = &mut *FILES[video as usize].lock().unwrap();
        if file.is_some() {
            return None;
        }
        let name = if video { "debugvfile" } else { "debugafile" };
        match File::create(name) {
            Ok(f) => {
                *file = Some(BufWriter::new(f));
                OPEN.store(true, Relaxed);
            }
            Err(e) if !std::mem::replace(warned, true) => return Some(super::debug_warning(name, &e)),
            Err(_) => {}
        }
        None
    }

    /// DebugFile::printHex(): the thread, the note, `data`'s size, `extra`
    /// in hex and `more`, and `data` in hex.
    pub fn hex(video: bool, note: &str, data: &[u8], extra: u64, more: i32) {
        if !on() {
            return;
        }
        let Some(f) = &mut FILES[video as usize].lock().unwrap().0 else { return };
        let _ = write!(f, "TID: {} {note} {} 0x{extra:x} {more} [", tid(), data.len());
        for b in data {
            let _ = write!(f, "{b:02X}");
        }
        let _ = f.write_all(b"]\n");
    }

    /// hex() of no data, to both files.
    pub fn both(note: &str, extra: u64, more: i32) {
        hex(false, note, &[], extra, more);
        hex(true, note, &[], extra, more);
    }

    /// rtpstream_shutdown(): the files written out and closed.
    pub fn close() {
        OPEN.store(false, Relaxed);
        for f in &FILES {
            if let Some(mut f) = f.lock().unwrap().0.take() {
                let _ = f.flush();
            }
        }
    }

    /// The thread's id, SIPp's tid_self().
    #[cfg(unix)]
    fn tid() -> u64 {
        // SAFETY: no arguments, no failure.
        unsafe { libc::pthread_self() as usize as u64 }
    }

    #[cfg(not(unix))]
    fn tid() -> u64 {
        0
    }

    /// A playback thread's id, as its tid() says it, SIPp's getThreadId().
    #[cfg(unix)]
    pub fn thread_id<T>(h: &std::thread::JoinHandle<T>) -> u64 {
        use std::os::unix::thread::JoinHandleExt;
        h.as_pthread_t() as usize as u64
    }

    #[cfg(not(unix))]
    pub fn thread_id<T>(_: &std::thread::JoinHandle<T>) -> u64 {
        0
    }
}

/// SIPp's global RTP counters, which the scenario screen shows.
pub mod counters {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
    use std::sync::Mutex;

    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO: AtomicU64 = AtomicU64::new(0);
    /// rtp_stream, audio then video: packets and bytes sent (header and
    /// a whole packet's payload, as rtpstream_apckts and _abytes_out), and
    /// bytes read back while streaming (_abytes_in).
    pub static STREAM_PACKETS: [AtomicU64; 2] = [ZERO; 2];
    pub static STREAM_BYTES_OUT: [AtomicU64; 2] = [ZERO; 2];
    pub static STREAM_BYTES_IN: [AtomicU64; 2] = [ZERO; 2];
    /// play_pcap_*: packets and payload bytes sent (rtp_pckts_pcap).
    pub static PCAP_PACKETS: AtomicU64 = ZERO;
    pub static PCAP_BYTES: AtomicU64 = ZERO;
    /// -rtp_echo's audio and video sockets: packets and bytes echoed.
    pub static ECHO_PACKETS: [AtomicU64; 2] = [ZERO; 2];
    pub static ECHO_BYTES: [AtomicU64; 2] = [ZERO; 2];
    /// How many calls a playback thread takes (-rtp_threadtasks), and the
    /// threads running (rtpstream_numthreads), which last until the run
    /// ends.
    pub static TASKS_PER_THREAD: AtomicU64 = AtomicU64::new(50);
    /// -mb: the size of a playback thread's receive buffer, as SIPp's
    /// media_bufsize: an echoed packet longer than it is cut to it.
    pub static MEDIA_BUFSIZE: AtomicUsize = AtomicUsize::new(2048);
    pub static THREADS: AtomicU64 = ZERO;
    /// The rates of the last display period, in kB/s: pcap, echo 1st and
    /// 2nd stream, rtp_stream audio and video out, audio and video in.
    static LAST_RATES: Mutex<[f64; 7]> = Mutex::new([0.0; 7]);

    pub fn add(c: &AtomicU64, n: u64) {
        c.fetch_add(n, Relaxed);
    }

    pub fn threads() -> u64 {
        THREADS.load(Relaxed)
    }

    /// The screen task's report, once per display period, `ms` long: its
    /// RTP rates, which every screen shows until the next one. The byte
    /// counts restart; with no time passed, the last rates stay.
    pub fn take_rates(ms: u64) {
        if ms == 0 {
            return;
        }
        let rate = |c: &AtomicU64| c.swap(0, Relaxed) as f64 / ms as f64;
        *LAST_RATES.lock().unwrap() = [
            rate(&PCAP_BYTES),
            rate(&ECHO_BYTES[0]),
            rate(&ECHO_BYTES[1]),
            rate(&STREAM_BYTES_OUT[0]),
            rate(&STREAM_BYTES_OUT[1]),
            rate(&STREAM_BYTES_IN[0]),
            rate(&STREAM_BYTES_IN[1]),
        ];
    }

    /// draw_scenario_screen()'s RTP lines, with the last period's rates.
    pub fn screen_lines(threads: u64, echo: bool) -> Vec<String> {
        let line = |left: String, right: String| format!("  {:<38.39}  {right}", left);
        let [pcap, echo1, echo2, a_out, v_out, a_in, v_in] = *LAST_RATES.lock().unwrap();
        let mut l = vec![line(format!("{} Total RTP pckts sent ", PCAP_PACKETS.load(Relaxed)), format!("{pcap:.3} last period RTP rate (kB/s)"))];
        if threads > 0 {
            l.push(line(format!("{} Total AUDIO RTP pckts sent", STREAM_PACKETS[0].load(Relaxed)), format!("{a_out:.3} kB/s AUDIO RTP OUT")));
            l.push(line(format!("{} Total VIDEO RTP pckts sent", STREAM_PACKETS[1].load(Relaxed)), format!("{v_out:.3} KB/s VIDEO RTP OUT")));
            l.push(line(format!("{threads} RTP sending threads active"), format!("{a_in:.3} kB/s AUDIO RTP IN")));
            l.push(line(format!("{threads} RTP sending threads active"), format!("{v_in:.3} KB/s VIDEO RTP IN")));
        }
        if echo {
            for (i, (which, rate)) in [("1st", echo1), ("2nd", echo2)].into_iter().enumerate() {
                let left = format!("{} Total echo RTP pckts {which} stream", ECHO_PACKETS[i].load(Relaxed));
                l.push(line(left, format!("{rate:.3} last period RTP rate (kB/s)")));
            }
        }
        l
    }
}

/// One packet's worth of a payload type, as SIPp's setRTPStreamActInfo().
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Codec {
    pub payload: u8,
    pub bytes: usize,
    pub ticks: u32,
    pub interval: Duration,
    /// SIPp's stream_type: H264 is video, the others audio.
    pub video: bool,
}

/// setRTPStreamActInfo()'s payload type and name, with its errors (and
/// their line ends).
pub fn codec(payload: i64, name: Option<&str>) -> Result<Codec, String> {
    let default_name = match payload {
        0 => "PCMU/8000",
        8 => "PCMA/8000",
        9 => "G722/8000",
        18 => "G729/8000",
        _ => "",
    };
    let name = name.filter(|n| !n.is_empty()).unwrap_or(default_name);
    if name.is_empty() {
        return Err("Missing mandatory payload_name parameter in rtp_stream action".into());
    }
    let (bytes, ms, ticks) = match (payload, name) {
        (0, "PCMU/8000") | (8, "PCMA/8000") | (9, "G722/8000") => (160, 20, 160),
        (18, "G729/8000") => (20, 20, 160),
        (13, _) => (1, 150, 1200),
        (96..=127, "H264/90000") => (1280, 160, 1280),
        (96..=127, "iLBC/8000") => (50, 30, 240),
        (0 | 8 | 9 | 18, _) => return Err(format!("rtp_stream: payload {payload} {name} is not supported")),
        (0..=95, _) => return Err(format!("Unknown static rtp payload type {payload} - cannot set playback parameters\n")),
        (96..=127, _) => return Err(format!("Unknown dynamic rtp payload type {payload} - cannot set playback parameters\n")),
        _ => return Err(format!("Invalid rtp payload type {payload} - cannot set playback parameters\n")),
    };
    let video = name == "H264/90000";
    Ok(Codec { payload: payload as u8, bytes, ticks, interval: Duration::from_millis(ms), video })
}

/// apattern/vpattern N: every payload byte is 0xAA, 0xBB, ... 0xFF.
pub fn pattern(id: u8, codec: &Codec) -> Result<Vec<u8>, String> {
    match id {
        1..=6 => Ok(vec![0xAA + 0x11 * (id - 1); codec.bytes]),
        _ => Err(format!("rtp_stream pattern {id}: must be 1 to 6")),
    }
}

/// Even local ports from -min_rtp_port up, as SIPp hands them out.
pub struct RtpPorts {
    next: u16,
    min: u16,
    max: u16,
}

impl RtpPorts {
    pub fn new(min: u16, max: u16) -> RtpPorts {
        RtpPorts { next: min, min, max }
    }

    /// A socket on the next free port, and one on the port after it for
    /// RTCP, if that is free: as SIPp, only so that the peer's RTCP draws
    /// no ICMP port unreachable.
    /// SIPp's rtpstream_get_localport(): it tries as many ports as the
    /// range has, and fails with its warning.
    pub fn bind(&mut self, ip: IpAddr) -> Result<(UdpSocket, Option<UdpSocket>), String> {
        let tries = if self.min < self.max.saturating_sub(2) { self.max - self.min } else { 1 };
        for _ in 0..tries {
            let port = self.next;
            self.next = if self.next.saturating_add(2) > self.max.saturating_sub(1) { self.min } else { self.next + 2 };
            if let Ok(s) = UdpSocket::bind(SocketAddr::new(ip, port)) {
                s.set_nonblocking(true).map_err(|_| "Could not set socket options for RTP streaming".to_string())?;
                let rtcp = port.checked_add(1).and_then(|p| UdpSocket::bind(SocketAddr::new(ip, p)).ok());
                let rtcp = rtcp.filter(|r| r.set_nonblocking(true).is_ok());
                return Ok((s, rtcp));
            }
        }
        Err(format!("Could not bind port for RTP streaming after {tries} tries"))
    }
}

thread_local! {
    /// A packet and its SRTP, kept by the thread for its next one.
    static PACKET: std::cell::RefCell<(Vec<u8>, Vec<u8>)> = const { std::cell::RefCell::new((Vec::new(), Vec::new())) };
}

/// A packet a stream sent, for -rtpcheck_debug: the RTP, whether its SRTP
/// protected it (none without SRTP), what went, and how its send went.
pub struct Sent<'a> {
    pub plain: &'a [u8],
    pub srtp: Option<bool>,
    pub packet: &'a [u8],
    pub result: &'a io::Result<usize>,
}

/// A file played as RTP, one packet every 20 ms.
pub struct Stream {
    data: Arc<Vec<u8>>,
    pos: usize,
    /// Plays left; -1 for ever.
    loops: i64,
    codec: Codec,
    /// The next packet's: a call's streams number theirs on from 0, the
    /// first's, as SIPp's.
    pub seq: u16,
    ssrc: u32,
    pub next: Instant,
    /// Its playback thread's clock is the run's, this much ahead: SIPp's
    /// shift_ms. The stream's packets go on the multiples of their packet
    /// time on it, and are stamped with it.
    pub phase: Duration,
    /// The packet time of `next` on that clock, from the first packet on.
    time: u64,
    /// It waited (paused or held) and plays again: its next packet goes
    /// as a first one.
    resumed: bool,
    pub remote: SocketAddr,
    pub paused: bool,
    /// The peer's SDP has no address for it: it waits as if paused.
    pub held: bool,
    /// SRTP for what goes out, when the SDP negotiated it.
    pub srtp: Option<srtp::Context>,
    /// -rtpcheck_debug: the peer's SRTP, to decrypt what comes back as
    /// SIPp logs it.
    pub rx: Option<srtp::Context>,
    pub sent: u64,
    /// The RTP bytes of the packets sent, header and payload, as SIPp's
    /// rtpstream_abytes_out.
    pub bytes: u64,
}

impl Stream {
    pub fn new(data: impl Into<Arc<Vec<u8>>>, loops: i64, codec: Codec, remote: SocketAddr, ssrc: u32) -> Stream {
        Stream {
            data: data.into(),
            pos: 0,
            loops: if loops == 0 { 1 } else { loops },
            codec,
            seq: 0,
            ssrc,
            next: Instant::now(),
            phase: Duration::ZERO,
            time: 0,
            resumed: false,
            remote,
            paused: false,
            held: false,
            srtp: None,
            rx: None,
            sent: 0,
            bytes: 0,
        }
    }

    /// Whether its last packet is out.
    pub fn finished(&self) -> bool {
        self.loops == 0
    }

    /// The next packet: always a whole payload, the file played in a loop
    /// into it, as often as it takes for a file shorter than a packet. The
    /// stream ends after the packet in which the file ends for the last
    /// of its loops, as SIPp's.
    /// The next packet into `p`, stamped `ts`; false once the stream has
    /// played.
    #[inline(always)]
    fn packet(&mut self, p: &mut Vec<u8>, ts: u32) -> bool {
        let len = self.data.len();
        if self.loops == 0 || len == 0 {
            return false;
        }
        p.clear();
        p.extend_from_slice(&[0x80, self.codec.payload & 0x7f]);
        p.extend_from_slice(&self.seq.to_be_bytes());
        p.extend_from_slice(&ts.to_be_bytes());
        p.extend_from_slice(&self.ssrc.to_be_bytes());
        let (mut want, mut at) = (self.codec.bytes, self.pos);
        while want > 0 {
            let n = want.min(len - at);
            p.extend_from_slice(&self.data[at..at + n]);
            (want, at) = (want - n, 0);
        }
        // What the file has left past this packet, a loop more each time
        // it ends in it.
        let mut left = len as i64 - self.pos as i64 - self.codec.bytes as i64;
        while left <= 0 {
            left += len as i64;
            if self.loops > 0 {
                self.loops -= 1;
            }
        }
        self.pos = len - left as usize;
        self.seq = self.seq.wrapping_add(1);
        true
    }

    /// It played no more (`waited`), and plays again if it does: as SIPp's
    /// thread, which finds it resumed as it next comes to the call, for
    /// the packet of one of its streams (`other`'s) or its own, it goes
    /// then, stamped with the packet time it goes in, and on from there.
    pub fn resume(&mut self, waited: bool, other: Option<Instant>) {
        if waited && !self.paused && !self.held && self.sent > 0 {
            self.resumed = true;
            self.next = other.map_or(self.next, |o| o.min(self.next));
        }
    }

    /// Sends the packets that are due; false once the file has played out.
    /// The first goes at once, the others on the multiples of their
    /// packet time on the playback thread's clock, as SIPp's (timenow_ms %
    /// ms_per_packet): all the streams of a thread go out at once, which
    /// wakes it once a packet time and not once a packet, and the threads
    /// wake up apart. Each is stamped with the packet time it is for, as
    /// SIPp's: the first with the one it goes in, and a paused stream's
    /// go by unsent.
    pub fn send_due(&mut self, sock: &UdpSocket, now: Instant) -> bool {
        PACKET.with_borrow_mut(|(plain, protected)| self.send_due_with(sock, now, usize::MAX, plain, protected, |_| {}))
    }

    /// send_due() of one packet time, for -rtpcheck_debug: `sent` has its
    /// packet, if one goes.
    pub fn send_next_traced(&mut self, sock: &UdpSocket, now: Instant, sent: impl FnMut(Sent<'_>)) -> bool {
        PACKET.with_borrow_mut(|(plain, protected)| self.send_due_with(sock, now, 1, plain, protected, sent))
    }

    fn send_due_with(&mut self, sock: &UdpSocket, now: Instant, mut times: usize, plain: &mut Vec<u8>, protected: &mut Vec<u8>, mut sent: impl FnMut(Sent<'_>)) -> bool {
        while self.next <= now && times > 0 {
            times -= 1;
            let paused = self.paused || self.held;
            let first = (self.sent == 0 || self.resumed) && !paused;
            if first {
                self.resumed = false;
                // The packet time it goes in, on the thread's clock.
                let interval = self.codec.interval.as_nanos() as u64;
                let clock = now.saturating_duration_since(crate::call::epoch()) + self.phase;
                self.time = clock.as_nanos() as u64 / interval;
                self.next = crate::call::epoch() + (Duration::from_nanos((self.time + 1) * interval) - self.phase);
            } else {
                self.next += self.codec.interval;
            }
            let time = self.time;
            self.time += 1;
            if paused {
                continue;
            }
            if !self.packet(plain, time.wrapping_mul(u64::from(self.codec.ticks)) as u32) {
                return false;
            }
            // A packet that does not protect goes as it is.
            let srtp = self.srtp.as_mut().map(|ctx| ctx.protect_into(plain, protected));
            let p = if srtp == Some(true) { &protected[..] } else { &plain[..] };
            let result = sock.send_to(p, self.remote);
            sent(Sent { plain, srtp, packet: p, result: &result });
            if result.is_ok() {
                self.sent += 1;
                self.bytes += plain.len() as u64;
            }
        }
        true
    }
}

/// An rtp_stream file, with SIPp's error; SIPp cannot read an empty one.
pub fn read_stream_file(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).ok().filter(|d| !d.is_empty()).ok_or_else(|| format!("Cannot read/cache rtpstream file {path}"))
}

/// The samples of an rtp_stream file, read once and shared by its plays,
/// as SIPp's rtpstream_cache_file() does: of a WAV file, its audio mixed
/// down to one channel, with SIPp's warnings as it caches it.
pub fn stream_file(path: &str, log: &mut crate::log::Log) -> Result<Arc<Vec<u8>>, String> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, Arc<Vec<u8>>>>> = std::sync::OnceLock::new();
    let mut cache = CACHE.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner());
    if let Some(data) = cache.get(path) {
        return Ok(data.clone());
    }
    let data = Arc::new(wav_payload(read_stream_file(path)?, path, |w| log.warning(&w)));
    cache.insert(path.to_string(), data.clone());
    Ok(data)
}

/// Where the peer's SDP sends each media, scanned as SIPp scans it: a
/// media section's own c= line, else the session one (RFC 4566 5.7).
pub mod sdp {
    /// The first `needle` from `from` on: its first byte found with
    /// memchr(), then the rest compared, not a compare at each byte.
    fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
        let (&first, rest) = needle.split_first()?;
        let mut at = from;
        loop {
            let h = hay.get(at..)?;
            // SAFETY: memchr() reads h's own bytes, and finds one of them or none.
            let found = unsafe { libc::memchr(h.as_ptr().cast(), first.into(), h.len()) };
            if found.is_null() {
                return None;
            }
            let i = at + (found as usize - h.as_ptr() as usize);
            if hay[i + 1..].starts_with(rest) {
                return Some(i);
            }
            at = i + 1;
        }
    }

    /// find_in_sdp(): what follows the first `pattern` in `part` up to a
    /// space, a slash (a port count, a TTL) or the end of the line; empty
    /// if there is none.
    fn find_in_sdp<'a>(pattern: &str, part: &'a [u8]) -> &'a [u8] {
        let Some(begin) = find(part, pattern.as_bytes(), 0).map(|b| b + pattern.len()) else { return &[] };
        match part[begin..].iter().position(|c| b" /\r\n".contains(c)) {
            Some(n) => &part[begin..begin + n],
            None => &[],
        }
    }

    /// The address of the c= line of a part of an SDP, empty if it has
    /// none, and whether it is an IPv6 one.
    fn connection(part: &[u8]) -> (&[u8], bool) {
        match find_in_sdp("c=IN IP4 ", part) {
            [] => (find_in_sdp("c=IN IP6 ", part), true),
            host => (host, false),
        }
    }

    /// The media section from its m= line at `pos` to the next one.
    fn section(sdp: &[u8], pos: usize) -> &[u8] {
        &sdp[pos..find(sdp, b"\nm=", pos + 1).unwrap_or(sdp.len())]
    }

    /// The connection address of a media section: that of its own c=
    /// line, else that of the session part before the first m= line.
    fn media_connection<'a>(sdp: &'a [u8], section: &'a [u8]) -> (&'a [u8], bool) {
        match connection(section) {
            ([], _) => connection(&sdp[..find(sdp, b"\nm=", 0).unwrap_or(sdp.len())]),
            c => c,
        }
    }

    fn text(b: &[u8]) -> String {
        String::from_utf8_lossy(b).into_owned()
    }

    /// Where rtp_stream sends a kind of media (SIPp's
    /// extract_rtp_remote_addr()): the address and the port of the first
    /// m= line of the kind, or of the second one when the first has port
    /// 0; None when neither has a port. The error of SIPp's when there is
    /// no c= line for it.
    pub fn stream_remote(msg: &str, kind: &str) -> Result<Option<(String, u16)>, String> {
        let Some(body) = crate::sip::body_start(msg) else { return Ok(None) };
        // From the blank line, so that every line starts with '\n'.
        let sdp = &msg.as_bytes()[body + 2..];
        let prefix = format!("\nm={kind}");
        let (mut pos, mut port, mut media) = (Some(0), 0, &sdp[..0]);
        for _ in 0..2 {
            let Some(at) = pos.and_then(|p| find(sdp, prefix.as_bytes(), p)) else { break };
            media = section(sdp, at);
            // The prefix and the blank after it, then the port up to a space.
            let from = at + prefix.len() + 1;
            let end = find(sdp, b" ", from);
            port = end.map_or(0, |end| {
                let digits = &sdp[from.min(end)..end];
                let n = digits.iter().take_while(|c| c.is_ascii_digit()).count();
                std::str::from_utf8(&digits[..n]).ok().and_then(|d| d.parse().ok()).unwrap_or(0)
            });
            pos = end;
            if port != 0 {
                break;
            }
        }
        if port == 0 {
            return Ok(None);
        }
        match media_connection(sdp, media) {
            ([], _) => Err(format!("extract_rtp_remote_addr: no c= line for m={kind} in SDP message body")),
            (host, _) => Ok(Some((text(host), port))),
        }
    }

    /// Whether the message has a c= line of the IP version (SIPp's check
    /// that it has some media information).
    pub fn has_connection(msg: &str, ipv6: bool) -> bool {
        !find_in_sdp(if ipv6 { "c=IN IP6 " } else { "c=IN IP4 " }, msg.as_bytes()).is_empty()
    }

    /// Where a pcap play of a kind goes (SIPp's get_remote_media_addr()):
    /// the address, its IP version and the port of the first m= line of
    /// the kind, or of the second one when the first has port 0 (a stream
    /// refused, RFC 3264 6); None without a port or an address.
    pub fn pcap_remote(msg: &str, kind: &str) -> Option<(String, bool, String)> {
        let msg = msg.as_bytes();
        let prefix = format!("\nm={kind} ");
        let (mut pos, mut port, mut media) = (find(msg, prefix.as_bytes(), 0), &b""[..], &b""[..]);
        for _ in 0..2 {
            let Some(at) = pos else { break };
            media = section(msg, at);
            port = find_in_sdp(&prefix[1..], media);
            if port != b"0" {
                break;
            }
            pos = find(msg, prefix.as_bytes(), at + 1);
        }
        if port.is_empty() || port == b"0" {
            return None;
        }
        match media_connection(msg, media) {
            ([], _) => None,
            (host, ipv6) => Some((text(host), ipv6, text(port))),
        }
    }

    #[cfg(test)]
    #[test]
    fn find_is_the_first_match() {
        let naive = |hay: &[u8], needle: &[u8], from: usize| hay.get(from..)?.windows(needle.len()).position(|w| w == needle).map(|i| from + i);
        let hay = b"m=audio\nm=aud\nm=audio 0\nc=IN IP4 \nm=audio 5\nmm=";
        for needle in [&b"\nm="[..], b"\nm=audio ", b"m", b"mm=", b"c=IN IP4 ", b"=", b"x", b"5\nmm=x"] {
            for from in 0..=hay.len() + 1 {
                assert_eq!(find(hay, needle, from), naive(hay, needle, from), "{needle:?} {from}");
            }
        }
    }
}

/// The audio of an rtp_stream file, as SIPp's wav_audio_t: where it
/// starts in the file and its size, and the fields of a WAV file's fmt
/// chunk (rate 0: none).
#[derive(Debug, Clone, Copy, PartialEq)]
struct WavAudio {
    offset: usize,
    size: usize,
    format: u16,
    channels: u16,
    rate: u32,
    block_align: u16,
    bits: u16,
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

/// SIPp's rtpstream_wav_audio(): the data chunk of a WAV file, of its
/// declared size, after a walk of its chunks that a bogus size ends. A
/// file of no RIFF header plays whole, a RIFF file of another form past
/// its RIFF header, one of a chunk past its end whole, and one of no data
/// chunk from past its last chunk.
fn wav_audio(data: &[u8]) -> WavAudio {
    let size = data.len();
    let whole = WavAudio { offset: 0, size, format: 0, channels: 1, rate: 0, block_align: 0, bits: 0 };
    if size < 42 || &data[..4] != b"RIFF" {
        return whole;
    }
    if &data[8..12] != b"WAVE" {
        return WavAudio { offset: 8, size: size - 8, ..whole };
    }
    let (mut audio, mut pos) = (whole, 12);
    while pos + 8 <= size {
        let id = &data[pos..pos + 4];
        let chunk = le32(data, pos + 4) as usize;
        pos += 8;
        if id == b"data" {
            return WavAudio { offset: pos, size: chunk.min(size - pos), ..audio };
        }
        if id == b"fmt " && chunk >= 16 && size - pos >= 16 {
            let fmt = &data[pos..];
            (audio.format, audio.channels, audio.rate) = (le16(fmt, 0), le16(fmt, 2), le32(fmt, 4));
            (audio.block_align, audio.bits) = (le16(fmt, 12), le16(fmt, 14));
            // WAVE_FORMAT_EXTENSIBLE: the format is in its SubFormat.
            if audio.format == 0xFFFE && chunk >= 40 && size - pos >= 40 {
                audio.format = le16(fmt, 24);
            }
        }
        if chunk > size - pos {
            return whole;
        }
        // Each chunk is padded to an even size.
        pos += chunk + (chunk & 1);
    }
    audio.offset = pos.min(size);
    audio.size = size - audio.offset;
    audio
}

/// SIPp's rtpstream_wav_mix_down(): the channels of a WAV file's audio
/// mixed down to the one of an RTP stream, in place. Only linear PCM
/// (format 1) of 8-bit unsigned or 16-bit signed samples mixes, as the
/// mean of its channels; of the other formats of whole-byte samples, such
/// as A-law (6) and mu-law (7), the first channel plays, and other
/// formats play as they are.
fn wav_mix_down(data: &mut Vec<u8>, audio: &WavAudio, path: &str, mut warn: impl FnMut(String)) {
    let (channels, sample, block) = (audio.channels as usize, audio.bits as usize / 8, audio.block_align as usize);
    if channels <= 1 {
        return;
    }
    if sample == 0 || !audio.bits.is_multiple_of(8) || block != channels * sample {
        warn(format!("rtp_stream file {path}: {channels} channels of format {} do not mix, playing them as they are", audio.format));
        return;
    }
    let pcm = audio.format == 1 && sample <= 2;
    if !pcm {
        warn(format!("rtp_stream file {path}: {channels} channels of format {} do not mix, playing the first one", audio.format));
    }
    let frames = data.len() / block;
    for i in 0..frames {
        let (from, to) = (i * block, i * sample);
        if !pcm {
            data.copy_within(from..from + sample, to);
            continue;
        }
        let frame = &data[from..from + block];
        let sum: i64 = match sample {
            1 => frame.iter().map(|&b| i64::from(b) - 128).sum(),
            _ => frame.as_chunks::<2>().0.iter().map(|&s| i64::from(i16::from_le_bytes(s))).sum(),
        };
        // Truncated towards zero, as SIPp's.
        let mean = sum / channels as i64;
        if sample == 1 {
            data[to] = (mean + 128) as u8;
        } else {
            data[to..to + 2].copy_from_slice(&(mean as i16).to_le_bytes());
        }
    }
    data.truncate(frames * sample);
}

/// What SIPp plays of an rtp_stream file (rtpstream_cache_file()): of a
/// WAV file, its audio mixed down to one channel, in the memory of the
/// file, not resampled, with SIPp's warnings for what does not mix or is
/// not 8 kHz.
pub fn wav_payload(mut data: Vec<u8>, path: &str, mut warn: impl FnMut(String)) -> Vec<u8> {
    let audio = wav_audio(&data);
    if matches!(audio.format, 1 | 6 | 7) && audio.rate != 8000 {
        warn(format!("rtp_stream file {path}: {} Hz plays at the rate of the payload type, not resampled", audio.rate));
    }
    data.truncate(audio.offset + audio.size);
    data.drain(..audio.offset);
    wav_mix_down(&mut data, &audio, path, warn);
    data.shrink_to_fit();
    data
}

/// The <exec rtp_echo> switch of -rtp_echo, SIPp's rtp_echo_state.
pub static ECHO_ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// -rtp_echo: what arrives on the media ports goes back where it came from.
pub struct Echo {
    socks: Vec<UdpSocket>,
}

impl Echo {
    /// Binds audio and video (the port two above), moving up two at a time
    /// while taken, as SIPp does. Returns the audio port.
    /// A failure has the socket SIPp names, and its error.
    pub fn bind(ip: IpAddr, first: u16, max: u16) -> Result<(Echo, u16), (String, io::Error)> {
        let mut port = first;
        let mut attempt = 1;
        loop {
            let pair = (UdpSocket::bind(SocketAddr::new(ip, port)), UdpSocket::bind(SocketAddr::new(ip, port + 2)));
            match pair {
                (Ok(a), Ok(v)) => {
                    let set = a.set_nonblocking(true).and_then(|_| v.set_nonblocking(true));
                    set.map_err(|e| (format!("Unable to bind audio RTP socket (IP={ip}, port={port})"), e))?;
                    return Ok((Echo { socks: vec![a, v] }, port));
                }
                (Err(e), _) if attempt >= 100 || port.saturating_add(4) > max => return Err((format!("Unable to bind audio RTP socket (IP={ip}, port={port})"), e)),
                (_, Err(e)) if attempt >= 100 || port.saturating_add(4) > max => return Err((format!("Unable to bind video RTP socket (IP={ip}, port={})", port + 2), e)),
                _ => {
                    port += 2;
                    attempt += 1;
                }
            }
        }
    }

    /// SIPp's rtp_echo_thread(): one for audio, one for video, until the
    /// process ends.
    pub fn start(&self) -> io::Result<()> {
        for (i, s) in self.socks.iter().enumerate() {
            let s = s.try_clone()?;
            s.set_nonblocking(false)?;
            std::thread::Builder::new().name("rtp_echo".into()).stack_size(crate::mediapool::THREAD_STACK).spawn(move || {
                block_signals();
                // -mb: what is longer is cut to it, as in SIPp.
                let mut buf = vec![0u8; counters::MEDIA_BUFSIZE.load(std::sync::atomic::Ordering::Relaxed)];
                // An error stops the echo on this socket, with SIPp's
                // warning.
                let stop = |what: &str, e: io::Error| {
                    crate::log::defer_thread_warning(format!("Error on RTP echo {what} - stopping echo - errno= {}", e.raw_os_error().unwrap_or(0)));
                };
                loop {
                    let (n, from) = match s.recv_from(&mut buf) {
                        Ok(got) => got,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(e) => return stop("reception", e),
                    };
                    if !ECHO_ON.load(std::sync::atomic::Ordering::Relaxed) {
                        continue;
                    }
                    match s.send_to(&buf[..n], from) {
                        Ok(sent) => {
                            counters::add(&counters::ECHO_PACKETS[i], 1);
                            counters::add(&counters::ECHO_BYTES[i], sent as u64);
                        }
                        Err(e) => return stop("transmission", e),
                    }
                }
            })?;
        }
        Ok(())
    }
}

/// Signals go to the engine's thread, as SIPp's other threads mask them.
pub fn block_signals() {
    crate::sys::block_signals();
}

#[cfg(test)]
mod wav_tests {
    use super::{wav_audio, wav_payload};

    fn le16(v: u32) -> Vec<u8> {
        (v as u16).to_le_bytes().to_vec()
    }

    fn le32(v: u32) -> Vec<u8> {
        v.to_le_bytes().to_vec()
    }

    /// A RIFF chunk: its id, a size, its body and a pad byte to even size.
    fn chunk_sized(id: &[u8; 4], body: &[u8], size: u32) -> Vec<u8> {
        let mut out = [&id[..], &le32(size), body].concat();
        if body.len() % 2 == 1 {
            out.push(0);
        }
        out
    }

    fn chunk(id: &[u8; 4], body: &[u8]) -> Vec<u8> {
        chunk_sized(id, body, body.len() as u32)
    }

    fn fmt(format: u32, channels: u32, bits: u32, rate: u32) -> Vec<u8> {
        let block = channels * bits / 8;
        chunk(b"fmt ", &[le16(format), le16(channels), le32(rate), le32(rate * block), le16(block), le16(bits)].concat())
    }

    fn file(chunks: &[Vec<u8>]) -> Vec<u8> {
        let chunks = chunks.concat();
        [&b"RIFF"[..], &le32(4 + chunks.len() as u32), b"WAVE", &chunks].concat()
    }

    fn audio_of(file: &[u8]) -> Vec<u8> {
        let a = wav_audio(file);
        file[a.offset..a.offset + a.size].to_vec()
    }

    /// What rtp_stream plays of a file, and the warnings it caches it with.
    fn cached(file: &[u8]) -> (Vec<u8>, Vec<String>) {
        let mut warnings = Vec::new();
        (wav_payload(file.to_vec(), "f.wav", |w| warnings.push(w)), warnings)
    }

    #[test]
    fn mono_pcm() {
        let audio = vec![b'a'; 100];
        let f = file(&[fmt(1, 1, 8, 8000), chunk(b"data", &audio)]);
        let a = wav_audio(&f);
        assert_eq!((a.offset, a.size, a.format, a.channels, a.rate, a.bits), (44, 100, 1, 1, 8000, 8));
        assert_eq!(cached(&f), (audio, vec![]));
    }

    #[test]
    fn data_size() {
        let audio = vec![b'a'; 100];
        // The declared size plays, not a chunk after it.
        assert_eq!(audio_of(&file(&[fmt(7, 1, 8, 8000), chunk(b"data", &audio), chunk(b"LIST", b"INFOjunk")])), audio);
        // Of a data chunk past the end of the file, what there is.
        assert_eq!(audio_of(&file(&[fmt(7, 1, 8, 8000), chunk_sized(b"data", &audio, 1000)])), audio);
        assert_eq!(audio_of(&file(&[fmt(7, 1, 8, 8000), chunk_sized(b"data", &audio, u32::MAX)])), audio);
        assert_eq!(audio_of(&file(&[fmt(7, 1, 8, 8000), chunk(b"data", b"")])), b"");
    }

    #[test]
    fn odd_chunk_padding() {
        let audio = vec![b'a'; 100];
        let f = file(&[chunk(b"LIST", b"odd"), fmt(6, 1, 8, 8000), chunk(b"data", &audio)]);
        let a = wav_audio(&f);
        assert_eq!((a.offset, a.format), (56, 6));
        assert_eq!(audio_of(&f), audio);
    }

    #[test]
    fn chunk_past_the_end() {
        // 8 + 0xFFFFFFF8 wraps to 0 in 32 bits: this looped forever in SIPp.
        let f = file(&[fmt(1, 2, 16, 8000), [&b"JUNK"[..], &le32(0xFFFF_FFF8)].concat(), chunk(b"data", &[b'a'; 100])]);
        let a = wav_audio(&f);
        assert_eq!((a.offset, a.size, a.channels), (0, f.len(), 1));
        assert_eq!(cached(&f), (f, vec![]));
    }

    #[test]
    fn no_fmt() {
        let audio = vec![b'a'; 100];
        // Of no fmt chunk, or one too short, the data plays as it is.
        assert_eq!(audio_of(&file(&[chunk(b"data", &audio)])), audio);
        assert_eq!(cached(&file(&[chunk(b"data", &audio)])).0, audio);
        let f = file(&[chunk(b"fmt ", &[le16(1), le16(2)].concat()), chunk(b"data", &audio)]);
        let a = wav_audio(&f);
        assert_eq!((a.channels, a.rate), (1, 0));
        assert_eq!(cached(&f), (audio, vec![]));
    }

    #[test]
    fn not_wav() {
        let raw = vec![b'a'; 100];
        assert_eq!(audio_of(&raw), raw);
        assert_eq!(cached(&raw).0, raw);
        // A RIFF header too short to be of a WAV file.
        let riff = file(&[chunk(b"data", b"abc")]);
        assert_eq!(audio_of(&riff), riff);
        // A WAV file of no data chunk: past its last chunk.
        assert_eq!(audio_of(&file(&[fmt(1, 1, 16, 8000), chunk(b"LIST", b"INFOjunk")])), b"");
        // A RIFF file of another form: past its RIFF header.
        let avi = [&b"RIFF"[..], &le32(100), b"AVI ", &[b'a'; 40]].concat();
        assert_eq!(audio_of(&avi), &avi[8..]);
    }

    #[test]
    fn mix_down_16() {
        let v = |n: i16| le16(n as u16 as u32);
        let audio = [v(1000), v(3000), v(-1000), v(-3001), v(32767), v(32767), v(-32768), v(-32768), b"x".to_vec()].concat();
        let mix = [v(2000), v(-2000), v(32767), v(-32768)].concat();
        assert_eq!(cached(&file(&[chunk(b"LIST", b"odd"), fmt(1, 2, 16, 8000), chunk(b"data", &audio)])), (mix, vec![]));
    }

    #[test]
    fn mix_down_8() {
        // Unsigned, of silence at 128.
        let audio = b"\xC8\x64\x00\xFF\x80\x81\x10\x20\x30";
        assert_eq!(cached(&file(&[fmt(1, 2, 8, 8000), chunk(b"data", audio)])).0, b"\x96\x80\x80\x18");
    }

    #[test]
    fn g711_first_channel() {
        let audio = b"\x11\x22\x33\x44\x55\x66";
        let first = |format| format!("rtp_stream file f.wav: 2 channels of format {format} do not mix, playing the first one");
        assert_eq!(cached(&file(&[fmt(6, 2, 8, 8000), chunk(b"data", audio)])), (b"\x11\x33\x55".to_vec(), vec![first(6)]));
        assert_eq!(cached(&file(&[fmt(7, 2, 8, 8000), chunk(b"data", audio)])), (b"\x11\x33\x55".to_vec(), vec![first(7)]));
        // 24-bit PCM, which does not mix either.
        assert_eq!(cached(&file(&[fmt(1, 2, 24, 8000), chunk(b"data", audio)])), (b"\x11\x22\x33".to_vec(), vec![first(1)]));
    }

    #[test]
    fn extensible() {
        let audio = [le16(1000), le16(3000)].concat();
        // WAVE_FORMAT_EXTENSIBLE of 2 16-bit channels of a SubFormat.
        let fmt = [le16(0xFFFE), le16(2), le32(8000), le32(32000), le16(4), le16(16), le16(22), le16(16), le32(3)].concat();
        let guid = b"\x00\x00\x00\x00\x10\x00\x80\x00\x00\xAA\x00\x38\x9B\x71";
        let pcm = file(&[chunk(b"fmt ", &[&fmt[..], &le16(1), guid].concat()), chunk(b"data", &audio)]);
        assert_eq!(wav_audio(&pcm).format, 1);
        assert_eq!(cached(&pcm), (le16(2000), vec![]));
        let ulaw = file(&[chunk(b"fmt ", &[&fmt[..], &le16(7), guid].concat()), chunk(b"data", &audio)]);
        assert_eq!(wav_audio(&ulaw).format, 7);
        assert_eq!(cached(&ulaw).0, le16(1000));
        // Of no SubFormat, it does not mix.
        let none = file(&[chunk(b"fmt ", &fmt[..18]), chunk(b"data", &audio)]);
        assert_eq!(wav_audio(&none).format, 0xFFFE);
        assert_eq!(cached(&none), (le16(1000), vec!["rtp_stream file f.wav: 2 channels of format 65534 do not mix, playing the first one".to_string()]));
    }

    #[test]
    fn unmixable() {
        // 4-bit IMA ADPCM plays as it is.
        let audio = vec![b'a'; 100];
        let warning = "rtp_stream file f.wav: 2 channels of format 17 do not mix, playing them as they are";
        assert_eq!(cached(&file(&[fmt(0x11, 2, 4, 8000), chunk(b"data", &audio)])), (audio, vec![warning.to_string()]));
    }

    #[test]
    fn rate() {
        let f = file(&[fmt(1, 1, 16, 16000), chunk(b"data", &[0; 4])]);
        assert_eq!(cached(&f).1, ["rtp_stream file f.wav: 16000 Hz plays at the rate of the payload type, not resampled"]);
        // Not of a format it would know the rate of.
        assert_eq!(cached(&file(&[fmt(0x11, 1, 4, 16000), chunk(b"data", &[0; 4])])).1, Vec::<String>::new());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn next_packet(s: &mut Stream) -> Option<Vec<u8>> {
        let mut p = Vec::new();
        s.packet(&mut p, 0x01020304).then_some(p)
    }

    #[test]
    fn rtp_screen_lines() {
        use counters::*;
        add(&PCAP_PACKETS, 3);
        add(&PCAP_BYTES, 480);
        add(&STREAM_PACKETS[0], 50);
        add(&STREAM_BYTES_OUT[0], 50 * 172);
        add(&ECHO_PACKETS[0], 2);
        add(&ECHO_BYTES[0], 344);
        take_rates(1000);
        let l = screen_lines(1, true);
        assert_eq!(l[0], "  3 Total RTP pckts sent                  0.480 last period RTP rate (kB/s)");
        assert_eq!(l[1], "  50 Total AUDIO RTP pckts sent           8.600 kB/s AUDIO RTP OUT");
        assert_eq!(l[2], "  0 Total VIDEO RTP pckts sent            0.000 KB/s VIDEO RTP OUT");
        assert_eq!(l[3], "  1 RTP sending threads active            0.000 kB/s AUDIO RTP IN");
        assert_eq!(l[5], "  2 Total echo RTP pckts 1st stream       0.344 last period RTP rate (kB/s)");
        // Every screen until the next period shows the same rates, and
        // with no time passed, the period's rates stay.
        assert_eq!(screen_lines(1, true), l);
        take_rates(0);
        let l = screen_lines(1, false);
        assert_eq!(l.len(), 5);
        assert!(l[0].ends_with(" 0.480 last period RTP rate (kB/s)"), "{}", l[0]);
        assert!(l[1].ends_with(" 8.600 kB/s AUDIO RTP OUT"), "{}", l[1]);
        // A new period restarts the counts.
        take_rates(1000);
        assert!(screen_lines(1, false)[1].ends_with(" 0.000 kB/s AUDIO RTP OUT"));
    }

    #[test]
    fn sdp_stream_remote() {
        let audio = |m: &str| sdp::stream_remote(m, "audio");
        let msg = "SIP/2.0 200 OK\r\nContent-Type: application/sdp\r\n\r\nv=0\r\nc=IN IP4 10.1.2.3\r\nm=video 7000 RTP/AVP 31\r\nm=audio 5071 RTP/AVP 8 0\r\n";
        assert_eq!(audio(msg), Ok(Some(("10.1.2.3".into(), 5071))));
        assert_eq!(audio("SIP/2.0 200 OK\r\n\r\n"), Ok(None));
        let media_level = "X\r\n\r\nc=IN IP4 1.1.1.1\r\nm=audio 4000 RTP/AVP 0\r\nc=IN IP4 2.2.2.2\r\n";
        assert_eq!(audio(media_level), Ok(Some(("2.2.2.2".into(), 4000))));
        // A port count and a TTL (C c89e796).
        let counted = "X\r\n\r\nv=0\r\nc=IN IP4 224.2.1.1/127\r\nm=audio 30000/2 RTP/AVP 0 101\r\n";
        assert_eq!(audio(counted), Ok(Some(("224.2.1.1".into(), 30000))));
        // The second m= line of a kind when the first has port 0, with the
        // c= line of its own section; another section's c= is not the
        // session's.
        let msg = "SIP/2.0 200 OK\r\n\r\nv=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 0 RTP/AVP 0\r\nc=IN IP4 192.0.2.3\r\n\
            m=video 7000 RTP/AVP 31\r\nc=IN IP4 192.0.2.2\r\nm=audio 6000 RTP/AVP 0\r\n";
        assert_eq!(audio(msg), Ok(Some(("192.0.2.1".into(), 6000))));
        assert_eq!(sdp::stream_remote(msg, "video"), Ok(Some(("192.0.2.2".into(), 7000))));
        let v6 = "X\r\n\r\nv=0\r\nc=IN IP6 ::1\r\nm=audio 0 RTP/AVP 0\r\nm=video 7000/2 RTP/AVP 31\r\nm=audio 6000 RTP/AVP 0\r\n";
        assert_eq!(audio(v6), Ok(Some(("::1".into(), 6000))));
        // Only media-level c= lines: none for audio is SIPp's error.
        let media_only = "X\r\n\r\nv=0\r\nm=audio 6000 RTP/AVP 0\r\nm=video 7000 RTP/AVP 31\r\nc=IN IP4 192.0.2.2\r\n";
        assert_eq!(audio(media_only), Err("extract_rtp_remote_addr: no c= line for m=audio in SDP message body".into()));
        assert_eq!(sdp::stream_remote(media_only, "video"), Ok(Some(("192.0.2.2".into(), 7000))));
        assert_eq!(audio("X\r\n\r\nv=0\r\nm=audio 0 RTP/AVP 0\r\n"), Ok(None));
    }

    #[test]
    fn sdp_pcap_remote() {
        let msg = "X\r\n\r\nv=0\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=audio 6000 RTP/AVP 0\r\n\
            m=video 7000 RTP/AVP 31\r\nc=IN IP6 2001:db8::2\r\nm=image 8000 udptl t38\r\n";
        assert_eq!(sdp::pcap_remote(msg, "audio"), Some(("192.0.2.1".into(), false, "6000".into())));
        assert_eq!(sdp::pcap_remote(msg, "video"), Some(("2001:db8::2".into(), true, "7000".into())));
        assert_eq!(sdp::pcap_remote(msg, "image"), Some(("192.0.2.1".into(), false, "8000".into())));
        assert!(sdp::has_connection(msg, false) && sdp::has_connection(msg, true));
        // An m=text line, after a refused video (C's remote_media_addr_of_text).
        let text = "X\r\n\r\nv=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 6000 RTP/AVP 0\r\nm=video 0 RTP/AVP 31\r\n\
            m=text 8000 RTP/AVP 98 100\r\na=rtpmap:98 t140/1000\r\na=rtpmap:100 red/1000\r\n";
        assert_eq!(sdp::pcap_remote(text, "text"), Some(("192.0.2.1".into(), false, "8000".into())));
        // The second m= line of a kind when the first has port 0, with its
        // own c= line (C's remote_media_addr_skips_zero_port); none when
        // that one is refused too.
        let zero = "X\r\n\r\nv=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 0 RTP/AVP 0\r\n\
            m=video 7000 RTP/AVP 31\r\nm=audio 6000 RTP/AVP 8\r\nc=IN IP4 192.0.2.3\r\n";
        assert_eq!(sdp::pcap_remote(zero, "audio"), Some(("192.0.2.3".into(), false, "6000".into())));
        assert_eq!(sdp::pcap_remote(zero, "video"), Some(("192.0.2.1".into(), false, "7000".into())));
        let refused = "X\r\n\r\nc=IN IP4 192.0.2.1\r\nm=audio 0 RTP/AVP 0\r\nm=audio 0 RTP/AVP 8\r\nm=audio 6000 RTP/AVP 8\r\n";
        assert_eq!(sdp::pcap_remote(refused, "audio"), None);
        assert_eq!(sdp::pcap_remote("X\r\n\r\nc=IN IP4 192.0.2.1\r\nm=audio 0 RTP/AVP 0\r\n", "audio"), None);
        assert_eq!(sdp::pcap_remote("X\r\n\r\nm=audio 6000 RTP/AVP 0\r\n", "audio"), None);
        assert!(!sdp::has_connection("X\r\n\r\nm=audio 6000 RTP/AVP 0\r\n", false));
    }

    #[test]
    fn stream_packets_loop_and_end() {
        let remote = "127.0.0.1:9".parse().unwrap();
        let mut s = Stream::new(vec![7; 200], 2, codec(8, Some("PCMA/8000")).unwrap(), remote, 0x01020304);
        let sizes: Vec<usize> = std::iter::from_fn(|| next_packet(&mut s)).map(|p| p.len()).collect();
        // 200 bytes played twice, 160 at a time after a 12-byte header: the
        // packets are whole, the file wrapping into them, and the stream
        // ends with the packet in which it ends the second time.
        assert_eq!(sizes, vec![172, 172, 172]);
        let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut s = Stream::new(vec![7; 200], 1, codec(8, Some("PCMA/8000")).unwrap(), sink.local_addr().unwrap(), 1);
        // The first goes at once, the next as they are due.
        assert!(s.send_due(&sock, s.next));
        assert!(!s.send_due(&sock, Instant::now() + Duration::from_secs(1)));
        assert_eq!((s.sent, s.bytes), (2, 2 * 172));
        // A file shorter than a packet fills it as often as it takes, each
        // time a loop.
        let file: Vec<u8> = (0..100).collect();
        let mut s = Stream::new(file.clone(), 3, codec(0, None).unwrap(), remote, 1);
        let packets: Vec<Vec<u8>> = std::iter::from_fn(|| next_packet(&mut s)).map(|p| p[12..].to_vec()).collect();
        let played: Vec<u8> = file.iter().copied().cycle().take(320).collect();
        assert_eq!(packets, [played[..160].to_vec(), played[160..].to_vec()]);
        let mut s = Stream::new(vec![1, 2, 3], 1, codec(0, None).unwrap(), remote, 0x01020304);
        let p = next_packet(&mut s).unwrap();
        assert_eq!(&p[..12], &[0x80, 0, 0, 0, 1, 2, 3, 4, 1, 2, 3, 4]);
        assert_eq!(codec(96, None).unwrap_err(), "Missing mandatory payload_name parameter in rtp_stream action");
        assert_eq!(codec(97, Some("x")).unwrap_err(), "Unknown dynamic rtp payload type 97 - cannot set playback parameters\n");
        assert_eq!(codec(300, Some("x")).unwrap_err(), "Invalid rtp payload type 300 - cannot set playback parameters\n");
    }

    #[test]
    fn stream_timestamps_follow_the_thread_clock() {
        let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
        sink.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let ms = |n: u64| crate::call::epoch() + Duration::from_millis(n);
        let stamps = |s: &mut Stream, now: Instant| {
            let before = s.sent;
            s.send_due(&sock, now);
            let mut buf = [0u8; 300];
            let mut got = Vec::new();
            for _ in before..s.sent {
                let n = sink.recv(&mut buf).unwrap();
                got.push((u16::from_be_bytes([buf[2], buf[3]]), u32::from_be_bytes(buf[4..8].try_into().unwrap()), n));
            }
            got
        };
        // A thread 7 ms ahead: the first packet goes at once, stamped with
        // the packet time it goes in, 20 ms on its clock (8 ticks a ms);
        // the next ones on the next multiples of 20 ms, 33 ms and on.
        let mut s = Stream::new(vec![1; 1600], 1, codec(0, None).unwrap(), sink.local_addr().unwrap(), 1);
        (s.phase, s.next) = (Duration::from_millis(7), ms(15));
        assert_eq!(stamps(&mut s, ms(15)).iter().map(|p| p.1).collect::<Vec<_>>(), [160]);
        assert_eq!(s.next, ms(33));
        assert_eq!(stamps(&mut s, ms(53)).iter().map(|p| p.1).collect::<Vec<_>>(), [320, 480]);
        // Paused, its packet times go by: it is stamped on after them.
        s.paused = true;
        s.send_due(&sock, ms(113));
        s.paused = false;
        s.resume(true, None);
        assert_eq!(stamps(&mut s, ms(133)).iter().map(|p| (p.0, p.1)).collect::<Vec<_>>(), [(3, 1120)]);
        // Resumed with another stream of the call's packet before its own
        // next: it goes then, for the packet time it goes in.
        s.paused = true;
        s.send_due(&sock, ms(153));
        s.paused = false;
        s.resume(true, Some(ms(165)));
        assert_eq!(stamps(&mut s, ms(165)).iter().map(|p| (p.0, p.1)).collect::<Vec<_>>(), [(4, 1280)]);
        assert_eq!(s.next, ms(173));
    }

    #[test]
    fn rtcp_on_the_next_port_when_free() {
        let ip = IpAddr::from([127, 0, 0, 1]);
        let mut ports = RtpPorts::new(41_010, 41_050);
        let (rtp, rtcp) = ports.bind(ip).unwrap();
        let port = rtp.local_addr().unwrap().port();
        assert_eq!(rtcp.unwrap().local_addr().unwrap().port(), port + 1);
        // The next pair's RTCP port is taken: RTP goes ahead without it.
        let _taken = UdpSocket::bind(SocketAddr::new(ip, port + 3)).unwrap();
        let (rtp, rtcp) = ports.bind(ip).unwrap();
        assert_eq!(rtp.local_addr().unwrap().port(), port + 2);
        assert!(rtcp.is_none());
    }
}

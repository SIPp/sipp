//! SIPp's RTP playback threads (rtpstream.cpp): the calls' media run in a
//! pool of threads, each with up to -rtp_threadtasks calls (tasks), which
//! start as calls need them and last until the run ends, as SIPp's.
//!
//! A thread owns the media sockets and state of its calls: the rtp_stream
//! file or pattern it sends, the echoes of a pattern it checks, the
//! call's rtp_echo, its play_pcap_* and play_dtmf plays, and what comes
//! for <rtp_stats> and <rtp_dtmf>. It sleeps in ppoll() on those sockets
//! until the next packet is due, and the engine wakes it up with the
//! commands of its calls (an eventfd in the set). What the engine reads
//! back goes through atomics: the screen's counters (media::counters)
//! and, as each call ends, its RTP check; and what came, under a mutex.

use crate::media::{self, counters, rtp_debug, Stream};
use crate::pcap::Player;
use crate::srtp;
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use crate::sys::{self, AsRawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed, Ordering::SeqCst};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// A pattern stream's check: the echoes that came back intact.
pub struct PatternCheck {
    pub rx: Option<srtp::Context>,
    /// The pattern's id, its bit in SIPp's RTP error mask.
    pub id: u8,
    pub byte: u8,
    /// The payload bytes compared, as many as the pattern sends.
    pub len: usize,
    pub ok: u64,
}

/// What the engine asks of a call's media.
pub enum Cmd {
    /// The call's audio or video RTP socket, and its RTCP one.
    Sockets { video: bool, rtp: UdpSocket, rtcp: Option<UdpSocket> },
    /// rtp_stream: a file, or a pattern and its check; Task::send() adds
    /// what to tell the engine when it has played.
    Stream { video: bool, stream: Stream, check: Option<PatternCheck>, end: Option<(Arc<Playing>, u64)> },
    Pause { video: bool, paused: bool },
    /// The peer's SDP moved its media: the stream follows; or it has no
    /// address for it: the stream holds.
    Remote { video: bool, addr: Option<SocketAddr> },
    /// rtp_echo start or update with the call's SRTP contexts (rx, tx),
    /// or stop; Task::send() adds where to tell of a failed receive.
    Echo { video: bool, srtp: Option<(Option<srtp::Context>, Option<srtp::Context>)>, failed: Option<Arc<Playing>> },
    /// play_pcap_* or play_dtmf, on audio (0), image (1), video (2) or
    /// text (3).
    Play { index: usize, player: Player },
    /// [media_port] in our SDP, or the peer's SDP, moved a play.
    PcapAddr { index: usize, from: Option<u16>, to: Option<SocketAddr> },
    /// A scenario has <rtp_stats> or <rtp_dtmf>: what comes on the audio
    /// and video RTP sockets is counted there, from the first packet.
    Count(Arc<[Mutex<Received>; 2]>),
    /// The call ended: its RTP check, and its sockets closed.
    End,
    Exit,
}

/// How long the packets to echo or check gather before a thread reads
/// them, once some came.
const GATHER: Duration = Duration::from_millis(1);

/// SIPp's playback thread sleeps for at most this long.
const IDLE_PASS: Duration = Duration::from_millis(100);

/// The engine's side of a thread.
struct Worker {
    /// Boxed: the channel's blocks hold 31 of what it sends, and a Cmd is
    /// a few hundred bytes.
    tx: Sender<(u64, Box<Cmd>)>,
    wake: Arc<sys::Wake>,
    tasks: AtomicUsize,
}

impl Worker {
    fn send(&self, id: u64, cmd: Cmd) {
        if self.tx.send((id, Box::new(cmd))).is_ok() {
            self.wake.wake();
        }
    }
}

struct Pool {
    /// Each thread returns the patterns whose check failed in it.
    workers: Vec<(Arc<Worker>, JoinHandle<u64>)>,
    next_id: u64,
}

static POOL: Mutex<Pool> = Mutex::new(Pool { workers: Vec::new(), next_id: 1 });
/// The patterns whose check failed, as SIPp's rtpstream_shutdown() mask.
static RTP_ERRORS: AtomicU64 = AtomicU64::new(0);
/// -audiotolerance and -videotolerance, as f64 bits.
static TOLERANCE: [AtomicU64; 2] = [AtomicU64::new(0x3ff0_0000_0000_0000), AtomicU64::new(0x3ff0_0000_0000_0000)];

pub fn set_tolerance(audio: f64, video: f64) {
    TOLERANCE[0].store(audio.to_bits(), Relaxed);
    TOLERANCE[1].store(video.to_bits(), Relaxed);
}

/// A scenario has <rtp_stats> or <rtp_dtmf>: the calls count the RTP
/// they receive, as SIPp's rtp_stats_used.
static COUNT_RECEIVED: AtomicBool = AtomicBool::new(false);
/// The payload types of the scenarios' <rtp_dtmf>, a bit each, as SIPp's
/// rtp_dtmf_payload_types: the calls decode the RFC 4733 events that
/// come with them.
static DTMF_TYPES: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

/// The calls count what they receive, and decode the events of these
/// payload types (bit n for type n).
pub fn count_received(dtmf_types: u128) {
    COUNT_RECEIVED.store(true, Relaxed);
    DTMF_TYPES[0].store(dtmf_types as u64, Relaxed);
    DTMF_TYPES[1].store((dtmf_types >> 64) as u64, Relaxed);
}

/// The RTP a call received on its audio or video port, for <rtp_stats>
/// and <rtp_dtmf>, as SIPp's rtpstream_received_t.
#[derive(Default)]
pub struct Received {
    pub packets: u64,
    /// Of the first packet, as it came: with SRTP, still encrypted.
    pub first_pt: Option<u8>,
    pub first_payload: Vec<u8>,
    /// The digits of the RFC 4733 events that came, each with its payload
    /// type, and the timestamp of the last, whose repeats are the same.
    pub dtmf: Vec<(u8, u8)>,
    dtmf_timestamp: u32,
}

impl Received {
    /// rtpstream_count_received(): an RTP packet that came. Its payload is
    /// past the CSRCs and the header extension, and before the padding.
    /// An audio packet with a payload type of <rtp_dtmf> is an RFC 4733
    /// event: its first packet adds a digit, the others have its timestamp.
    fn count(&mut self, pkt: &[u8], video: bool) {
        let len = pkt.len();
        if len < 12 || pkt[0] >> 6 != 2 {
            return;
        }
        let mut start = 12 + 4 * (pkt[0] & 0x0f) as usize;
        if pkt[0] & 0x10 != 0 && start + 4 <= len {
            start += 4 + 4 * u16::from_be_bytes([pkt[start + 2], pkt[start + 3]]) as usize;
        }
        let end = if pkt[0] & 0x20 != 0 { len - (pkt[len - 1] as usize).min(len) } else { len };
        let pt = pkt[1] & 0x7f;
        self.packets += 1;
        if self.packets == 1 {
            self.first_pt = Some(pt);
            if start < end {
                self.first_payload = pkt[start..end].to_vec();
            }
        }
        let event = DTMF_TYPES[pt as usize >> 6].load(Relaxed) >> (pt & 63) & 1 != 0;
        if video || !event || start + 4 > end || pkt[start] >= 16 {
            return;
        }
        let timestamp = u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
        if self.dtmf.last().is_some_and(|&(p, _)| p == pt) && self.dtmf_timestamp == timestamp {
            return;
        }
        self.dtmf.push((pt, b"0123456789*#ABCD"[pkt[start] as usize]));
        self.dtmf_timestamp = timestamp;
    }
}

/// Whether a call's rtp_stream files or patterns still play, for
/// rtp_stream="wait": the streams started and those that have played, a
/// count each for audio and video. A paused one still plays, an endless
/// one plays for ever.
pub struct Playing {
    task: u64,
    started: [AtomicU64; 2],
    ended: [AtomicU64; 2],
    /// The call waits for them: the thread tells the engine (ENDED) when
    /// they have played.
    waiting: AtomicBool,
    /// rtpecho_t's error: the audio or video echo failed to receive since
    /// it started.
    echo_failed: [AtomicBool; 2],
}

/// The tasks whose call waits and whose stream just played, for the
/// engine to wake the call.
static ENDED: Mutex<Vec<u64>> = Mutex::new(Vec::new());

/// What ENDED has, taken.
pub fn take_ended() -> Vec<u64> {
    std::mem::take(&mut ENDED.lock().unwrap())
}

impl Playing {
    /// rtpstream_is_playing().
    fn playing(&self) -> bool {
        (0..2).any(|v| self.started[v].load(SeqCst) != self.ended[v].load(SeqCst))
    }

    /// The thread: stream `n` of `video` has played.
    fn ended(&self, video: usize, n: u64) {
        self.ended[video].store(n, SeqCst);
        if self.waiting.load(SeqCst) {
            ENDED.lock().unwrap().push(self.task);
        }
    }
}

/// A call's place in a playback thread, from its first RTP socket or
/// play to its end.
pub struct Task {
    id: u64,
    worker: Arc<Worker>,
    playing: Arc<Playing>,
    /// What came, audio and video, when a scenario has <rtp_stats> or
    /// <rtp_dtmf>.
    received: Option<Arc<[Mutex<Received>; 2]>>,
}

impl Task {
    /// rtpstream_start_task(): a thread with room, or a new one.
    pub fn start() -> Task {
        let mut pool = POOL.lock().unwrap();
        let max = counters::TASKS_PER_THREAD.load(Relaxed).max(1) as usize;
        let id = pool.next_id;
        pool.next_id += 1;
        let worker = match pool.workers.iter().find(|(w, _)| w.tasks.load(Relaxed) < max) {
            Some((w, _)) => w.clone(),
            None => {
                let (tx, rx) = mpsc::channel();
                let w = Arc::new(Worker { tx, wake: Arc::new(sys::Wake::new()), tasks: AtomicUsize::new(0) });
                let wake = w.wake.clone();
                counters::THREADS.fetch_add(1, Relaxed);
                // Each thread's clock is 1 ms ahead of the one before's,
                // over 20 ms, as SIPp's shift_ms: its streams and plays go
                // on its multiples, and the threads wake up apart.
                let shift = Duration::from_millis(pool.workers.len() as u64 % 20);
                let handle = std::thread::Builder::new()
                    .name("rtp".into())
                    .stack_size(THREAD_STACK)
                    .spawn(move || {
                        let failed = run(rx, &wake, shift);
                        counters::THREADS.fetch_sub(1, Relaxed);
                        failed
                    })
                    .expect("cannot start an RTP playback thread");
                rtp_debug::both("CREATED THREAD: ", rtp_debug::thread_id(&handle), 0);
                pool.workers.push((w.clone(), handle));
                w
            }
        };
        worker.tasks.fetch_add(1, Relaxed);
        let playing = Arc::new(Playing { task: id, started: Default::default(), ended: Default::default(), waiting: AtomicBool::new(false), echo_failed: Default::default() });
        let received = COUNT_RECEIVED.load(Relaxed).then(|| Arc::new(<[Mutex<Received>; 2]>::default()));
        if let Some(r) = &received {
            worker.send(id, Cmd::Count(r.clone()));
        }
        Task { id, worker, playing, received }
    }

    pub fn send(&self, mut cmd: Cmd) {
        match &mut cmd {
            Cmd::Stream { video, end, .. } => {
                let n = self.playing.started[*video as usize].fetch_add(1, SeqCst) + 1;
                *end = Some((self.playing.clone(), n));
            }
            Cmd::Echo { failed, .. } => *failed = Some(self.playing.clone()),
            _ => {}
        }
        self.worker.send(self.id, cmd);
    }

    /// rtpstream_rtpecho_stop*()'s -1: the echo failed to receive since
    /// it started; a start clears it.
    pub fn echo_failed(&self, video: bool) -> bool {
        self.playing.echo_failed[video as usize].load(SeqCst)
    }

    pub fn echo_started(&self, video: bool) {
        self.playing.echo_failed[video as usize].store(false, SeqCst);
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    /// rtpstream_received(): what the call's audio or video port received
    /// so far, when a scenario has <rtp_stats> or <rtp_dtmf>.
    pub fn received(&self, video: bool) -> Option<std::sync::MutexGuard<'_, Received>> {
        self.received.as_ref().map(|r| r[video as usize].lock().unwrap())
    }

    /// Whether an rtp_stream still plays, even paused.
    pub fn playing(&self) -> bool {
        self.playing.playing()
    }

    /// rtp_stream="wait": whether the call waits for its streams, for
    /// take_ended() to have it once they have played. Checking whether
    /// they play is to come after it is set, so no end goes unseen.
    pub fn wait(&self, waiting: bool) {
        self.playing.waiting.store(waiting, SeqCst);
    }
}

impl Drop for Task {
    /// rtpstream_stop_task(): the thread checks the call's echoes, closes
    /// its sockets and stops its plays.
    fn drop(&mut self) {
        self.worker.tasks.fetch_sub(1, Relaxed);
        self.worker.send(self.id, Cmd::End);
    }
}

/// rtpstream_shutdown(): the threads end, after the calls they still
/// have; the RTP check of all the calls.
pub fn finish() -> u64 {
    let workers = std::mem::take(&mut POOL.lock().unwrap().workers);
    for (w, _) in &workers {
        w.send(0, Cmd::Exit);
    }
    // -rtpcheck_debug: each thread's result, and all of them so far, as
    // SIPp's int.
    let mut total = 0;
    for (_, h) in workers {
        rtp_debug::both("EXISTING THREADID: ", rtp_debug::thread_id(&h), 0);
        match h.join() {
            Ok(failed) => {
                total |= failed;
                rtp_debug::both("JOINED THREAD: ", failed, total as i32);
            }
            Err(_) => rtp_debug::both("ERROR RETURNED BY JOINHANDLE::JOIN!", 0, 0),
        }
    }
    rtp_debug::close();
    RTP_ERRORS.load(Relaxed)
}

thread_local! {
    /// The patterns whose check failed in this playback thread.
    static FAILED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Patterns whose check failed, into the run's mask and the thread's.
fn fail(mask: u64) {
    RTP_ERRORS.fetch_or(mask, Relaxed);
    FAILED.set(FAILED.get() | mask);
}

/// One media type's socket and what plays on it, in the thread.
#[derive(Default)]
struct Media {
    sock: Option<UdpSocket>,
    /// The port after it, bound for the peer's RTCP and never answered.
    rtcp: Option<UdpSocket>,
    /// Boxed: a call's video has none, an echo's audio neither.
    stream: Option<Box<Stream>>,
    /// Whom to tell once the stream has played, and its number.
    stream_end: Option<(Arc<Playing>, u64)>,
    /// rtp_echo start: incoming packets go back, decrypted with the peer's
    /// key and encrypted with ours when SRTP is on.
    echo: Option<(Option<srtp::Context>, Option<srtp::Context>)>,
    /// Where the echo tells of a failed receive.
    echo_failed: Option<Arc<Playing>>,
    check: Option<PatternCheck>,
    /// The stream plays a pattern: its packets are the ones checked.
    pattern: bool,
    /// Pattern packets sent by the streams of this check that ended, for
    /// its ratio: a file's are not checked, as in SIPp.
    sent_before: u64,
    /// Where the next stream numbers its packets from: after the last's.
    seq: u16,
    /// What the thread's poll set has of it: the RTP socket, the RTCP one.
    polled: [bool; 2],
    /// Where what comes is counted, for <rtp_stats> and <rtp_dtmf>.
    received: Option<Arc<[Mutex<Received>; 2]>>,
    /// -rtpcheck_debug's view of the RTP check.
    trace: Option<Box<Trace>>,
}

impl Media {
    /// Whether anything reads this socket: an echo or a pattern check.
    fn active(&self) -> bool {
        self.sock.is_some() && (self.echo.is_some() || self.check.is_some())
    }

    /// Whether the thread waits on the sockets (RTP, RTCP): for an echo,
    /// or once its stream is over for a check, or for what comes to be
    /// counted (SIPp's rtpstream_listens()). While it streams, it reads
    /// what came back after each packet, as SIPp.
    fn wants(&self) -> [bool; 2] {
        let reads = self.check.is_some() || self.received.is_some();
        let rtp = self.sock.is_some() && (self.echo.is_some() || (self.stream.is_none() && reads));
        [rtp, self.rtcp.is_some() && self.active()]
    }

    /// The poll set follows what the thread waits on; `key` is the
    /// task's slot and whether video, for the events.
    fn sync(&mut self, poll: &mut sys::MediaPoll, key: u64) {
        let want = self.wants();
        for (i, fd) in [self.sock.as_ref(), self.rtcp.as_ref()].into_iter().enumerate() {
            let Some(fd) = fd.map(AsRawFd::as_raw_fd) else { continue };
            if want[i] != self.polled[i] {
                poll.watch(fd, key << 1 | i as u64, want[i]);
                self.polled[i] = want[i];
            }
        }
    }

    /// The rtp_stream packets that are due; when the next one is.
    fn send_due(&mut self, now: Instant, index: usize, buf: &mut [u8]) -> Option<Instant> {
        let (s, sock) = (self.stream.as_mut()?, self.sock.as_ref()?);
        if s.next > now {
            return Some(s.next);
        }
        let (before, bytes) = (s.sent, s.bytes);
        let playing = s.send_due(sock, now);
        // Played once its last packet is out, as SIPp's loop count.
        if !playing || s.finished() {
            if let Some((p, n)) = self.stream_end.take() {
                p.ended(index, n);
            }
        }
        let sent = s.sent - before;
        let next = s.next;
        counters::add(&counters::STREAM_PACKETS[index], sent);
        counters::add(&counters::STREAM_BYTES_OUT[index], s.bytes - bytes);
        // SIPp reads what came back after each packet.
        if sent > 0 && self.echo.is_none() {
            self.read(buf, index);
        }
        if playing {
            return Some(next);
        }
        self.played();
        None
    }

    /// Its stream has played.
    fn played(&mut self) {
        self.sent_before += self.pattern_sent();
        self.seq = self.stream.take().map_or(self.seq, |s| s.seq);
    }

    /// What arrived on the media socket: counted, and echoed back or
    /// checked against the pattern we play.
    fn read(&mut self, buf: &mut [u8], index: usize) {
        if self.trace.is_some() && self.echo.is_none() {
            return self.read_unread(buf, index);
        }
        self.read_with(buf, index, |_| {});
    }

    /// read(), with each packet to `first` first.
    fn read_with(&mut self, buf: &mut [u8], index: usize, mut first: impl FnMut(&[u8])) {
        let Some(sock) = &self.sock else { return };
        let (streaming, echoes, echoing, check) = (self.stream.is_some(), self.echo.is_some(), &mut self.echo, &mut self.check);
        let mut received = self.received.as_ref().map(|r| r[index].lock().unwrap());
        let mut each = |pkt: &[u8], from| {
            first(pkt);
            if let Some(r) = received.as_mut() {
                r.count(pkt, index == 1);
            }
            // What comes back while streaming, as rtpstream_abytes_in.
            if streaming && echoing.is_none() {
                counters::add(&counters::STREAM_BYTES_IN[index], pkt.len() as u64);
            }
            if let Some((rx, tx)) = echoing.as_mut() {
                echo(sock, pkt, from, rx, tx, index == 1);
            } else if let Some(check) = check.as_mut() {
                SRTP_PACKET.with_borrow_mut(|(plain_buf, _)| {
                    let plain = match check.rx.as_mut() {
                        Some(ctx) => ctx.unprotect_into(pkt, plain_buf).then_some(&plain_buf[..]),
                        None => Some(pkt),
                    };
                    // SIPp compares the payload a pattern packet has: what
                    // comes after it, as SRTP's tag when nothing decrypts, is not.
                    if plain.is_some_and(|p| p.len() >= 12 + check.len.max(1) && p[12..12 + check.len.max(1)].iter().all(|&b| b == check.byte)) {
                        check.ok += 1;
                    }
                });
            }
        };
        // rtpstream_echotask(): an echo's receive error ends its reading
        // until the next pass, and fails it; an ICMP port unreachable for
        // an earlier echo (the peer's call ending) does neither.
        while let Some(errno) = recv_all(sock, buf, &mut each) {
            if !echoes {
                break;
            }
            let what = if index == 1 { "VIDEO" } else { "AUDIO" };
            if errno == sys::ECONNREFUSED {
                media::echo_debug::print(index == 1, &format!("{what} echo peer port unreachable (ECONNREFUSED)...\n"));
                continue;
            }
            media::echo_debug::print(index == 1, &format!("Error on RTP echo reception - unable to perform rtpstream {what} echo - errno = {errno}\n"));
            if let Some(p) = &self.echo_failed {
                p.echo_failed[index].store(true, SeqCst);
            }
            break;
        }
    }

    fn drain_rtcp(&self, buf: &mut [u8]) {
        if let Some(rtcp) = &self.rtcp {
            let _ = recv_all(rtcp, buf, |_, _| {});
        }
    }

    /// The packets the stream playing sent, if it is a pattern's.
    fn pattern_sent(&self) -> u64 {
        self.stream.as_ref().filter(|_| self.pattern).map_or(0, |s| s.sent)
    }

    /// SIPp's RTP check: a pattern stream fails if none of it came back.
    /// SIPp's verdict: the share of packets whose echo failed reaches the
    /// -audiotolerance or -videotolerance (1.0: all of them).
    /// set_bit(): a failed pattern sets bit id - 1.
    fn check_failed(&self, tolerance: f64) -> u64 {
        let Some(c) = &self.check else { return 0 };
        let sent = self.sent_before + self.pattern_sent();
        let failed = sent > 0 && sent.saturating_sub(c.ok) as f64 / sent as f64 >= tolerance;
        if failed && c.id > 0 { 1 << (c.id - 1) } else { 0 }
    }
}

/// A media thread's stack: its streams, plays and echoes run in 64 KB,
/// where std's 2 MB for each of hundreds of threads is address space for
/// nothing.
pub const THREAD_STACK: usize = 256 * 1024;

thread_local! {
    /// A packet without and with SRTP, kept by the thread for its next one.
    static SRTP_PACKET: std::cell::RefCell<(Vec<u8>, Vec<u8>)> = const { std::cell::RefCell::new((Vec::new(), Vec::new())) };
}

/// The datagrams read in one recvmmsg() at most.
pub const RECV_BATCH: usize = 8;

/// What waits on `sock`, to `each` with where it came from, in batches of
/// RECV_BATCH datagrams, each in its share of `buf`: one recvmmsg() for
/// what one recv() at a time takes, and without its last call, the one
/// that finds none left.
#[cfg(target_os = "linux")]
fn recv_all(sock: &UdpSocket, buf: &mut [u8], mut each: impl FnMut(&[u8], SocketAddr)) -> Option<i32> {
    let size = buf.len() / RECV_BATCH;
    loop {
        // SAFETY: plain C structs, all zeros empty.
        let mut addrs: [libc::sockaddr_storage; RECV_BATCH] = unsafe { std::mem::zeroed() };
        let mut iovs: [libc::iovec; RECV_BATCH] = unsafe { std::mem::zeroed() };
        let mut msgs: [libc::mmsghdr; RECV_BATCH] = unsafe { std::mem::zeroed() };
        for (i, ((m, iov), addr)) in msgs.iter_mut().zip(&mut iovs).zip(&mut addrs).enumerate() {
            *iov = libc::iovec { iov_base: buf[i * size..].as_mut_ptr().cast(), iov_len: size };
            m.msg_hdr.msg_name = (addr as *mut libc::sockaddr_storage).cast();
            m.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            m.msg_hdr.msg_iov = iov;
            m.msg_hdr.msg_iovlen = 1;
        }
        // SAFETY: each message points at its own address and share of buf.
        let n = unsafe { libc::recvmmsg(sock.as_raw_fd(), msgs.as_mut_ptr(), RECV_BATCH as libc::c_uint, libc::MSG_DONTWAIT, std::ptr::null_mut()) };
        if n < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return (errno != libc::EAGAIN && errno != libc::EWOULDBLOCK && errno != libc::EINTR).then_some(errno);
        }
        if n == 0 {
            return None;
        }
        for (i, (m, addr)) in msgs.iter().zip(&addrs).take(n as usize).enumerate() {
            if let Some(from) = socket_addr(addr) {
                each(&buf[i * size..i * size + m.msg_len as usize], from);
            }
        }
        if (n as usize) < RECV_BATCH {
            return None;
        }
    }
}

#[cfg(target_os = "linux")]
/// A received datagram's source.
fn socket_addr(addr: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match addr.ss_family as libc::c_int {
        libc::AF_INET => {
            // SAFETY: an AF_INET address is a sockaddr_in.
            let a = unsafe { &*(addr as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>() };
            Some(SocketAddr::from((u32::from_be(a.sin_addr.s_addr).to_be_bytes(), u16::from_be(a.sin_port))))
        }
        libc::AF_INET6 => {
            // SAFETY: an AF_INET6 address is a sockaddr_in6.
            let a = unsafe { &*(addr as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>() };
            Some(SocketAddr::V6(std::net::SocketAddrV6::new(a.sin6_addr.s6_addr.into(), u16::from_be(a.sin6_port), a.sin6_flowinfo, a.sin6_scope_id)))
        }
        _ => None,
    }
}

/// recv_all() one datagram at a time, where there is no recvmmsg(): into
/// the first share of `buf`, from a socket that is non-blocking there.
#[cfg(not(target_os = "linux"))]
fn recv_all(sock: &UdpSocket, buf: &mut [u8], mut each: impl FnMut(&[u8], SocketAddr)) -> Option<i32> {
    let size = buf.len() / RECV_BATCH;
    let slot = &mut buf[..size];
    loop {
        match sock.recv_from(slot) {
            Ok((n, from)) => each(&slot[..n], from),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) => return None,
            Err(e) => return Some(e.raw_os_error().unwrap_or(0)),
        }
    }
}

/// rtpstream_echotask(): a packet of the call back to where it came from,
/// through the call's SRTP, with -srtpcheck_debug's log.
fn echo(sock: &UdpSocket, pkt: &[u8], from: SocketAddr, rx: &mut Option<srtp::Context>, tx: &mut Option<srtp::Context>, video: bool) {
    let n = pkt.len();
    let debug = media::echo_debug::is_open(video);
    let what = if video { "VIDEO" } else { "AUDIO" };
    let log = |text: String| media::echo_debug::print(video, &text);
    if debug {
        let head: String = (0..12).map(|i| format!("{:02X}", pkt.get(i).copied().unwrap_or(0))).collect();
        log(format!("DATA SUCCESSFULLY RECEIVED [{what}] nr = {n}...{head}\n"));
    }
    SRTP_PACKET.with_borrow_mut(|(plain_buf, out_buf)| {
        let plain = match rx.as_mut() {
            Some(ctx) => {
                let ok = ctx.unprotect_into(pkt, plain_buf);
                if debug {
                    log(format!("RXUAS{what} -- processIncomingPacket() rc == {}\n", if ok { 0 } else { -1 }));
                }
                ok.then_some(&plain_buf[..])
            }
            None => Some(pkt),
        };
        let out = match (plain, tx.as_mut()) {
            (Some(p), Some(ctx)) => {
                let ok = ctx.protect_into(p, out_buf);
                if debug {
                    log(format!("TXUAS{what} -- processOutgoingPacket() rc == {}\n", if ok { 0 } else { -1 }));
                }
                ok.then_some(&out_buf[..])
            }
            (p, None) => p,
            (None, Some(_)) => None,
        };
        let Some(out) = out else { return };
        let sent = sock.send_to(out, from);
        let seq = u16::from_be_bytes([pkt.get(2).copied().unwrap_or(0), pkt.get(3).copied().unwrap_or(0)]);
        let ns = match sent {
            // Nothing went out, so SIPp counts nothing.
            Err(e) => {
                if debug {
                    log(format!("Error on RTP echo transmission [{what}] seq_num = [{seq}] -- errno = {}\n", e.raw_os_error().unwrap_or(0)));
                }
                return;
            }
            Ok(ns) => ns,
        };
        if debug {
            if ns == n {
                log(format!("DATA SUCCESSFULLY SENT [{what}] seq_num = [{seq}]...\n"));
            } else {
                log(format!("DATA SUCCESSFULLY SENT [{what}] seq_num = [{seq}] -- MISMATCHED RECV/SENT BYTE COUNT -- errno = 0 nr = {n} ns = {ns}\n"));
            }
        }
        // SIPp counts them with -rtp_echo's, rtp_pckts and rtp2_pckts.
        counters::add(&counters::ECHO_PACKETS[video as usize], 1);
        counters::add(&counters::ECHO_BYTES[video as usize], ns as u64);
    });
}

/// A call's media in its thread.
struct TaskState {
    media: [Media; 2],
    /// A play per stream (audio with its DTMF, image, video, text), all
    /// at once. Boxed: most calls play no pcap.
    playback: [Option<Box<Player>>; 4],
    /// -rtpcheck_debug: when SIPp's thread runs the task while it plays
    /// no stream, at its next pass for a new one; and whether its call
    /// ended, which that pass comes to.
    idle_pass: Option<Instant>,
    ended: bool,
}

impl TaskState {
    fn apply(&mut self, cmd: Cmd, buf: &mut [u8]) {
        match cmd {
            Cmd::Sockets { video, rtp, rtcp } => {
                // Linux reads them with MSG_DONTWAIT: recv_all() elsewhere
                // needs them non-blocking.
                #[cfg(not(target_os = "linux"))]
                for s in std::iter::once(&rtp).chain(rtcp.as_ref()) {
                    let _ = s.set_nonblocking(true);
                }
                let m = &mut self.media[video as usize];
                (m.sock, m.rtcp) = (Some(rtp), rtcp);
            }
            Cmd::Stream { video, mut stream, check, end } => {
                // rtpstream_check_verdict(): the pattern playing gets its
                // verdict, with what came back of it, and the new stream
                // its own check.
                let m = &mut self.media[video as usize];
                if m.active() {
                    m.read(buf, video as usize);
                }
                fail(m.check_failed(tolerance(video as usize)));
                if rtp_debug::on() {
                    m.verdict_traced(video);
                    let t = m.trace.get_or_insert_with(Default::default);
                    (t.pattern, t.first_seq) = (check.as_ref().map_or(-1, |c| i32::from(c.id)), None);
                }
                m.sent_before = 0;
                m.seq = m.stream.as_ref().map_or(m.seq, |s| s.seq);
                stream.seq = m.seq;
                m.stream = Some(Box::new(stream));
                m.stream_end = end;
                m.pattern = check.is_some();
                m.check = check;
            }
            Cmd::Pause { video, paused } => {
                let other = self.next_packet(!video);
                if let Some(s) = self.media[video as usize].stream.as_mut() {
                    let waited = s.paused || s.held;
                    s.paused = paused;
                    s.resume(waited, other);
                }
            }
            Cmd::Remote { video, addr } => {
                let other = self.next_packet(!video);
                if let Some(s) = self.media[video as usize].stream.as_mut() {
                    let waited = s.paused || s.held;
                    s.held = addr.is_none();
                    s.remote = addr.unwrap_or(s.remote);
                    s.resume(waited, other);
                }
            }
            Cmd::Echo { video, srtp, failed } => {
                let m = &mut self.media[video as usize];
                (m.echo, m.echo_failed) = (srtp, failed);
            }
            Cmd::Play { index, mut player } => {
                self.playback[index] = None;
                // Audio and image end each other too, as a switch to T.38
                // often keeps the remote port: no RTP and UDPTL mixed.
                if index < 2 {
                    self.playback[1 - index] = None;
                }
                self.playback[index] = player.poll().then(|| Box::new(player));
            }
            Cmd::PcapAddr { index, from, to } => {
                if let Some(p) = self.playback[index].as_mut() {
                    p.update(from, to);
                }
            }
            Cmd::Count(received) => {
                for m in &mut self.media {
                    m.received = Some(received.clone());
                }
            }
            Cmd::End | Cmd::Exit => {}
        }
    }

    /// When the call's audio or video stream sends its next packet, if
    /// it plays.
    fn next_packet(&self, video: bool) -> Option<Instant> {
        let m = &self.media[video as usize];
        m.stream.as_ref().filter(|s| m.sock.is_some() && !s.paused && !s.held).map(|s| s.next)
    }

    /// Due packets out; when the next one is.
    fn service(&mut self, now: Instant, buf: &mut [u8]) -> Option<Instant> {
        let mut next = None::<Instant>;
        let mut due = |t: Option<Instant>| {
            if let Some(t) = t {
                next = Some(next.map_or(t, |n| n.min(t)));
            }
        };
        for (i, m) in self.media.iter_mut().enumerate() {
            due(m.send_due(now, i, buf));
        }
        for p in &mut self.playback {
            if let Some(player) = p.as_mut() {
                if player.next_wakeup().is_some_and(|t| t <= now) && !player.poll() {
                    *p = None;
                    continue;
                }
                due(player.next_wakeup());
            }
        }
        next
    }

    /// The call ended: what its sockets hold still counts, then its
    /// check's verdict.
    fn end(mut self, buf: &mut [u8]) {
        for (i, m) in self.media.iter_mut().enumerate().filter(|(_, m)| m.active()) {
            m.drain_rtcp(buf);
            m.read(buf, i);
        }
        let mask = self.media[0].check_failed(tolerance(0)) | self.media[1].check_failed(tolerance(1));
        fail(mask);
        if rtp_debug::on() {
            self.media[0].verdict_traced(false);
            self.media[1].verdict_traced(true);
        }
    }
}

/// -rtpcheck_debug: a media's RTP check as SIPp's playback thread logs
/// it (rtpstream_playrtptask()), which compares the last packet that came
/// back after each one it sends with it. Its counts are SIPp's, which
/// our check (the echoes that came back) does not use.
#[derive(Default)]
struct Trace {
    /// audio/video_comparison_errors: the call's, over its streams.
    errors: u64,
    /// audio/video_check_failures and _packets: the stream's, until its
    /// verdict.
    failures: u64,
    packets: u64,
    /// The stream's pattern, -1 for a file (audio_pattern_id).
    pattern: i32,
    /// The stream's first packet, once it went (audio_seq_check).
    first_seq: Option<u16>,
    /// The last echo's (audio_seq_echoed): at first none, not even of the
    /// packet before the first.
    seq_echoed: Option<u16>,
    /// What came after the packet sent (audio_in), each packet read into
    /// it over the one before, cut to the size of ours, and how many.
    echo: Vec<u8>,
    echoes: usize,
    /// What we read that SIPp reads after its next packet: at a stream's
    /// change, or after it ended; as much as a socket's buffer holds.
    unread: Vec<Vec<u8>>,
    /// The payload of the packet sent.
    payload: Vec<u8>,
}

/// The packets Trace::unread holds at most.
const UNREAD_MAX: usize = 1024;

impl Media {
    /// read() for -rtpcheck_debug: SIPp reads it after its next packet.
    fn read_unread(&mut self, buf: &mut [u8], index: usize) {
        let mut t = self.trace.take().unwrap();
        self.read_with(buf, index, |pkt| {
            if t.unread.len() < UNREAD_MAX {
                t.unread.push(pkt.to_vec());
            }
        });
        self.trace = Some(t);
    }

    /// Whether a packet time of its stream is due.
    fn due(&self, now: Instant) -> bool {
        self.sock.is_some() && self.stream.as_ref().is_some_and(|s| s.next <= now)
    }

    /// send_due() as -rtpcheck_debug logs it: the packet due, and what came
    /// back after it compared with it, or the note of a stream that sends
    /// nothing now; whether the comparison failed (SIPp's comparison_acheck).
    fn send_traced(&mut self, now: Instant, index: usize, buf: &mut [u8]) -> bool {
        let video = index == 1;
        let Media { stream: Some(s), sock: Some(sock), trace, stream_end, .. } = self else { return false };
        if s.next > now || s.paused || s.held {
            rtp_debug::hex(video, "TIMESTAMP NOT QUITE RIGHT...", &[], 0, 0);
            if s.next <= now {
                s.send_next_traced(sock, now, |_| {});
            }
            return false;
        }
        let t = trace.get_or_insert_with(Default::default);
        let (mut srtp, mut result, mut seq, mut rx_size) = (None, None, 0, 0);
        let rx_tag = s.rx.as_ref().map_or(0, srtp::Context::tag_len);
        let playing = s.send_next_traced(sock, now, |p| {
            (srtp, seq) = (p.srtp, u16::from_be_bytes([p.plain[2], p.plain[3]]));
            result = Some(p.result.as_ref().map(|&n| (n, p.packet.to_vec())).map_err(|e| e.raw_os_error().unwrap_or(0)));
            t.payload.clear();
            t.payload.extend_from_slice(&p.plain[12..]);
            rx_size = p.plain.len() + rx_tag;
        });
        // Played once its last packet is out, as SIPp's loop count.
        if !playing || s.finished() {
            if let Some((p, n)) = stream_end.take() {
                p.ended(index, n);
            }
        }
        if let Some(ok) = srtp {
            let note = if video { "TXUACVIDEO -- protect_into() rc == " } else { "TXUACAUDIO -- protect_into() rc == " };
            rtp_debug::hex(video, note, &[], if ok { 0 } else { u64::MAX }, 0);
        }
        let mut failed = false;
        match result {
            Some(Ok((n, packet))) => {
                counters::add(&counters::STREAM_PACKETS[index], 1);
                counters::add(&counters::STREAM_BYTES_OUT[index], 12 + t.payload.len() as u64);
                if video || t.pattern > 0 {
                    t.packets += 1;
                }
                rtp_debug::hex(video, "SIPP SUCCESS SEND LOG: ", &packet, n as u64, packets(index));
                failed = self.compare_traced(buf, index, seq, rx_size);
            }
            Some(Err(errno)) => rtp_debug::hex(video, "SEND FAILED: ", &[], u64::MAX, errno),
            None => {}
        }
        if !playing {
            self.played();
        }
        failed
    }

    /// What came back after the packet `seq` went, logged, and the last of
    /// it compared with it: whether that failed.
    fn compare_traced(&mut self, buf: &mut [u8], index: usize, seq: u16, size: usize) -> bool {
        let video = index == 1;
        let mut t = self.trace.take().unwrap();
        (t.echoes, t.echo) = (0, vec![0; size]);
        let came = |t: &mut Trace, pkt: &[u8]| {
            let n = pkt.len().min(size);
            t.echo[..n].copy_from_slice(&pkt[..n]);
            t.echoes += 1;
            rtp_debug::hex(video, "SIPP SUCCESS RECV LOG: ", &t.echo, pkt.len() as u64, packets(index));
        };
        // SIPp reads what came back after each packet.
        if self.echo.is_none() {
            for pkt in std::mem::take(&mut t.unread) {
                came(&mut t, &pkt);
            }
            self.read_with(buf, index, |pkt| came(&mut t, pkt));
        }
        let seq_echoed = *t.seq_echoed.get_or_insert(seq.wrapping_sub(2));
        let first_seq = *t.first_seq.get_or_insert(seq);
        let failed = if t.echoes > 0 {
            let echo_seq = u16::from_be_bytes([t.echo[2], t.echo[3]]);
            let mut plain = Vec::new();
            let payload = match self.stream.as_mut().and_then(|s| s.rx.as_mut()) {
                Some(rx) => {
                    let ok = rx.unprotect_into(&t.echo, &mut plain);
                    let note = if video { "RXUACVIDEO -- unprotect_into() rc == " } else { "RXUACAUDIO -- unprotect_into() rc == " };
                    rtp_debug::hex(video, note, &[], if ok { 0 } else { u64::MAX }, 0);
                    if ok { plain.get(12..).unwrap_or(&[]) } else { &[][..] }
                }
                None => &t.echo[12.min(size)..],
            };
            if !video {
                t.seq_echoed = Some(echo_seq);
            }
            // An audio packet is compared if it is the echo of one of the
            // pattern's; what the payload lacks is zeros.
            let compared = video || (t.pattern > 0 && echo_seq.wrapping_sub(first_seq) < 0x8000);
            let same = !compared || t.payload.iter().enumerate().all(|(i, &b)| payload.get(i).copied().unwrap_or(0) == b);
            if !same {
                t.errors += 1;
            }
            rtp_debug::hex(video, if same { "COMPARISON OK " } else { "COMPARISON FAILED" }, &[], t.errors, packets(index));
            !same
        } else if !video && (t.pattern < 1 || seq_echoed == seq.wrapping_sub(1)) {
            // No pattern, or the echo of the packet before came: this
            // one's is on its way.
            false
        } else {
            t.errors += 1;
            rtp_debug::hex(video, "NODATA", &[], t.errors, packets(index));
            true
        };
        self.trace = Some(t);
        failed
    }

    /// The RTP check of a step of the stream (SIPp's audio_check_failures).
    fn check_traced(&mut self, video: bool, failed: bool) {
        let failures = match self.trace.as_mut() {
            Some(t) => {
                t.failures += u64::from(failed);
                t.failures
            }
            None => 0,
        };
        let note = if failed { "----FAILED RTP CHECK----" } else { "----PASSED RTP CHECK----" };
        rtp_debug::hex(video, note, &[], failures, packets(video as usize));
    }

    /// rtpstream_check_verdict(): the stream's failures and packets, which
    /// start over.
    fn verdict_traced(&mut self, video: bool) {
        if let Some(t) = self.trace.as_mut().filter(|t| t.packets > 0) {
            rtp_debug::hex(video, "----RTP CHECK VERDICT----", &[], t.failures, t.packets as i32);
            (t.failures, t.packets) = (0, 0);
        }
    }
}

/// rtpstream_apckts or _vpckts, as SIPp logs them.
fn packets(index: usize) -> i32 {
    counters::STREAM_PACKETS[index].load(Relaxed) as i32
}

impl TaskState {
    /// service() as -rtpcheck_debug logs it: while a stream of the call's
    /// is due, a step of each, as SIPp's thread runs a task whose packet
    /// is due, and the RTP check of the step. One that plays none SIPp
    /// runs once a pass of its thread comes, at its creation and then on
    /// the multiples of 100 ms of the thread's clock, which `shift` is
    /// ahead by: when its stream has played, after the step that finds
    /// it over.
    fn service_traced(&mut self, slot: usize, now: Instant, shift: Duration, pass: bool, buf: &mut [u8]) -> Option<Instant> {
        let step = |t: &mut TaskState, buf: &mut [u8]| {
            // A SOCKET on Windows.
            #[allow(clippy::unnecessary_cast)]
            let fd = |m: &Media| m.sock.as_ref().map_or(-1, |s| s.as_raw_fd() as i32);
            rtp_debug::hex(false, "----AUDIO RTP SOCKET----", &[], slot as u64, fd(&t.media[0]));
            rtp_debug::hex(true, "----VIDEO RTP SOCKET----", &[], slot as u64, fd(&t.media[1]));
            for (i, m) in t.media.iter_mut().enumerate() {
                let failed = m.send_traced(now, i, buf);
                m.check_traced(i == 1, failed);
            }
        };
        let mut stepped = false;
        while self.media.iter().any(|m| m.due(now)) {
            step(self, buf);
            stepped = true;
        }
        let next = self.service(now, buf);
        if self.media.iter().any(|m| m.sock.is_some() && m.stream.is_some()) {
            return next;
        }
        let due = self.idle_pass.is_none_or(|t| t <= now);
        if pass && due && !stepped {
            step(self, buf);
        }
        if (pass && due) || stepped {
            // rtpstream_playrtptask(): on the next multiple of 100 ms.
            let ms = (now.saturating_duration_since(crate::call::epoch()) + shift).as_millis() as u64;
            let at = Duration::from_millis(ms + 100 - ms % 100).saturating_sub(shift);
            self.idle_pass = Some(crate::call::epoch() + at);
        }
        match (next, self.idle_pass) {
            (Some(n), Some(i)) => Some(n.min(i)),
            (n, i) => n.or(i),
        }
    }
}

/// -audiotolerance (0) or -videotolerance (1).
fn tolerance(video: usize) -> f64 {
    f64::from_bits(TOLERANCE[video].load(Relaxed))
}

/// rtpstream_playback_thread(): its calls' commands, due packets and
/// sockets, in a poll set with the engine's wake-up.
fn run(rx: Receiver<(u64, Box<Cmd>)>, wake: &sys::Wake, shift: Duration) -> u64 {
    sys::block_signals();
    let mut poll = sys::MediaPoll::new();
    const WAKE: u64 = u64::MAX;
    poll.watch(wake.fd(), WAKE, true);
    // The tasks by slot (the key of their sockets' events), and the slots
    // by task.
    let mut slots: Vec<Option<Box<TaskState>>> = Vec::new();
    let mut ids: HashMap<u64, usize> = HashMap::new();
    // The slots in the order of SIPp's task list: a new task last, the
    // last in the place of one that ends.
    let mut order: Vec<usize> = Vec::new();
    // RECV_BATCH datagrams of up to -mb bytes; pages none reaches stay
    // out of memory.
    let mut buf = vec![0u8; counters::MEDIA_BUFSIZE.load(Relaxed).max(1) * RECV_BATCH];
    let mut ready = Vec::with_capacity(64);
    let mut gathered = false;
    // -rtpcheck_debug: SIPp's thread makes a pass over its tasks when its
    // sleep ends, at the next one due or 100 ms after the pass before, or
    // when a play, a resume or an echo wakes it up; not for what it reads.
    // Its first pass at once.
    let (mut last_pass, mut pass_due, mut woken) = (Instant::now(), None::<Instant>, true);
    loop {
        loop {
            let (id, cmd) = match rx.try_recv() {
                Ok((id, cmd)) => (id, *cmd),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => (0, Cmd::Exit),
            };
            match cmd {
                Cmd::Exit => {
                    for slot in order {
                        slots[slot].take().unwrap().end(&mut buf);
                    }
                    rtp_debug::both("PLAYBACK THREAD EXITING...", FAILED.get(), 0);
                    return FAILED.get();
                }
                Cmd::End => {
                    if let Some(slot) = ids.remove(&id) {
                        // With -rtpcheck_debug, at the next pass, as SIPp's
                        // thread comes to the task to end it.
                        match rtp_debug::on() {
                            true => slots[slot].as_mut().unwrap().ended = true,
                            false => {
                                order.swap_remove(order.iter().position(|&s| s == slot).unwrap());
                                slots[slot].take().unwrap().end(&mut buf);
                            }
                        }
                    }
                }
                mut cmd => {
                    match &mut cmd {
                        Cmd::Play { player, .. } => player.align(shift),
                        Cmd::Stream { stream, .. } => stream.phase = shift,
                        _ => {}
                    }
                    let slot = *ids.entry(id).or_insert_with(|| match slots.iter().position(Option::is_none) {
                        Some(free) => free,
                        None => {
                            slots.push(None);
                            slots.len() - 1
                        }
                    });
                    let t = slots[slot].get_or_insert_with(|| {
                        order.push(slot);
                        Box::new(TaskState { media: Default::default(), playback: [None, None, None, None], idle_pass: None, ended: false })
                    });
                    woken |= match &cmd {
                        Cmd::Stream { .. } | Cmd::Play { .. } | Cmd::Pause { paused: false, .. } => true,
                        Cmd::Echo { video, srtp: Some(_), .. } => t.media[*video as usize].echo.is_none(),
                        _ => false,
                    };
                    t.apply(cmd, &mut buf);
                }
            }
        }
        let now = Instant::now();
        let mut next = None::<Instant>;
        let debug = rtp_debug::on();
        let pass = std::mem::take(&mut woken) || pass_due.is_some_and(|t| t <= now) || now >= last_pass + IDLE_PASS;
        if pass {
            last_pass = now;
        }
        let mut i = 0;
        while i < order.len() {
            let slot = order[i];
            let t = slots[slot].as_mut().unwrap();
            let due = if debug {
                if pass {
                    rtp_debug::both("----DEBUG CURRENTTASK/NUMTASKS----", i as u64, order.len() as i32);
                    if t.ended {
                        order.swap_remove(i);
                        slots[slot].take().unwrap().end(&mut buf);
                        continue;
                    }
                }
                t.service_traced(i, now, shift, pass, &mut buf)
            } else {
                t.service(now, &mut buf)
            };
            if let Some(t) = due {
                next = Some(next.map_or(t, |n| n.min(t)));
            }
            for (v, m) in t.media.iter_mut().enumerate() {
                m.sync(&mut poll, (slot as u64) << 1 | v as u64);
            }
            i += 1;
        }
        if debug {
            pass_due = next;
            next = Some(next.map_or(last_pass + IDLE_PASS, |n| n.min(last_pass + IDLE_PASS)));
        }
        // Packets came in: the next ones are let gather a while, not to
        // wake up (and have their senders wake us up) once a packet.
        if gathered {
            let pause = next.map_or(GATHER, |n| n.saturating_duration_since(Instant::now()).min(GATHER));
            std::thread::sleep(pause);
        }
        let wait = next.map(|n| n.saturating_duration_since(Instant::now()));
        ready.clear();
        poll.wait(wait, |key| ready.push(key));
        gathered = ready.iter().any(|&k| k != WAKE);
        for &key in &ready {
            if key == WAKE {
                wake.clear();
                continue;
            }
            let (slot, video, rtcp) = ((key >> 2) as usize, (key >> 1 & 1) as usize, key & 1 == 1);
            let Some(t) = slots.get_mut(slot).and_then(Option::as_mut) else { continue };
            let m = &mut t.media[video];
            if rtcp {
                m.drain_rtcp(&mut buf);
            } else {
                m.read(&mut buf, video);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_pattern_gets_its_own_verdict() {
        // A pattern never echoed fails when the next one starts, though
        // that one's echoes all come back; they are the next one's alone.
        let remote: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let check = |id| Some(PatternCheck { rx: None, id, byte: 1, len: 160, ok: 0 });
        let stream = || Stream::new(vec![1; 160], -1, media::codec(0, None).unwrap(), remote, 1);
        let mut buf = [0u8; 16];
        let mut t = TaskState { media: Default::default(), playback: [None, None, None, None], idle_pass: None, ended: false };
        t.apply(Cmd::Stream { video: false, stream: stream(), check: check(30), end: None }, &mut buf);
        t.media[0].stream.as_mut().unwrap().sent = 10;
        t.apply(Cmd::Stream { video: false, stream: stream(), check: check(31), end: None }, &mut buf);
        assert_ne!(RTP_ERRORS.load(Relaxed) & 1 << 29, 0);
        t.media[0].stream.as_mut().unwrap().sent = 10;
        t.media[0].check.as_mut().unwrap().ok = 10;
        t.end(&mut buf);
        assert_eq!(RTP_ERRORS.load(Relaxed) & 1 << 30, 0);
    }

    #[test]
    fn a_calls_streams_number_their_packets_on() {
        let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
        let stream = || Stream::new(vec![1; 160], 1, media::codec(0, None).unwrap(), sink.local_addr().unwrap(), 1);
        let mut buf = [0u8; 16];
        let mut t = TaskState { media: Default::default(), playback: [None, None, None, None], idle_pass: None, ended: false };
        let media = UdpSocket::bind("127.0.0.1:0").unwrap();
        // As the pool's own: a read with nothing there must not block.
        media.set_nonblocking(true).unwrap();
        t.media[0].sock = Some(media);
        let mut seqs = Vec::new();
        for _ in 0..2 {
            t.apply(Cmd::Stream { video: false, stream: stream(), check: None, end: None }, &mut buf);
            let s = t.media[0].stream.as_ref().unwrap();
            seqs.push(s.seq);
            // Its one packet, then its end.
            t.media[0].send_due(s.next, 0, &mut buf);
            t.media[0].send_due(Instant::now() + Duration::from_secs(1), 0, &mut buf);
        }
        // From 0, and on from the first's one packet, as SIPp's.
        assert_eq!(seqs, [0, 1]);
        assert!(t.media[0].stream.is_none());
        assert_eq!(t.media[0].seq, 2);
    }

    #[test]
    fn received_payloads_and_events() {
        count_received(1 << 101);
        let mut r = Received::default();
        // Not RTP: not counted.
        r.count(&[0x40; 20], false);
        assert_eq!(r.packets, 0);
        // A CSRC, a header extension of one word and two bytes of padding.
        let mut first = vec![0xb1, 8, 0, 1, 0, 0, 0, 160, 0, 0, 0, 1, 9, 9, 9, 9, 0xbe, 0xde, 0, 1, 7, 7, 7, 7];
        first.extend([0xd5, 0xd5, 0, 2]);
        r.count(&first, false);
        assert_eq!((r.packets, r.first_pt, &r.first_payload[..]), (1, Some(8), &[0xd5, 0xd5][..]));
        // An event of three packets, the last one again; then the same digit anew.
        let event = |ts: u8, digit: u8| vec![0x80, 101, 0, 2, 0, 0, 1, ts, 0, 0, 0, 1, digit, 0x0a, 0, 160];
        for p in [event(1, 11), event(1, 11), event(1, 11), event(2, 11), event(3, 5)] {
            r.count(&p, false);
        }
        // Not on video, nor of another payload type.
        r.count(&event(4, 1), true);
        let mut other = event(5, 2);
        other[1] = 96;
        r.count(&other, false);
        assert_eq!(r.dtmf, [(101, b'#'), (101, b'#'), (101, b'5')]);
        assert_eq!((r.packets, r.first_pt), (8, Some(8)));
    }
}

//! play_pcap_*: the UDP packets of a capture file, replayed on its timing.
//! Reads classic libpcap and pcapng files, as SIPp's prepare_pcap.c does
//! through libpcap: Ethernet (with an 802.1Q tag), Linux cooked and raw IP
//! links.

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Which SDP media a playback goes to and comes from.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PcapMedia {
    Audio,
    Image,
    Video,
    /// Real-time text, RFC 4103.
    Text,
}

#[derive(Debug)]
pub struct Packet {
    /// When it goes out, from the start of the playback.
    pub at: Duration,
    /// Its UDP destination port in the capture; its offset from `base`
    /// picks the port it is sent from and to (RTP, RTCP, ...).
    pub dport: u16,
    /// The UDP payload.
    pub payload: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct Pcap {
    pub packets: Vec<Packet>,
    /// The lowest UDP destination port in the capture.
    pub base: u16,
}

const LINKTYPE_ETHERNET: u32 = 1;
const LINKTYPE_RAW: u32 = 101;
const LINKTYPE_LINUX_SLL: u32 = 113;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const IPPROTO_UDP: u8 = 17;

/// A captured frame: when, its bytes, and its length on the wire.
struct Frame<'a> {
    ts: Duration,
    data: &'a [u8],
    len: usize,
}

/// A classic libpcap file's link type and frames, as libpcap reads them:
/// an Err is its pcap_open_offline() error, and a record it can't read
/// ends the capture.
fn classic(data: &[u8]) -> Result<(u32, Vec<Frame<'_>>), String> {
    let magic = u32::from_le_bytes(data[..4].try_into().unwrap());
    let (le, nanos) = match magic {
        0xa1b2c3d4 => (true, false),
        0xd4c3b2a1 => (false, false),
        0xa1b23c4d => (true, true),
        0x4d3cb2a1 => (false, true),
        _ => return Err("unknown file format".into()),
    };
    if data.len() < 24 {
        return Err(format!("truncated dump file; tried to read 24 file header bytes, only got {}", data.len() - 4));
    }
    let u16_at = |b: &[u8], at: usize| {
        let v: [u8; 2] = b[at..at + 2].try_into().unwrap();
        if le { u16::from_le_bytes(v) } else { u16::from_be_bytes(v) }
    };
    let u32_at = |b: &[u8], at: usize| {
        let v: [u8; 4] = b[at..at + 4].try_into().unwrap();
        if le { u32::from_le_bytes(v) } else { u32::from_be_bytes(v) }
    };
    let (major, minor) = (u16_at(data, 4), u16_at(data, 6));
    if major < 2 {
        return Err("archaic pcap savefile format".into());
    }
    if !(major == 2 && minor <= 4) && !(major == 543 && minor == 0) {
        return Err(format!("unsupported pcap savefile version {major}.{minor}"));
    }
    let link = u32_at(data, 20) & 0x0fff_ffff;
    let mut frames = Vec::new();
    let mut pos = 24;
    while pos + 16 <= data.len() {
        let (sec, frac) = (u32_at(data, pos), u32_at(data, pos + 4));
        let (caplen, len) = (u32_at(data, pos + 8) as usize, u32_at(data, pos + 12) as usize);
        let Some(frame) = data.get(pos + 16..pos + 16 + caplen) else { break };
        pos += 16 + caplen;
        let ts = Duration::new(sec.into(), if nanos { frac } else { frac.saturating_mul(1000) });
        frames.push(Frame { ts, data: frame, len });
    }
    Ok((link, frames))
}

const PCAPNG_SHB: u32 = 0x0a0d_0d0a;

/// A pcapng file's frames, as libpcap reads them: every section's
/// interfaces must share the first one's link type; each has its own
/// timestamp resolution (if_tsresol) and offset (if_tsoffset).
fn pcapng(data: &[u8]) -> Result<(u32, Vec<Frame<'_>>), String> {
    struct Iface {
        /// Timestamp units per second.
        units: u64,
        offset: u64,
    }
    let bad = || "truncated pcapng file".to_string();
    let mut le = true;
    let mut ifaces: Vec<Iface> = Vec::new();
    let mut link = None::<u32>;
    let mut frames = Vec::new();
    if data.len() < 12 {
        return Err("unknown file format".into());
    }
    let mut pos = 0;
    while pos + 12 <= data.len() {
        let u32_at = |at: usize, le: bool| -> Option<u32> {
            let v: [u8; 4] = data.get(at..at + 4)?.try_into().ok()?;
            Some(if le { u32::from_le_bytes(v) } else { u32::from_be_bytes(v) })
        };
        let kind = u32_at(pos, true).ok_or_else(bad)?;
        if kind == PCAPNG_SHB {
            // The byte-order magic sets the section's endianness.
            le = match u32_at(pos + 8, true) {
                Some(0x1a2b_3c4d) => true,
                Some(0x4d3c_2b1a) => false,
                _ => return Err("unknown file format".into()),
            };
            ifaces.clear();
        }
        let kind = u32_at(pos, le).ok_or_else(bad)?;
        let total = u32_at(pos + 4, le).ok_or_else(bad)? as usize;
        if total < 12 || !total.is_multiple_of(4) {
            return Err("corrupt pcapng block".into());
        }
        let body = data.get(pos + 8..pos + total - 4).ok_or_else(bad)?;
        let b32 = |at: usize| u32_at(pos + 8 + at, le).ok_or_else(bad);
        let b16 = |at: usize| -> Result<u16, String> {
            let v: [u8; 2] = body.get(at..at + 2).ok_or_else(bad)?.try_into().unwrap();
            Ok(if le { u16::from_le_bytes(v) } else { u16::from_be_bytes(v) })
        };
        match kind {
            // Interface Description Block.
            1 => {
                let l = u32::from(b16(0)?);
                if *link.get_or_insert(l) != l {
                    return Err(format!("an interface has a type {l} different from the type of the first interface"));
                }
                let (mut units, mut offset) = (1_000_000u64, 0u64);
                let mut at = 8;
                while at + 4 <= body.len() {
                    let (code, olen) = (b16(at)?, usize::from(b16(at + 2)?));
                    let value = body.get(at + 4..at + 4 + olen).ok_or_else(bad)?;
                    match (code, olen) {
                        (0, _) => break,
                        (9, 1) => {
                            let r = value[0];
                            let exp = u32::from(r & 0x7f);
                            units = if r & 0x80 != 0 { 1u64.checked_shl(exp) } else { 10u64.checked_pow(exp) }
                                .ok_or("unsupported if_tsresol")?;
                        }
                        (14, 8) => {
                            let v: [u8; 8] = value.try_into().unwrap();
                            offset = if le { u64::from_le_bytes(v) } else { u64::from_be_bytes(v) };
                        }
                        _ => {}
                    }
                    at += 4 + olen.div_ceil(4) * 4;
                }
                ifaces.push(Iface { units, offset });
            }
            // Enhanced Packet Block, and the obsolete Packet Block.
            2 | 6 => {
                let iface = if kind == 6 { b32(0)? as usize } else { usize::from(b16(0)?) };
                let i = ifaces.get(iface).ok_or("a packet names an unknown interface")?;
                let ts = (u64::from(b32(4)?) << 32) | u64::from(b32(8)?);
                let (caplen, len) = (b32(12)? as usize, b32(16)? as usize);
                let frame = body.get(20..20 + caplen).ok_or_else(bad)?;
                let nanos = (u128::from(ts % i.units) * 1_000_000_000 / u128::from(i.units)) as u32;
                frames.push(Frame { ts: Duration::new(ts / i.units + i.offset, nanos), data: frame, len });
            }
            // Simple Packet Block: no timestamp, the first interface's.
            3 => {
                ifaces.first().ok_or("a packet names an unknown interface")?;
                let len = b32(0)? as usize;
                let caplen = len.min(body.len().saturating_sub(4));
                frames.push(Frame { ts: Duration::ZERO, data: &body[4..4 + caplen], len });
            }
            _ => {}
        }
        pos += total;
    }
    Ok((link.unwrap_or(LINKTYPE_ETHERNET), frames))
}

/// SIPp's prepare_pkts() of a capture file: its libpcap and SIPp errors,
/// as it reports them.
pub fn load(path: &str) -> Result<Pcap, String> {
    let open = |e: String| format!("Can't open PCAP file '{path}': {e}");
    let mut file = std::fs::File::open(path).map_err(|e| open(format!("{path}: {}", crate::net::os_error(&e))))?;
    let mut data = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut data).map_err(|e| open(format!("error reading dump file: {}", crate::net::os_error(&e))))?;
    let (link, frames) = frames(&data).map_err(open)?;
    packets(link, frames)
}

/// pcap_open_offline()'s link type and the frames pcap_next_ex() reads.
fn frames(data: &[u8]) -> Result<(u32, Vec<Frame<'_>>), String> {
    if data.len() < 4 {
        return Err(format!("truncated dump file; tried to read 4 file header bytes, only got {}", data.len()));
    }
    match u32::from_le_bytes(data[..4].try_into().unwrap()) {
        PCAPNG_SHB => pcapng(data),
        _ => classic(data),
    }
}

#[cfg(test)]
pub fn parse(data: &[u8]) -> Result<Pcap, String> {
    let (link, frames) = frames(data)?;
    packets(link, frames)
}

fn packets(link: u32, frames: Vec<Frame<'_>>) -> Result<Pcap, String> {
    let ethertype = |frame: &[u8], at: usize| frame.get(at..at + 2).map_or(0, |b| u16::from_be_bytes([b[0], b[1]]));
    let mut pcap = Pcap { packets: Vec::new(), base: u16::MAX };
    let (mut first, mut last, mut at) = (None::<Duration>, Duration::ZERO, Duration::ZERO);
    for Frame { ts, data: frame, len } in frames {
        if frame.len() != len {
            return Err("You got truncated packets. Please create a new dump with -s0".into());
        }
        // get_ethertype_offset(): each frame's own, with or without an
        // 802.1Q tag.
        let mut offset = match link {
            LINKTYPE_RAW => 0,
            LINKTYPE_ETHERNET => 12,
            LINKTYPE_LINUX_SLL => 14,
            other => return Err(format!("Unsupported link-type {other}")),
        };
        let l3 = if offset > 0 {
            if ethertype(frame, offset) == ETHERTYPE_VLAN {
                offset += 4;
            }
            let t = ethertype(frame, offset);
            if t != ETHERTYPE_IPV4 && t != ETHERTYPE_IPV6 {
                eprintln!("Ignoring non IP{{4,6}} packet, got ether_type {t} ({t:04x})!");
                continue;
            }
            offset + 2
        } else {
            0
        };
        let Some(udp) = frame.get(l3..).and_then(udp_of) else {
            eprintln!("prepare_pcap.c: Ignoring non UDP packet!");
            continue;
        };
        let Some(udp) = Some(udp).filter(|u| u.len() >= 8) else { continue };
        let dport = u16::from_be_bytes([udp[2], udp[3]]);
        let ulen = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
        let Some(payload) = udp.get(8..ulen.max(8)) else { continue };

        // SIPp's do_sleep(): keep the gaps between packets, and send one
        // that is stamped before the last one right away.
        if first.is_some() && ts > last {
            at += ts - last;
        }
        first.get_or_insert(ts);
        last = ts;
        pcap.base = pcap.base.min(dport);
        pcap.packets.push(Packet { at, dport, payload: payload.to_vec() });
    }
    if pcap.packets.is_empty() {
        pcap.base = 0;
    }
    Ok(pcap)
}

/// SIPp's send_packets_socket(): a raw socket of the plays from an
/// address, SIPp's ERROR() text if it can't be had (no root or
/// CAP_NET_RAW). An IPPROTO_RAW socket, which the plays give their IP
/// headers: a raw UDP one gets a copy of each UDP packet in, and holds
/// its lock while the kernel delivers what it sends, so the playback
/// threads would wait on it.
fn open_raw(ip: IpAddr) -> Result<Socket, String> {
    let (domain, family) = if ip.is_ipv4() { (Domain::IPV4, "IPv4") } else { (Domain::IPV6, "IPv6") };
    let err = |e: std::io::Error| format!("Can't create raw {family} socket (need to run as root?): {}", crate::net::os_error(&e));
    // SOCK_RAW and IPPROTO_RAW: 3 and 255 on Linux and Windows alike.
    let s = Socket::new(domain, Type::from(3), Some(Protocol::from(255))).map_err(err)?;
    s.bind(&SockAddr::from(SocketAddr::new(ip, 0))).map_err(|e| format!("Can't bind media raw socket: {}", crate::net::os_error(&e)))?;
    s.set_nonblocking(true).map_err(err)?;
    Ok(s)
}

thread_local! {
    /// The raw sockets of this playback thread's plays, one per address,
    /// as SIPp's threads each have one: a socket shared by the threads
    /// makes them contend on its send buffer and its file.
    static RAW: RefCell<HashMap<IpAddr, Rc<Socket>>> = RefCell::new(HashMap::new());
}

fn thread_socket(ip: IpAddr) -> Result<Rc<Socket>, String> {
    RAW.with(|m| match m.borrow_mut().entry(ip) {
        Entry::Occupied(e) => Ok(e.get().clone()),
        Entry::Vacant(e) => Ok(e.insert(Rc::new(open_raw(ip)?)).clone()),
    })
}

/// Opens (once per address) a socket in the calling thread, as SIPp's
/// main thread does, to have the error before a playback thread would.
fn check_raw(ip: IpAddr) -> Result<(), String> {
    static CHECKED: Mutex<Option<HashSet<IpAddr>>> = Mutex::new(None);
    let mut checked = CHECKED.lock().unwrap();
    let checked = checked.get_or_insert_with(HashSet::new);
    if !checked.contains(&ip) {
        open_raw(ip)?;
        checked.insert(ip);
    }
    Ok(())
}

/// A playback in progress. Each packet goes out from the local port that
/// sits as far above `from` as its capture port sits above the capture's
/// base, to the same offset above `to`: RTP to RTP, RTCP to RTCP. As SIPp,
/// it writes the IP and UDP headers itself, over a raw socket.
pub struct Player {
    pcap: Arc<Pcap>,
    /// On a multiple of PLAY_SLOT once align()ed: the plays of a playback
    /// thread go at the same phase, and it wakes up for them at once.
    /// Each packet goes in the millisecond of its time from there, as
    /// SIPp's send_packets_due().
    start: Instant,
    next: usize,
    to: SocketAddr,
    /// The source address.
    src: IpAddr,
    /// The source port at offset 0.
    sport: u16,
    /// A packet the socket could not take, tried again then.
    retry: Option<Instant>,
}

impl Player {
    /// A play from `from`, or SIPp's ERROR() text if there is no raw
    /// socket to send it from.
    pub fn new(pcap: Arc<Pcap>, from: SocketAddr, to: SocketAddr) -> Result<Player, String> {
        check_raw(from.ip())?;
        Ok(Player { pcap, start: Instant::now(), next: 0, to, src: from.ip(), sport: from.port(), retry: None })
    }

    /// Starts on the next multiple of PLAY_SLOT on the playback thread's
    /// clock, the run's `shift` ahead, as its streams go.
    pub fn align(&mut self, shift: Duration) {
        let clock = Instant::now().saturating_duration_since(crate::call::epoch()) + shift;
        let slot = PLAY_SLOT.as_nanos();
        let start = Duration::from_nanos(clock.as_nanos().div_ceil(slot).saturating_mul(slot) as u64);
        self.start = crate::call::epoch() + (start - shift);
    }

    /// rtpstream_update_pcap(): the call's media addresses changed.
    pub fn update(&mut self, from_port: Option<u16>, to: Option<SocketAddr>) {
        self.sport = from_port.unwrap_or(self.sport);
        self.to = to.unwrap_or(self.to);
    }

    /// SIPp's send_packets_due(): sends what is due; false once the
    /// capture is over, or a send failed.
    pub fn poll(&mut self) -> bool {
        let now = Instant::now();
        if self.retry.is_some_and(|r| r > now) {
            return true;
        }
        self.retry = None;
        let raw = match thread_socket(self.src) {
            Ok(raw) => raw,
            Err(e) => {
                crate::log::defer_thread_warning(e);
                return false;
            }
        };
        while let Some(p) = self.pcap.packets.get(self.next).filter(|p| in_ms(self.start + p.at) <= now) {
            let diff = p.dport.wrapping_sub(self.pcap.base);
            let dport = self.to.port().wrapping_add(diff);
            let packet = ip_udp(self.src, self.sport.wrapping_add(diff), SocketAddr::new(self.to.ip(), dport), &p.payload);
            match raw.send_to(&packet, &SockAddr::from(SocketAddr::new(self.to.ip(), 0))) {
                Ok(_) => count_sent(p.payload.len()),
                // A full send buffer, which all the plays share: the
                // packet leaves as soon as the socket takes it.
                Err(e) if matches!(e.raw_os_error(), Some(crate::sys::EAGAIN | crate::sys::ENOBUFS | crate::sys::EINTR)) => {
                    self.retry = Some(now + Duration::from_millis(1));
                    return true;
                }
                Err(e) => {
                    crate::log::defer_thread_warning(format!("send_packets.c: sendto failed with error: {}", crate::net::os_error(&e)));
                    return false;
                }
            }
            self.next += 1;
        }
        self.next < self.pcap.packets.len()
    }

    pub fn next_wakeup(&self) -> Option<Instant> {
        self.retry.or_else(|| self.pcap.packets.get(self.next).map(|p| in_ms(self.start + p.at)))
    }
}

/// The plays start on multiples of 20 ms, the usual packet time of RTP:
/// the plays of a capture with a packet time that divides it go at the
/// same phase.
const PLAY_SLOT: Duration = Duration::from_millis(20);

/// The start of the millisecond of the run that `t` is in.
fn in_ms(t: Instant) -> Instant {
    let epoch = crate::call::epoch();
    epoch + Duration::from_millis(t.saturating_duration_since(epoch).as_millis() as u64)
}

/// A UDP packet from `src`:`sport` to `to` with its IP header, as an
/// IPPROTO_RAW socket sends it: the kernel fills in the IPv4 checksum
/// and ID. No UDP checksum over IPv4; over IPv6, where it is required,
/// ours. An IPv4 address to or from IPv6 goes as its mapped IPv6 one.
fn ip_udp(src: IpAddr, sport: u16, to: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let len = 8 + payload.len();
    let mut packet = Vec::with_capacity(40 + len);
    let v6 = |ip: IpAddr| match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    };
    match (src, to.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            packet.extend_from_slice(&[0x45, 0]);
            packet.extend_from_slice(&((20 + len) as u16).to_be_bytes());
            packet.extend_from_slice(&[0, 0, 0, 0, 64, IPPROTO_UDP, 0, 0]);
            packet.extend_from_slice(&s.octets());
            packet.extend_from_slice(&d.octets());
        }
        _ => {
            packet.extend_from_slice(&[0x60, 0, 0, 0]);
            packet.extend_from_slice(&(len as u16).to_be_bytes());
            packet.extend_from_slice(&[IPPROTO_UDP, 64]);
            packet.extend_from_slice(&v6(src).octets());
            packet.extend_from_slice(&v6(to.ip()).octets());
        }
    }
    let udp = packet.len();
    packet.extend_from_slice(&sport.to_be_bytes());
    packet.extend_from_slice(&to.port().to_be_bytes());
    packet.extend_from_slice(&(len as u16).to_be_bytes());
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(payload);
    if udp == 40 {
        // Over the pseudo-header: the addresses, the length and the protocol.
        let words = |b: &[u8]| b.chunks(2).map(|w| u32::from(w[0]) << 8 | u32::from(*w.get(1).unwrap_or(&0))).sum::<u32>();
        let mut sum = words(&packet[8..40]) + len as u32 + u32::from(IPPROTO_UDP) + words(&packet[udp..]);
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let sum = match !(sum as u16) {
            0 => 0xffff,
            c => c,
        };
        packet[udp + 6..udp + 8].copy_from_slice(&sum.to_be_bytes());
    }
    packet
}

/// rtp_pcap_count(): a packet sent, and its UDP payload.
fn count_sent(payload: usize) {
    crate::media::counters::add(&crate::media::counters::PCAP_PACKETS, 1);
    crate::media::counters::add(&crate::media::counters::PCAP_BYTES, payload as u64);
}

/// SIPp's parse_dtmf(): play_dtmf's "digits[,tone_length[,payload_type]]"
/// as its events, tone length (ms) and payload type. An invalid field
/// keeps its default; the first problem comes with them.
pub fn parse_dtmf(spec: &str) -> (Vec<u8>, u64, u8, Option<&'static str>) {
    let (digits, rest) = spec.split_once(',').map_or((spec, None), |(d, r)| (d, Some(r)));
    let (length, pt) = rest.map_or((None, None), |r| r.split_once(',').map_or((Some(r), None), |(l, p)| (Some(l), Some(p))));
    // strtol(): leading blanks and a sign, then all digits.
    let field = |f: Option<&str>, min: i64, max: i64, default: i64| match f {
        None | Some("") => Some(default),
        Some(f) => f.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']).parse::<i64>().ok().filter(|v| (min..=max).contains(v)),
    };
    let mut error = None;
    // From the end, so that the first problem is the one left.
    let pt = field(pt, 0, 127, 96).unwrap_or_else(|| {
        error = Some("the payload type is not 0 to 127 (default 96)");
        96
    });
    let tone = field(length, 50, 2000, 200).unwrap_or_else(|| {
        error = Some("the tone length is not 50 to 2000 ms (default 200)");
        200
    });
    let events: Vec<u8> = digits.bytes().filter_map(|c| b"0123456789*#ABCD".iter().position(|&e| e == c).map(|i| i as u8)).collect();
    if events.is_empty() {
        error = Some("no digit to send (0-9, *, #, A-D)");
    }
    (events, tone as u64, pt as u8, error)
}

/// play_dtmf: RFC 2833 events for `events` (see parse_dtmf), after 400 ms
/// of no-op packets that warm up the stream, as SIPp's prepare_dtmf()
/// builds them. `seq` carries on from one play_dtmf of a call to the next.
pub fn dtmf(events: &[u8], tone: u64, pt: u8, seq: &mut u16, ssrc: u32) -> Pcap {
    let mut packets = Vec::new();
    if events.is_empty() {
        return Pcap { packets, base: 0 };
    }
    let mut push = |at_ms: u64, marker: bool, pt: u8, ts: u32, body: [u8; 4]| {
        let mut p = vec![0x80, if marker { 0x80 | pt } else { pt }];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&ts.to_be_bytes());
        p.extend_from_slice(&ssrc.to_be_bytes());
        p.extend_from_slice(&body);
        *seq = seq.wrapping_add(1);
        packets.push(Packet { at: Duration::from_millis(at_ms), dport: 0, payload: p });
    };
    // RTP timestamps count 8 kHz samples, from 24000.
    let ms = |t: u64| (t * 8) as u32;
    // No-ops are 97, unless the events use it.
    let noop = if pt == 97 { 96 } else { 97 };
    for i in 0..20 {
        push(i * 20, false, noop, 24000 + ms(i * 20), [0; 4]);
    }
    let (start, ts_start) = (400, 24000 + ms(400));
    for (n, &event) in events.iter().enumerate() {
        let n = n as u64;
        let (at, ts) = (start + (n + 1) * tone * 2, ts_start + ms(n * tone * 2));
        let body = |end: bool, duration: u64| {
            let d = (ms(duration) as u16).to_be_bytes();
            [event, if end { 0x80 } else { 0 } | 10, d[0], d[1]]
        };
        for cur in (0..tone).step_by(20) {
            push(at + cur, cur == 0, pt, ts, body(false, cur));
        }
        for i in 0..3 {
            push(at + tone + i + 1, false, pt, ts, body(true, tone));
        }
    }
    Pcap { packets, base: 0 }
}

/// The UDP datagram (header included) of an IPv4 or IPv6 packet.
fn udp_of(ip: &[u8]) -> Option<&[u8]> {
    match ip.first()? >> 4 {
        // Past the hop-by-hop, routing and destination options headers
        // (next header, length in 8 octets less 1), not a fragment.
        6 => {
            let (mut next, mut at) = (*ip.get(6)?, 40);
            while matches!(next, 0 | 43 | 60) && at + 8 <= ip.len() {
                next = ip[at];
                at += (usize::from(ip[at + 1]) + 1) * 8;
            }
            (next == IPPROTO_UDP && at + 8 <= ip.len()).then(|| &ip[at..])
        }
        // Anything else is taken as IPv4.
        _ => {
            let ihl = usize::from(ip[0] & 0x0f) * 4;
            (*ip.get(9)? == IPPROTO_UDP).then(|| ip.get(ihl..)).flatten()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pcap_file(link: u32, frames: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        for v in [0xa1b2c3d4u32, 0x0004_0002, 0, 0, 65535, link] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for (sec, usec, f) in frames {
            for v in [*sec, *usec, f.len() as u32, f.len() as u32] {
                out.extend_from_slice(&v.to_le_bytes());
            }
            out.extend_from_slice(f);
        }
        out
    }

    fn udp_v4(dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, IPPROTO_UDP, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2];
        ip.extend_from_slice(&1234u16.to_be_bytes());
        ip.extend_from_slice(&dport.to_be_bytes());
        ip.extend_from_slice(&(8 + payload.len() as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0]);
        ip.extend_from_slice(payload);
        ip
    }

    fn ether(ethertype: u16, l3: Vec<u8>) -> Vec<u8> {
        let mut f = vec![0; 12];
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend(l3);
        f
    }

    #[test]
    fn udp_payloads_timing_and_base() {
        let vlan = |dport, payload| {
            let mut f = vec![0; 12];
            f.extend_from_slice(&[0x81, 0x00, 0, 5, 0x08, 0x00]);
            f.extend(udp_v4(dport, payload));
            f
        };
        let file = pcap_file(LINKTYPE_ETHERNET, &[
            (10, 0, ether(ETHERTYPE_IPV4, udp_v4(4000, b"one"))),
            (10, 20_000, ether(0x0806, vec![0; 28])), // ARP: skipped
            (10, 25_000, vlan(4001, b"tag")), // Tagged, where the first was not
            (10, 40_000, ether(ETHERTYPE_IPV4, udp_v4(4001, b"rtcp"))),
            (10, 30_000, ether(ETHERTYPE_IPV4, udp_v4(4000, b"late"))),
            (10, 60_000, ether(ETHERTYPE_IPV4, udp_v4(4000, b"two"))),
        ]);
        let p = parse(&file).unwrap();
        let got: Vec<_> = p.packets.iter().map(|k| (k.at.as_millis(), k.dport, k.payload.as_slice())).collect();
        assert_eq!(got, [(0, 4000, &b"one"[..]), (25, 4001, b"tag"), (40, 4001, b"rtcp"), (40, 4000, b"late"), (70, 4000, b"two")]);
        assert_eq!(p.base, 4000);
        // Untagged after a tagged first one, and a first ARP one ignored.
        let p = parse(&pcap_file(LINKTYPE_ETHERNET, &[
            (1, 0, ether(0x0806, vec![0; 28])),
            (1, 0, vlan(4002, b"a")),
            (1, 0, ether(ETHERTYPE_IPV4, udp_v4(4003, b"b"))),
        ]))
        .unwrap();
        assert_eq!(p.packets.iter().map(|k| k.dport).collect::<Vec<_>>(), [4002, 4003]);
    }

    #[test]
    fn udp_behind_ipv6_extension_headers() {
        let v6 = |next: u8, ext: &[u8], udp: &[u8]| {
            let mut ip = vec![0x60, 0, 0, 0];
            ip.extend_from_slice(&((ext.len() + udp.len()) as u16).to_be_bytes());
            ip.extend_from_slice(&[next, 64]);
            ip.extend_from_slice(&[0; 32]);
            ip.extend_from_slice(ext);
            ip.extend_from_slice(udp);
            ether(ETHERTYPE_IPV6, ip)
        };
        let udp = |dport: u16| udp_v4(dport, b"x")[20..].to_vec();
        // Hop-by-hop, then routing (16 octets), then destination options.
        let (hop, routing, dst) = ([43, 0, 1, 4, 0, 0, 0, 0], [60, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [IPPROTO_UDP, 0, 1, 4, 0, 0, 0, 0]);
        let chain = [&hop[..], &routing, &dst].concat();
        let fragment = [IPPROTO_UDP, 0, 0, 0, 0, 0, 0, 1];
        let p = parse(&pcap_file(LINKTYPE_ETHERNET, &[
            (1, 0, v6(IPPROTO_UDP, &[], &udp(5000))),
            (1, 0, v6(0, &chain, &udp(5001))),
            (1, 0, v6(44, &fragment, &udp(5002))), // A fragment: not played
            (1, 0, v6(0, &hop[..4], &[])), // Cut short
        ]))
        .unwrap();
        assert_eq!(p.packets.iter().map(|k| k.dport).collect::<Vec<_>>(), [5000, 5001]);
    }

    #[test]
    fn libpcap_open_errors() {
        let err = |data: &[u8]| parse(data).unwrap_err();
        assert_eq!(err(b"abc"), "truncated dump file; tried to read 4 file header bytes, only got 3");
        assert_eq!(err(&[0xd4, 0xc3, 0xb2, 0xa1, 2, 0]), "truncated dump file; tried to read 24 file header bytes, only got 2");
        assert_eq!(err(&[0; 24]), "unknown file format");
        let mut v29 = pcap_file(LINKTYPE_ETHERNET, &[]);
        v29[6] = 9;
        assert_eq!(err(&v29), "unsupported pcap savefile version 2.9");
        v29[4] = 1;
        assert_eq!(err(&v29), "archaic pcap savefile format");
        // A record libpcap can't read ends the capture.
        let mut cut = pcap_file(LINKTYPE_RAW, &[(1, 0, udp_v4(4000, b"one")), (1, 0, udp_v4(4000, b"two"))]);
        cut.truncate(cut.len() - 3);
        assert_eq!(parse(&cut).unwrap().packets.len(), 1);
        let missing = load("/nonexistent/x.pcap").unwrap_err();
        let why = if cfg!(windows) { "The system cannot find the path specified." } else { "No such file or directory" };
        assert_eq!(missing, format!("Can't open PCAP file '/nonexistent/x.pcap': /nonexistent/x.pcap: {why}"));
    }

    /// A big-endian pcapng section: nanosecond timestamps from if_tsresol,
    /// shifted by if_tsoffset, and packets padded to 32 bits.
    fn pcapng_file(links: &[u16], frames: &[(u64, Vec<u8>)]) -> Vec<u8> {
        fn block(out: &mut Vec<u8>, kind: u32, body: &[u8]) {
            let total = 12 + body.len().div_ceil(4) * 4;
            out.extend_from_slice(&kind.to_be_bytes());
            out.extend_from_slice(&(total as u32).to_be_bytes());
            out.extend_from_slice(body);
            out.resize(out.len() + (4 - body.len() % 4) % 4, 0);
            out.extend_from_slice(&(total as u32).to_be_bytes());
        }
        let mut out = Vec::new();
        let mut shb = 0x1a2b_3c4du32.to_be_bytes().to_vec();
        shb.extend_from_slice(&[0, 1, 0, 0]);
        shb.extend_from_slice(&u64::MAX.to_be_bytes());
        block(&mut out, PCAPNG_SHB, &shb);
        for link in links {
            let mut idb = link.to_be_bytes().to_vec();
            idb.extend_from_slice(&[0, 0, 0, 0, 0xff, 0xff]);
            idb.extend_from_slice(&[0, 9, 0, 1, 9, 0, 0, 0]);
            idb.extend_from_slice(&[0, 14, 0, 8]);
            idb.extend_from_slice(&100u64.to_be_bytes());
            idb.extend_from_slice(&[0, 0, 0, 0]);
            block(&mut out, 1, &idb);
        }
        for (ns, f) in frames {
            let mut epb = 0u32.to_be_bytes().to_vec();
            for v in [(ns >> 32) as u32, *ns as u32, f.len() as u32, f.len() as u32] {
                epb.extend_from_slice(&v.to_be_bytes());
            }
            epb.extend_from_slice(f);
            block(&mut out, 6, &epb);
        }
        out
    }

    #[test]
    fn pcapng_as_libpcap_reads_it() {
        let raw = |port| udp_v4(port, b"abc");
        let p = parse(&pcapng_file(&[101], &[(1_000_000_500, raw(6000)), (1_020_000_750, raw(6001))])).unwrap();
        assert_eq!(p.base, 6000);
        assert_eq!(p.packets.len(), 2);
        assert_eq!(p.packets[1].at, Duration::from_nanos(20_000_250));
        assert_eq!(p.packets[0].payload, b"abc");
        assert!(parse(&pcapng_file(&[101, 1], &[])).unwrap_err().contains("different from the type"));
    }

    #[test]
    fn dtmf_events() {
        let mut seq = 1200;
        let (events, tone, pt, _) = parse_dtmf("1#x,100");
        let p = dtmf(&events, tone, pt, &mut seq, 0xdead);
        // 20 no-ops, then per digit 5 updates (100 ms / 20) and 3 ends.
        assert_eq!(p.packets.len(), 20 + 2 * (5 + 3));
        assert_eq!(seq, 1200 + 36);
        let seqs: Vec<u16> = p.packets.iter().map(|k| u16::from_be_bytes([k.payload[2], k.payload[3]])).collect();
        assert!(seqs.windows(2).all(|w| w[1] == w[0] + 1), "{seqs:?}");
        let first = &p.packets[20];
        assert_eq!(first.at, Duration::from_millis(400 + 200));
        assert_eq!(&first.payload[..2], &[0x80, 0x80 | 96]);
        assert_eq!(u32::from_be_bytes(first.payload[4..8].try_into().unwrap()), 24000 + 400 * 8);
        assert_eq!(&first.payload[12..], &[1, 10, 0, 0]);
        let end = &p.packets[27];
        assert_eq!(&end.payload[12..], &[1, 0x80 | 10, 0x03, 0x20]);
        let pound = &p.packets[28];
        assert_eq!((pound.payload[12], u32::from_be_bytes(pound.payload[4..8].try_into().unwrap())), (11, 24000 + 400 * 8 + 200 * 8));
        assert!(p.packets.windows(2).all(|w| w[0].at <= w[1].at));
        assert!(dtmf(&[], 200, 96, &mut seq, 1).packets.is_empty());
        // The payload type, and the no-ops' when the events take 97.
        let pts = |spec: &str, n: usize| {
            let (events, tone, pt, _) = parse_dtmf(spec);
            dtmf(&events, tone, pt, &mut 0, 1).packets[n].payload[1] & 0x7f
        };
        assert_eq!((pts("1", 20), pts("1,100,101", 20), pts("1,100,101", 0), pts("1,100,97", 0), pts("1,100,", 20)), (96, 101, 97, 96, 96));
    }

    #[test]
    fn dtmf_args() {
        let ok = |spec: &str| {
            let (_, tone, pt, error) = parse_dtmf(spec);
            assert_eq!(error, None, "{spec}");
            (tone, pt)
        };
        assert_eq!((ok("1"), ok("x1,,"), ok("*#ABCD,50,0"), ok("1,2000,127")), ((200, 96), (200, 96), (50, 0), (2000, 127)));
        let bad = |spec: &str| {
            let (_, tone, pt, error) = parse_dtmf(spec);
            (tone, pt, error.unwrap_or_else(|| panic!("{spec}")))
        };
        for spec in ["", "abc,100", ",100", "1,2001", "1,foo", "1,100x", "1,100,101x", "1,100,128", "1,100,-1", "1,100,101,1"] {
            bad(spec);
        }
        assert_eq!(bad("1,49").0, 200);
        assert_eq!(bad("1,100,foo"), (100, 96, "the payload type is not 0 to 127 (default 96)"));
        // The first problem is the one told.
        assert!(bad("1,10,128").2.contains("tone length"));
    }

    #[test]
    fn ip_headers() {
        let to = |ip: &str| SocketAddr::new(ip.parse().unwrap(), 6000);
        let v4 = ip_udp("10.0.0.1".parse().unwrap(), 5000, to("10.0.0.2"), b"abc");
        assert_eq!(v4, [&[0x45, 0, 0, 31, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2][..], &[0x13, 0x88, 0x17, 0x70, 0, 11, 0, 0], b"abc"].concat());
        let v6 = ip_udp("fe80::1".parse().unwrap(), 5000, to("fe80::2"), b"abc");
        assert_eq!((v6.len(), &v6[..8], &v6[40..46]), (51, &[0x60, 0, 0, 0, 0, 11, 17, 64][..], &[0x13, 0x88, 0x17, 0x70, 0, 11][..]));
        // Over the pseudo-header, the sum with the checksum is all ones.
        let mut sum: u32 = v6[8..40].chunks(2).chain(v6[40..].chunks(2)).map(|w| u32::from(w[0]) << 8 | u32::from(*w.get(1).unwrap_or(&0))).sum::<u32>() + 11 + 17;
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum, 0xffff);
    }

    #[test]
    fn shipped_captures() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../pcap/");
        let g711 = parse(&std::fs::read(format!("{dir}g711a.pcap")).unwrap()).unwrap();
        // 236 packets of 30 ms A-law: a 12-byte RTP header and 240 samples.
        assert_eq!(g711.packets.len(), 236);
        assert!(g711.packets.iter().all(|k| k.payload.len() == 252 && k.payload[0] == 0x80));
        let gaps: Vec<_> = g711.packets.windows(2).map(|w| (w[1].at - w[0].at).as_millis()).collect();
        assert!(gaps.iter().filter(|&&g| (28..=32).contains(&g)).count() > gaps.len() * 9 / 10, "{gaps:?}");
        assert!(parse(b"\x0a\x0d\x0d\x0a....................").is_err());
    }
}


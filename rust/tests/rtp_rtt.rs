//! The RTT probe (apattern 7): a UAC sends stamped RTP, an echoing UAS returns
//! it, and the UAC writes one row per call to -rtp_rtt_file and summarises the
//! round trips at exit. The second test runs without the flag.

use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

const UAC: &str = r#"<?xml version="1.0" encoding="ISO-8859-1" ?>
<!DOCTYPE scenario SYSTEM "sipp.dtd">
<scenario name="rtp_rtt_probe">
  <send retrans="500">
    <![CDATA[

      INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
      From: <sip:[from_user]@[local_ip]:[local_port]>;tag=[call_number]
      To: <sip:[service]@[remote_ip]:[remote_port]>
      Call-ID: [call_id]
      CSeq: 1 INVITE
      Contact: <sip:[from_user]@[local_ip]:[local_port]>
      Max-Forwards: 70
      Content-Type: application/sdp
      Content-Length: [len]

      v=0
      o=uac 0 0 IN IP[media_ip_type] [media_ip]
      s=-
      c=IN IP[media_ip_type] [media_ip]
      t=0 0
      m=audio [rtpstream_audio_port] RTP/AVP 0
      a=rtpmap:0 PCMU/8000

    ]]>
  </send>

  <recv response="100" optional="true" />
  <recv response="180" optional="true" />
  <recv response="200" />

  <send>
    <![CDATA[

      ACK [next_url] SIP/2.0
      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
      From: <sip:[from_user]@[local_ip]:[local_port]>;tag=[call_number]
      To: <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
      Call-ID: [call_id]
      CSeq: 1 ACK
      Max-Forwards: 70
      Content-Length: 0

    ]]>
  </send>

  <nop>
    <action>
      <exec rtp_stream="apattern,7,0,PCMU/8000" />
    </action>
  </nop>

  <pause />

  <send retrans="500">
    <![CDATA[

      BYE [next_url] SIP/2.0
      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
      From: <sip:[from_user]@[local_ip]:[local_port]>;tag=[call_number]
      To: <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
      Call-ID: [call_id]
      CSeq: 2 BYE
      Max-Forwards: 70
      Content-Length: 0

    ]]>
  </send>

  <recv response="200" crlf="true" />
</scenario>
"#;

/// Distinct loopback ports per test in this process.
static SLOT: AtomicU16 = AtomicU16::new(0);

struct Ports {
    uas_sip: u16,
    uac_sip: u16,
    uas_media: u16,
    uac_media: u16,
}

impl Ports {
    fn new() -> Ports {
        let slot = SLOT.fetch_add(1, Ordering::Relaxed) % 200;
        Ports {
            uas_sip: 16000 + slot * 6,
            uac_sip: 16001 + slot * 6,
            uas_media: 25000 + slot * 40,
            uac_media: 30000 + slot * 40,
        }
    }
}

fn dir(name: &str) -> std::path::PathBuf {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("test-rtp-rtt")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn start_uas(ports: &Ports, dir: &std::path::Path) -> Child {
    let child = Command::new(env!("CARGO_BIN_EXE_sipp-rs"))
        .args([
            "-sn", "uas", "-rtp_echo", "-i", "127.0.0.1",
            "-p", &ports.uas_sip.to_string(),
            "-mp", &ports.uas_media.to_string(),
            "-min_rtp_port", &ports.uas_media.to_string(),
            "-max_rtp_port", &(ports.uas_media + 20).to_string(),
            "-nostdin", "-timeout", "15s",
        ])
        .current_dir(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start the echoing UAS");
    wait_ready(ports.uas_sip);
    child
}

/// Whether the UAS has bound its SIP port, as /proc/net/udp shows it.
fn wait_ready(port: u16) {
    let needle = format!(":{port:04X}");
    for _ in 0..150 {
        if let Ok(text) = std::fs::read_to_string("/proc/net/udp") {
            if text.lines().skip(1).any(|l| l.split_whitespace().nth(1).is_some_and(|a| a.ends_with(&needle))) {
                // The -rtp_echo thread starts with the traffic.
                std::thread::sleep(Duration::from_millis(50));
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("the UAS did not bind port {port}");
}

fn uac(ports: &Ports, dir: &std::path::Path, rtt: bool) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sipp-rs"));
    cmd.current_dir(dir).args([
        &format!("127.0.0.1:{}", ports.uas_sip),
        "-sf", "rtp_rtt.xml", "-i", "127.0.0.1",
        "-p", &ports.uac_sip.to_string(),
        "-min_rtp_port", &ports.uac_media.to_string(),
        "-max_rtp_port", &(ports.uac_media + 20).to_string(),
        "-m", "1", "-nostdin", "-d", "2500",
        "-key", "from_user", "sipp", "-s", "service", "-timeout", "15s",
    ]);
    if rtt {
        cmd.args(["-trace_rtp_rtt", "-rtp_rtt_file", "rtt.csv"]);
    }
    cmd.output().expect("run the probe UAC")
}

#[test]
fn a_probe_measures_the_echo_round_trip() {
    let ports = Ports::new();
    let dir = dir("rows");
    std::fs::write(dir.join("rtp_rtt.xml"), UAC).unwrap();
    let mut uas = start_uas(&ports, &dir);
    let out = uac(&ports, &dir, true);
    let _ = uas.kill();
    let _ = uas.wait();

    assert_eq!(out.status.code(), Some(0), "stderr:\n{}", String::from_utf8_lossy(&out.stderr));
    let csv = std::fs::read_to_string(dir.join("rtt.csv")).expect("rtt.csv written");
    let mut lines = csv.lines();
    assert_eq!(
        lines.next().unwrap(),
        "date_ms;call;stream;window_ms;sent;matched;min_ms;avg_ms;p95_ms;max_ms;duplicates;late;missing"
    );
    let rows: Vec<Vec<&str>> = lines.map(|l| l.split(';').collect()).collect();
    let total: Vec<&Vec<&str>> = rows.iter().filter(|f| f[3] == "0").collect();
    assert_eq!(total.len(), 1, "one call-total row: {csv}");
    let t = total[0];
    let sent: u64 = t[4].parse().unwrap();
    let matched: u64 = t[5].parse().unwrap();
    assert!(sent > 0, "total {t:?}");
    assert!(matched >= sent * 9 / 10, "matched {matched} of {sent}: {t:?}");
    assert_eq!(t[10], "0", "duplicates: {t:?}");
    assert_eq!(t[11], "0", "late: {t:?}");
    let avg: f64 = t[7].parse().unwrap();
    assert!(avg < 50.0, "loopback RTT should be well under a packet time: {t:?}");

    // A 2.5 s hold: full windows plus the final partial one.
    let intervals: Vec<&Vec<&str>> = rows.iter().filter(|f| f[3] != "0").collect();
    assert!(intervals.len() >= 2, "no interval rows: {csv}");
    assert!(intervals.iter().all(|f| f[3].parse::<u64>().unwrap() > 0));
    let window_sent: u64 = intervals.iter().map(|f| f[4].parse::<u64>().unwrap()).sum();
    let window_matched: u64 = intervals.iter().map(|f| f[5].parse::<u64>().unwrap()).sum();
    assert_eq!((window_sent, window_matched), (sent, matched), "windows must partition the total");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("RTP RTT probe:"), "{stdout}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn without_the_flag_the_summary_is_still_printed() {
    let ports = Ports::new();
    let dir = dir("summary");
    std::fs::write(dir.join("rtp_rtt.xml"), UAC).unwrap();
    let mut uas = start_uas(&ports, &dir);
    let out = uac(&ports, &dir, false);
    let _ = uas.kill();
    let _ = uas.wait();

    assert_eq!(out.status.code(), Some(0), "stderr:\n{}", String::from_utf8_lossy(&out.stderr));
    assert!(!dir.join("rtt.csv").exists());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("RTP RTT probe:"), "{stdout}");
    std::fs::remove_dir_all(&dir).unwrap();
}

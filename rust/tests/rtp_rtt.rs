//! The RTT probe (apattern 7): a UAC sends stamped RTP, an echoing UAS returns
//! it, and the UAC writes one row per call to -rtp_rtt_file and summarises the
//! round trips at exit. The second test runs without the flag.

use std::process::{Child, Command};
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

const UAS: &str = r#"<?xml version="1.0" encoding="ISO-8859-1" ?>
<!DOCTYPE scenario SYSTEM "sipp.dtd">
<scenario name="uas_echo">
  <recv request="INVITE" crlf="true" />
  <send>
    <![CDATA[

      SIP/2.0 200 OK
      [last_Via:]
      [last_From:]
      [last_To:];tag=[pid]SIPpTag01[call_number]
      [last_Call-ID:]
      [last_CSeq:]
      Contact: <sip:[local_ip]:[local_port];transport=[transport]>
      Content-Type: application/sdp
      Content-Length: [len]

      v=0
      o=uas 0 0 IN IP[media_ip_type] [media_ip]
      s=-
      c=IN IP[media_ip_type] [media_ip]
      t=0 0
      m=audio [rtpstream_audio_port] RTP/AVP 0
      a=rtpmap:0 PCMU/8000

    ]]>
  </send>
  <recv request="ACK" crlf="true" />
  <nop>
    <action>
      <exec rtp_echo="startaudio" />
    </action>
  </nop>
  <recv request="BYE" crlf="true" />
  <send>
    <![CDATA[

      SIP/2.0 200 OK
      [last_Via:]
      [last_From:]
      [last_To:]
      [last_Call-ID:]
      [last_CSeq:]
      Contact: <sip:[local_ip]:[local_port];transport=[transport]>
      Content-Length: 0

    ]]>
  </send>
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
    std::fs::write(dir.join("uas_echo.xml"), UAS).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_sipp-rs"))
        .args([
            "-sf", "uas_echo.xml", "-i", "127.0.0.1",
            "-p", &ports.uas_sip.to_string(),
            "-mp", &ports.uas_media.to_string(),
            "-min_rtp_port", &ports.uas_media.to_string(),
            "-max_rtp_port", &(ports.uas_media + 20).to_string(),
            "-trace_probe_tags", "-probe_tags_file", "uas_tags.csv",
            "-nostdin", "-timeout", "15s",
        ])
        .current_dir(dir)
        .stdout(std::fs::File::create(dir.join("uas.out")).unwrap())
        .stderr(std::fs::File::create(dir.join("uas.err")).unwrap())
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

    assert_eq!(out.status.code(), Some(0), "stderr:\n{}", String::from_utf8_lossy(&out.stderr));
    let csv = std::fs::read_to_string(dir.join("rtt.csv")).expect("rtt.csv written");
    let mut lines = csv.lines();
    assert_eq!(
        lines.next().unwrap(),
        "date_ms;call;stream;window_ms;sent;matched;min_ms;avg_ms;p95_ms;max_ms;jitter_ms;duplicates;late;missing;tag"
    );
    let rows: Vec<Vec<&str>> = lines.map(|l| l.split(';').collect()).collect();
    let total: Vec<&Vec<&str>> = rows.iter().filter(|f| f[3] == "0").collect();
    assert_eq!(total.len(), 1, "one call-total row: {csv}");
    let t = total[0];
    let sent: u64 = t[4].parse().unwrap();
    let matched: u64 = t[5].parse().unwrap();
    assert!(sent > 0, "total {t:?}");
    assert!(matched >= sent * 9 / 10, "matched {matched} of {sent}: {t:?}");
    assert_eq!(t[11], "0", "duplicates: {t:?}");
    assert_eq!(t[12], "0", "late: {t:?}");
    assert!(t[10].parse::<f64>().unwrap() >= 0.0, "jitter: {t:?}");
    // The probe tag names the payload marker, so a capture pair can be
    // attributed to this call number; the total and its windows agree.
    let tag: u32 = t[14].parse().expect("tag column");
    assert!(tag != 0, "tag is the payload marker: {t:?}");
    let avg: f64 = t[7].parse().unwrap();
    assert!(avg < 50.0, "loopback RTT should be well under a packet time: {t:?}");

    // The echoing UAS noted the tag per call (-trace_probe_tags), so the legs
    // can be paired without a packet capture. Rows are flushed at the next
    // screen refresh after the call ends.
    let started = std::time::Instant::now();
    let tags = loop {
        if let Ok(text) = std::fs::read_to_string(dir.join("uas_tags.csv")) {
            if text.lines().count() >= 2 {
                break text;
            }
        }
        assert!(
            started.elapsed().as_secs() < 5,
            "the UAS did not write the probe tag row"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    let mut tag_lines = tags.lines();
    assert_eq!(
        tag_lines.next().unwrap(),
        "date_ms;call;stream;tag;packets;call_id"
    );
    let echoed: Vec<&str> = tag_lines.next().unwrap().split(';').collect();
    assert_eq!(echoed.len(), 6, "row shape: {echoed:?}");
    assert!(echoed[2] == "audio" || echoed[2] == "video", "stream: {echoed:?}");
    assert_eq!(echoed[3].parse::<u32>().unwrap(), tag, "the echoed tag is the sent one");
    assert!(echoed[4].parse::<u64>().unwrap() > 0, "echoed packets: {echoed:?}");
    assert!(echoed[5].contains('@'), "the UAS knows its call's Call-ID: {echoed:?}");

    // A 2.5 s hold: full windows plus the final partial one.
    let intervals: Vec<&Vec<&str>> = rows.iter().filter(|f| f[3] != "0").collect();
    assert!(intervals.len() >= 2, "no interval rows: {csv}");
    assert!(intervals.iter().all(|f| f[3].parse::<u64>().unwrap() > 0));
    assert!(intervals.iter().all(|f| f[14].parse::<u32>().unwrap() == tag),
        "every window carries the stream's tag: total {tag}, windows {:?}",
        intervals.iter().map(|f| f[14]).collect::<Vec<_>>());
    let window_sent: u64 = intervals.iter().map(|f| f[4].parse::<u64>().unwrap()).sum();
    let window_matched: u64 = intervals.iter().map(|f| f[5].parse::<u64>().unwrap()).sum();
    assert_eq!((window_sent, window_matched), (sent, matched), "windows must partition the total");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("RTP RTT probe:"), "{stdout}");
    // The UAS is still running: its rows flush on the next screen refresh.
    let _ = uas.kill();
    let _ = uas.wait();
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
    // The UAS is still running: its rows flush on the next screen refresh.
    let _ = uas.kill();
    let _ = uas.wait();
    std::fs::remove_dir_all(&dir).unwrap();
}

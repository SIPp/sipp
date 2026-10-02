//! SIGTERM ends the run at once, SIGUSR1 lets the open calls end first.
// Signals, which Windows has none of.
#![cfg(unix)]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const SCENARIO: &str = r#"<?xml version="1.0" encoding="ISO-8859-1" ?>
<scenario name="pause">
  <send>
    <![CDATA[
      OPTIONS sip:[service]@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[call_number]
      To: <sip:[service]@[remote_ip]:[remote_port]>
      Call-ID: [call_id]
      CSeq: 1 OPTIONS
      Content-Length: 0

    ]]>
  </send>
  <pause milliseconds="1500"/>
</scenario>
"#;

/// Runs the scenario at 10 calls/s, sends `sig` half a second after the
/// first message went out (the handlers are in place by then, however
/// long the start took), and returns the exit code, stdout and how long
/// the run lasted after the signal, and its -trace_screen file.
fn run_with(sig: libc::c_int, name: &str) -> (Option<i32>, String, Duration, String) {
    let dir = std::env::temp_dir().join(format!("sipp-rs-signal-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let xml = dir.join("pause.xml");
    std::fs::write(&xml, SCENARIO).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_sipp-rs"))
        .args(["-sf", xml.to_str().unwrap(), "-m", "100", "-r", "10", "-p", "0", "-nostdin", "-timeout", "20", "-trace_msg", "-message_file", "msg.log", "-trace_screen", "127.0.0.1:9"])
        .current_dir(&dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let log = dir.join("msg.log");
    let wait = Instant::now();
    while std::fs::metadata(&log).map_or(true, |m| m.len() == 0) && wait.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(500));
    let start = Instant::now();
    let child_id = child.id();
    // SAFETY: a signal to our own child.
    unsafe { libc::kill(child_id as libc::pid_t, sig) };
    let out = child.wait_with_output().unwrap();
    let took = start.elapsed();
    let screen = std::fs::read_to_string(dir.join(format!("pause_{}_screen.log", child_id))).unwrap_or_default();
    std::fs::remove_dir_all(&dir).unwrap();
    (out.status.code(), String::from_utf8_lossy(&out.stdout).into_owned(), took, screen)
}

fn cumulative(stdout: &str, counter: &str) -> u32 {
    let line = stdout.lines().rfind(|l| l.trim_start().starts_with(counter)).unwrap();
    line.rsplit('|').next().unwrap().trim().parse().unwrap()
}

#[test]
fn sigterm_ends_the_run_now() {
    let (code, stdout, took, screen) = run_with(libc::SIGTERM, "term");
    assert_eq!(code, Some(0), "{stdout}");
    assert!(took < Duration::from_millis(900), "{took:?}");
    assert!(stdout.contains("Test Terminated"), "{stdout}");
    // The -trace_screen file has the screens.
    assert!(screen.contains("Scenario Screen"), "{screen}");
    // The calls still open neither succeeded nor failed.
    assert_eq!(cumulative(&stdout, "Successful call"), 0, "{stdout}");
    assert_eq!(cumulative(&stdout, "Failed call"), 0, "{stdout}");
}

#[test]
fn sigusr1_quits_softly() {
    let (code, stdout, took, _) = run_with(libc::SIGUSR1, "usr1");
    assert_eq!(code, Some(0), "{stdout}");
    // No new call after the signal, and the open ones end their pause.
    assert!(took >= Duration::from_millis(900) && took < Duration::from_secs(3), "{took:?}");
    let created = cumulative(&stdout, "Outgoing calls created");
    assert!((1..=8).contains(&created), "{stdout}");
    assert_eq!(cumulative(&stdout, "Successful call"), created, "{stdout}");
}

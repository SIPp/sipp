//! How a run ends decides what it leaves behind, as SIPp's sipp_exit():
//! stop_now or a fatal error exits at once, with one statistics row and
//! the -trace_screen file; the traffic loop quitting writes a row, the
//! screen file, and another row.

use std::process::{Command, Stdio};

fn scenario(action: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="ISO-8859-1" ?>
<scenario name="exits">
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
  <nop><action>{action}</action></nop>
  <pause milliseconds="200"/>
</scenario>
"#
    )
}

/// The exit code, the -trace_stat rows and the -trace_screen file.
fn run(name: &str, action: &str) -> (Option<i32>, usize, String) {
    let dir = std::env::temp_dir().join(format!("sipp-rs-exits-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("exits.xml"), scenario(action)).unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_sipp-rs"))
        .args(["-sf", "exits.xml", "-m", "1", "-p", "0", "-nostdin", "-trace_stat", "-stf", "stat.csv", "-trace_screen", "-screen_file", "screen.log", "127.0.0.1:9"])
        .current_dir(&dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    let rows = std::fs::read_to_string(dir.join("stat.csv")).unwrap().lines().count() - 1;
    let screen = std::fs::read_to_string(dir.join("screen.log")).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    (status.code(), rows, screen)
}

#[test]
fn stop_now_exits_at_once() {
    // The row at the start, and sipp_exit()'s, and the screens.
    let (code, rows, screen) = run("now", r#"<exec int_cmd="stop_now"/>"#);
    assert_eq!((code, rows), (Some(97), 2));
    assert!(screen.contains("Scenario Screen"), "{screen}");
}

#[test]
fn a_fatal_error_exits_at_once() {
    let (code, rows, screen) = run("error", r#"<error message="boom"/>"#);
    assert_eq!((code, rows), (Some(255), 2));
    assert!(screen.contains("Scenario Screen"), "{screen}");
}

#[test]
fn stop_gracefully_ends_the_traffic_loop() {
    let (code, rows, screen) = run("gracefully", r#"<exec int_cmd="stop_gracefully"/>"#);
    assert_eq!((code, rows), (Some(0), 3));
    assert!(screen.contains("------- Waiting for active calls to end. Press [q] again to force exit. -------"), "{screen}");
    assert!(!screen.contains("Test Terminated"), "{screen}");
}

#[test]
fn a_setup_error_goes_through_sipp_exit() {
    let dir = std::env::temp_dir().join(format!("sipp-rs-exits-bind-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let taken = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port().to_string();
    let out = Command::new(env!("CARGO_BIN_EXE_sipp-rs"))
        .args(["-sn", "uac", "-i", "127.0.0.1", "-p", &port, "-m", "1", "-nostdin", "-trace_stat", "-stf", "stat.csv", "127.0.0.1:9"])
        .current_dir(&dir)
        .output()
        .unwrap();
    let rows = std::fs::read_to_string(dir.join("stat.csv")).unwrap().lines().count() - 1;
    std::fs::remove_dir_all(&dir).unwrap();
    let (stdout, stderr) = (String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    // EXIT_BIND_ERROR, the error as ERROR_NO() prints it (once: not
    // again as the last error), the closing screens, and a statistics
    // row.
    assert_eq!(out.status.code(), Some(254));
    let in_use = match () {
        _ if cfg!(windows) => "10048 (Only one usage of each socket address (protocol/network address/port) is normally permitted.)",
        _ if cfg!(target_os = "macos") => "48 (Address already in use)",
        _ => "98 (Address already in use)",
    };
    assert_eq!(stderr.matches(&format!(": Unable to bind main socket, errno = {in_use}\n")).count(), 1, "{stderr}");
    assert!(stdout.contains("Test Terminated"), "{stdout}");
    assert_eq!(rows, 1);
}

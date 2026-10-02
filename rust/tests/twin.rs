//! A reset of the 3PCC twin connection is a TCP reset like any other, as
//! in SIPp's read_error() and reset_connection(): fatal without a
//! reconnection left, else controller A connects to B again after
//! -reconnect_sleep, and controller B waits for A to. A call waiting for
//! a command the lost connection took fails as on a closed connection; a
//! command written while A connects again waits for the connection.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const A: &str = r#"<?xml version="1.0" encoding="ISO-8859-1" ?>
<scenario name="3pcc A without SIP">
  <sendCmd>
    <![CDATA[
      Call-ID: [call_id]
      From: a
    ]]>
  </sendCmd>
  <recvCmd/>
</scenario>
"#;

fn reset(s: TcpStream) {
    socket2::SockRef::from(&s).set_linger(Some(Duration::ZERO)).unwrap();
}

/// What a command up to its ESC says.
fn command(s: &mut TcpStream) -> String {
    let mut got = Vec::new();
    let mut b = [0u8; 1];
    while s.read(&mut b).unwrap() == 1 && b[0] != 0x1b {
        got.push(b[0]);
    }
    String::from_utf8(got).unwrap()
}

/// command(), up to the end of the connection or a read that fails.
fn command_until_closed(s: &mut TcpStream) -> String {
    let mut got = Vec::new();
    let mut b = [0u8; 1];
    while s.read(&mut b).is_ok_and(|n| n == 1) && b[0] != 0x1b {
        got.push(b[0]);
    }
    String::from_utf8_lossy(&got).into_owned()
}

fn sipp(dir: &std::path::Path, args: &[&str]) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_sipp-rs"))
        .args(args)
        .args(["-i", "127.0.0.1", "-p", "0", "-nostdin", "-timeout", "5"])
        .current_dir(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("sipp-rs-twin-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("a.xml"), A).unwrap();
    d
}

/// Controller A against a B that ends the first connection after the
/// command (a reset, else a close), and answers the next command.
fn controller_a(name: &str, rst: bool, options: &[&str]) -> (Output, usize) {
    let d = dir(name);
    let b = TcpListener::bind("127.0.0.1:0").unwrap();
    let twin = b.local_addr().unwrap().to_string();
    let mut args = vec!["-sf", "a.xml", "-3pcc", &twin, "-m", "2", "-trace_err", "-error_file", "errors.log"];
    args.extend(options);
    let mut child = sipp(&d, &args);
    let (mut first, _) = b.accept().unwrap();
    command(&mut first);
    if rst {
        reset(first);
    } else {
        drop(first);
    }
    b.set_nonblocking(true).unwrap();
    let mut connections = 1;
    let out = loop {
        if let Ok((mut again, _)) = b.accept() {
            connections += 1;
            again.set_nonblocking(false).unwrap();
            let cmd = command(&mut again);
            let call_id = cmd.lines().find_map(|l| l.trim().strip_prefix("Call-ID: ")).unwrap().to_string();
            again.write_all(format!("Call-ID: {call_id}\r\nFrom: b\r\n\x1b").as_bytes()).unwrap();
            break child.wait_with_output().unwrap();
        }
        if child.try_wait().unwrap().is_some() {
            break child.wait_with_output().unwrap();
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let errors = std::fs::read_to_string(d.join("errors.log")).unwrap_or_default();
    std::fs::remove_dir_all(&d).unwrap();
    let mut out = out;
    out.stderr = errors.into_bytes();
    (out, connections)
}

fn warnings(out: &Output) -> Vec<String> {
    String::from_utf8_lossy(&out.stderr).lines().filter_map(|l| l.split_once(": ").map(|(_, w)| w.to_string())).collect()
}


/// The system's words for a reset connection.
const RESET: &str = if cfg!(windows) {
    "Error on TCP connection, remote peer probably closed the socket: An existing connection was forcibly closed by the remote host."
} else {
    "Error on TCP connection, remote peer probably closed the socket: Connection reset by peer"
};
#[test]
fn controller_a_reconnects_to_b_failing_the_call_left_waiting() {
    let (out, connections) = controller_a("again", true, &["-max_reconnect", "1", "-reconnect_sleep", "10"]);
    assert_eq!((out.status.code(), connections), (Some(1), 2), "{out:?}");
    let w = warnings(&out);
    assert_eq!(
        w,
        [
            RESET,
            "Closing calls, because of TCP reset or close!",
            "Socket required a reconnection.",
        ]
    );
}

#[test]
fn controller_a_ends_on_a_reset_without_a_reconnection_left() {
    let (out, connections) = controller_a("fatal", true, &[]);
    assert_eq!((out.status.code(), connections), (Some(255), 1), "{out:?}");
    assert_eq!(warnings(&out), [RESET]);
}

#[test]
fn controller_a_fails_the_call_waiting_when_b_closes() {
    let (out, connections) = controller_a("closed", false, &[]);
    assert_eq!((out.status.code(), connections), (Some(1), 1), "{out:?}");
    assert_eq!(warnings(&out), ["The remote peer closed the TCP connection, failing 1 call(s)"]);
}

#[test]
fn controller_b_waits_for_a_again_on_a_reset() {
    let d = dir("b");
    let twin = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().to_string();
    let child = sipp(&d, &["-sn", "3pcc-C-B", "-3pcc", &twin, "-max_reconnect", "1", "-trace_err", "-error_file", "errors.log", "127.0.0.1:9"]);
    let connect = || (0..100).find_map(|_| TcpStream::connect(&twin).ok().or_else(|| { std::thread::sleep(Duration::from_millis(20)); None })).unwrap();
    let a = connect();
    std::thread::sleep(Duration::from_millis(100));
    reset(a);
    std::thread::sleep(Duration::from_millis(100));
    // A again, which ends cleanly.
    drop(connect());
    let mut out = child.wait_with_output().unwrap();
    out.stderr = std::fs::read(d.join("errors.log")).unwrap_or_default();
    std::fs::remove_dir_all(&d).unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(
        warnings(&out),
        [
            RESET,
            "Closing calls, because of TCP reset or close!",
            "3PCC controller A has ended -> exiting",
        ]
    );
}

#[test]
fn controller_a_sends_a_command_written_while_b_is_down() {
    let d = dir("down");
    let b = TcpListener::bind("127.0.0.1:0").unwrap();
    let twin = b.local_addr().unwrap().to_string();
    // The next connection that delivers a command with a Call-ID, which
    // B answers: one that closes or sends none first is skipped, as A's
    // connection that raced with B's listener closing and opening again
    // can be, on macOS.
    let errors = || std::fs::read_to_string(d.join("errors.log")).unwrap_or_default();
    // A connection within 10 s, or the test fails instead of hanging.
    let accept = |b: &TcpListener, child: &mut Child| {
        b.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match b.accept() {
                Ok((s, _)) => {
                    s.set_nonblocking(false).unwrap();
                    return s;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("accept: {e}"),
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!("A ended ({status}) without connecting: {}", errors());
            }
            assert!(Instant::now() < deadline, "A didn't connect within 10 s: {}", errors());
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    let answer = |b: &TcpListener, child: &mut Child| {
        for _ in 0..5 {
            let mut s = accept(b, child);
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let cmd = command_until_closed(&mut s);
            let Some(call_id) = cmd.lines().find_map(|l| l.trim().strip_prefix("Call-ID: ")) else { continue };
            s.write_all(format!("Call-ID: {call_id}\r\nFrom: b\r\n\x1b").as_bytes()).unwrap();
            return (s, call_id.to_string());
        }
        panic!("A sent no command with a Call-ID");
    };
    let args = ["-sf", "a.xml", "-3pcc", &twin, "-m", "2", "-max_reconnect", "-1", "-reconnect_sleep", "50", "-reconnect_close", "false"];
    let mut child = sipp(&d, &[&args[..], &["-trace_err", "-error_file", "errors.log"]].concat());
    let (first, one) = answer(&b, &mut child);
    std::thread::sleep(Duration::from_millis(20));
    reset(first);
    drop(b);
    // The second call's command comes while A's reconnections are refused.
    std::thread::sleep(Duration::from_millis(500));
    let b = TcpListener::bind(&twin).unwrap();
    let (_again, two) = answer(&b, &mut child);
    // -timeout 5 ends A; a kill after 15 s fails the test instead of hanging.
    let deadline = Instant::now() + Duration::from_secs(15);
    while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    let errors = errors();
    std::fs::remove_dir_all(&d).unwrap();
    assert_eq!(out.status.code(), Some(0), "{errors}");
    assert_ne!(one, two);
    assert!(!errors.contains("Unable to send"), "{errors}");
}

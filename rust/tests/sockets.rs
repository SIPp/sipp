//! The 3PCC twin sockets count among the open sockets, as in SIPp's
//! pollnfds: controller B's listener, and the connection it accepted.
// It counts them from SIGUSR2's dump: Unix only.
#![cfg(unix)]

use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn open_sockets(screens: &str) -> Vec<u32> {
    screens.lines().filter_map(|l| l.trim().strip_suffix("UDP errors (send/recv/cong)")).map(|l| l.split_whitespace().next().unwrap().parse().unwrap()).collect()
}

#[test]
fn controller_b_counts_its_twin_sockets() {
    let dir = std::env::temp_dir().join(format!("sipp-rs-sockets-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let twin = format!("127.0.0.1:{}", free_port());
    let mut child = Command::new(env!("CARGO_BIN_EXE_sipp-rs"))
        .args(["-sn", "3pcc-C-B", "-3pcc", &twin, "-i", "127.0.0.1", "-p", "0", "-nostdin", "-trace_screen", "-screen_file", "screen.log", "127.0.0.1:9"])
        .current_dir(&dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let signal = |sig| {
        std::thread::sleep(Duration::from_millis(300));
        // SAFETY: a signal to our own child.
        unsafe { libc::kill(child.id() as libc::pid_t, sig) };
    };
    // The main and control sockets, and the twin listener.
    signal(libc::SIGUSR2);
    std::thread::sleep(Duration::from_millis(100));
    let a = (0..50).find_map(|_| TcpStream::connect(&twin).ok().or_else(|| { std::thread::sleep(Duration::from_millis(20)); None })).unwrap();
    // And the twin connection.
    signal(libc::SIGUSR2);
    signal(libc::SIGTERM);
    child.wait().unwrap();
    drop(a);
    let screens = std::fs::read_to_string(dir.join("screen.log")).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    // The two dumps, and the screens SIGTERM's exit writes.
    assert_eq!(open_sockets(&screens), vec![3, 4, 4], "{screens}");
}

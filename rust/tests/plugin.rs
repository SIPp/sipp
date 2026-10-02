//! -plugin with the example plugin: its keywords in a message sent to us.

use std::net::UdpSocket;
use std::process::Command;
use std::time::Duration;

const SCENARIO: &str = r#"<?xml version="1.0" encoding="ISO-8859-1" ?>
<scenario name="plugin">
  <send>
    <![CDATA[
      OPTIONS sip:[service]@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[call_number]
      To: <sip:[service]@[remote_ip]:[remote_port]>
      Call-ID: [call_id]
      CSeq: 1 OPTIONS
      X-Shout: [shout [service] #[call_number]]
      X-Sent: [sent] [sent]
      X-Bad: [shout [nope]]
      Content-Length: 0

    ]]>
  </send>
</scenario>
"#;

#[test]
fn example_plugin_keywords() {
    let root = env!("CARGO_MANIFEST_DIR");
    let ok = Command::new(env!("CARGO")).args(["build", "-q", "-p", "sipp-plugin-example"]).current_dir(root).status().unwrap();
    assert!(ok.success());
    let dir = std::env::temp_dir().join(format!("sipp-rs-plugin-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let xml = dir.join("plugin.xml");
    std::fs::write(&xml, SCENARIO).unwrap();

    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    // Next to sipp-rs: the build above is for its target (CARGO_BUILD_TARGET
    // too), into its directory.
    let bin_dir = std::path::Path::new(env!("CARGO_BIN_EXE_sipp-rs")).parent().unwrap();
    let so = format!("{}/{}sipp_plugin_example{}", bin_dir.display(), std::env::consts::DLL_PREFIX, std::env::consts::DLL_SUFFIX);
    let run = Command::new(env!("CARGO_BIN_EXE_sipp-rs"))
        .args(["-sf", xml.to_str().unwrap(), "-plugin", &so, "-m", "1", "-p", "0", "-nostdin", "-timeout", "5"])
        .arg(peer.local_addr().unwrap().to_string())
        .current_dir(&dir)
        .output()
        .unwrap();
    let mut buf = [0u8; 2048];
    let n = peer.recv(&mut buf).unwrap();
    let msg = String::from_utf8_lossy(&buf[..n]);
    assert!(msg.contains("\r\nX-Shout: SERVICE #1\r\n"), "{msg}");
    assert!(msg.contains("\r\nX-Sent: 1 2\r\n"), "{msg}");
    assert!(msg.contains("\r\nX-Bad: UNSUPPORTED KEYWORD 'NOPE' IN XML SCENARIO FILE\r\n"), "{msg}");
    assert!(run.status.success(), "{run:?}");

    // A keyword can only be registered once.
    let twice = Command::new(env!("CARGO_BIN_EXE_sipp-rs")).args(["-plugin", &so, "-plugin", &so, "127.0.0.1:9"]).current_dir(&dir).output().unwrap();
    assert_eq!(twice.status.code(), Some(255));
    assert!(String::from_utf8_lossy(&twice.stderr).contains("Can not register keyword 'shout', already registered!"));
    std::fs::remove_dir_all(&dir).unwrap();
}

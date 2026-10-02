//! -lua_file and <exec lua>: a function reads and writes the call's variables.
#![cfg(feature = "lua")]

use std::net::UdpSocket;
use std::process::{Command, Output};
use std::time::Duration;

const LUA: &str = r#"
function greet(name, n)
  sipp.set("greeting", "hello " .. name .. " " .. (tonumber(n) + 1))
  sipp.set("count", tonumber(n) * 2)
  sipp.set("flag", sipp.get("input") == "20")
  sipp.log("input was " .. sipp.get("input"))
end

function broken()
  sipp.set("nosuchvar", "x")
end

function wrong()
  sipp.set("input", {})
end
"#;

/// The scenario, calling `call` first. Its variables are each used once
/// but `input`, which <assignstr> sets.
fn scenario(call: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="ISO-8859-1" ?>
<scenario name="lua">
  <nop>
    <action>
      <assignstr assign_to="input" value="20"/>
      <exec lua="{call}"/>
    </action>
  </nop>
  <send>
    <![CDATA[
      OPTIONS sip:[service]@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[call_number]
      To: <sip:[service]@[remote_ip]:[remote_port]>
      Call-ID: [call_id]
      CSeq: 1 OPTIONS
      X-Greeting: [$greeting]
      X-Count: [$count]
      X-Flag: [$flag]
      X-Input: [$input]
      Content-Length: 0

    ]]>
  </send>
</scenario>
"#
    )
}

fn run(dir: &std::path::Path, call: &str, lua: Option<&str>, peer: &UdpSocket) -> Output {
    let xml = dir.join("lua.xml");
    std::fs::write(&xml, scenario(call)).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sipp-rs"));
    cmd.args(["-sf", xml.to_str().unwrap(), "-m", "1", "-p", "0", "-nostdin", "-timeout", "5", "-trace_logs", "-log_file", "lua.log"]);
    if let Some(file) = lua {
        cmd.args(["-lua_file", file]);
    }
    cmd.arg(peer.local_addr().unwrap().to_string()).current_dir(dir).output().unwrap()
}

#[test]
fn functions_read_and_write_variables() {
    let dir = std::env::temp_dir().join(format!("sipp-rs-lua-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("script.lua"), LUA).unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(10))).unwrap();

    let out = run(&dir, "greet world [$input]", Some("script.lua"), &peer);
    let mut buf = [0u8; 2048];
    let n = peer.recv(&mut buf).unwrap();
    let msg = String::from_utf8_lossy(&buf[..n]);
    assert!(msg.contains("\r\nX-Greeting: hello world 21\r\n"), "{msg}");
    assert!(msg.contains("\r\nX-Count: 40.000000\r\n"), "{msg}");
    assert!(msg.contains("\r\nX-Flag: true\r\n"), "{msg}");
    assert!(out.status.success(), "{out:?}");
    let log = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).find(|p| p.to_string_lossy().contains("lua") && p.extension().is_some_and(|e| e == "log"));
    assert!(std::fs::read_to_string(log.unwrap()).unwrap().contains("input was 20"));

    // The errors end SIPp, with Lua's messages.
    for (call, file, said) in [
        ("broken", Some("script.lua"), "Lua function broken: script.lua:10: unknown SIPp variable 'nosuchvar'"),
        ("wrong", Some("script.lua"), "SIPp variables hold a string, a number or a boolean"),
        ("missing", Some("script.lua"), "Lua function missing is not defined"),
        ("greet", None, "needs a function name, and a Lua file with it given with -lua_file"),
        // The system's words for it follow.
        ("greet", Some("nofile.lua"), "Lua file nofile.lua: cannot open nofile.lua: "),
    ] {
        let out = run(&dir, call, file, &peer);
        let text = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(255), "{call}: {out:?}");
        assert!(text.contains(said), "{call}: {text}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

//! What SIPp prints as it starts: open_connections()'s resolving line.

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sipp-rs")).args(args).output().unwrap()
}

#[test]
fn the_remote_host_is_resolved_in_sipps_words() {
    let out = run(&["-sn", "uac", "nosuchhost.invalid", "-m", "1", "-nostdin"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(255));
    assert!(stderr.starts_with("Resolving remote host 'nosuchhost.invalid'... "), "{stderr}");
    assert!(stderr.contains(": Unknown remote host 'nosuchhost.invalid'.\nUse 'sipp -h' for details\n"), "{stderr}");
    // open_connections() fails with the screens up.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("------------------------------ Scenario Screen"), "{stdout}");
    assert!(stdout.contains("Test Terminated"), "{stdout}");
    assert!(stderr.ends_with("There were more errors, enable -trace_err to log them.\n"), "{stderr}");

    let out = run(&["-sn", "uac", "127.0.0.1:9", "-m", "1", "-p", "0", "-nostdin", "-nr", "-recv_timeout", "100"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.starts_with("Resolving remote host '127.0.0.1'... Done.\n"), "{stderr}");
    // Nothing of sipp-rs's own before the screens.
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("------------------------------ Scenario Screen"));

    let out = run(&["-sn", "uac", "-nostdin"]);
    assert!(String::from_utf8_lossy(&out.stderr).ends_with(": Missing remote host parameter. This scenario requires it\n"));
}

#[test]
fn a_local_ip_of_another_family_is_fatal() {
    let out = run(&["-sn", "uac", "-i", "127.0.0.1", "[::1]:9", "-m", "1", "-p", "5099", "-nostdin"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(255));
    assert!(stderr.starts_with("Resolving remote host '::1'... Done.\n"), "{stderr}");
    assert!(stderr.contains(": Network family mismatch for local (127.0.0.1) and remote (::1, "), "{stderr}");
    // SIPp's local_port, 0 before the main socket, which is not open.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("/1.000s   0          0.00 s") && stdout.contains("  0 open sockets "), "{stdout}");
    // An IPv4-mapped address is also an IPv4 one.
    let out = run(&["-sn", "uac", "-i", "::ffff:127.0.0.1", "127.0.0.1:9", "-m", "1", "-p", "0", "-nostdin", "-nr", "-recv_timeout", "100"]);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("family mismatch"));
}

#[test]
fn every_init_runs_and_takes_no_call_number() {
    // C 8c0f555 and 8c422d2: the -sf, -oocsf and -rxsf <init>s all run,
    // as call 0, and the first call is still number 1.
    let dir = std::env::temp_dir().join(format!("sipp-rs-init-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let init = |what: &str| format!(r#"<init><nop><action><log message="{what} init [call_number]"/></action></nop></init>"#);
    let uac = format!(
        r#"<scenario>{}<send><![CDATA[
          OPTIONS sip:[service]@[remote_ip]:[remote_port] SIP/2.0
          Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
          Call-ID: [call_id]
          CSeq: 1 OPTIONS
          Content-Length: 0
        ]]><action><log message="call [call_number] [call_id]"/></action></send></scenario>"#,
        init("main")
    );
    let other = |what: &str| format!(r#"<scenario>{}<recv request="OPTIONS"/></scenario>"#, init(what));
    for (name, xml) in [("uac.xml", uac), ("ooc.xml", other("ooc")), ("rx.xml", other("rx"))] {
        std::fs::write(dir.join(name), xml).unwrap();
    }
    let path = |name: &str| dir.join(name).to_str().unwrap().to_string();
    let log = path("logs.log");
    let out = run(&[
        "-sf", &path("uac.xml"), "-oocsf", &path("ooc.xml"), "-rxsf", &path("rx.xml"),
        "127.0.0.1:9", "-i", "127.0.0.1", "-p", "0", "-m", "1", "-nostdin", "-trace_logs", "-log_file", &log,
    ]);
    let logs = std::fs::read_to_string(&log).unwrap_or_default();
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    for line in ["main init 0", "ooc init 0", "rx init 0"] {
        assert!(logs.lines().any(|l| l.ends_with(line)), "{line}: {logs}");
    }
    assert!(logs.contains("call 1 1-"), "{logs}");
}

#[test]
fn option_errors_come_in_sipps_passes() {
    // -rfc3339 is read before any error, wherever it is.
    for args in [["-bogus", "-rfc3339"], ["-rfc3339", "-bogus"]] {
        let out = run(&[args[0], args[1], "127.0.0.1", "-nostdin"]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("T") && stderr.contains(": Invalid argument: '-bogus'."), "{stderr}");
        assert!(!stderr.contains('\t'), "{stderr}");
    }
    // A scenario file is read in pass 2, after the other options.
    let out = run(&["-sf", "nosuch.xml", "-m", "xx", "127.0.0.1", "-nostdin"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(": -m, \"xx\" is not a valid integer!"), "{stderr}");
    let out = run(&["-sf", "nosuch.xml", "-oocsn", "nosuch", "127.0.0.1", "-nostdin"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Unable to load or parse 'nosuch.xml' xml scenario file"), "{stderr}");
}

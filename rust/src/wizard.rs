//! SIPp's startup wizard: a bare launch at a terminal asks for a
//! scenario, its transport, peer and limits, and runs the command line
//! they make.

use std::io::{BufRead, Write};

struct Choice {
    name: &'static str,
    description: &'static str,
    needs_remote_host: bool,
    scenario_file: bool,
}

const SCENARIOS: &[Choice] = &[
    Choice { name: "uac", description: "Embedded UAC client scenario.", needs_remote_host: true, scenario_file: false },
    Choice { name: "uas", description: "Embedded UAS server scenario.", needs_remote_host: false, scenario_file: false },
    Choice { name: "regexp", description: "Embedded UAC scenario with regexp and variables.", needs_remote_host: true, scenario_file: false },
    Choice { name: "branchc", description: "Embedded client branching scenario.", needs_remote_host: true, scenario_file: false },
    Choice { name: "branchs", description: "Embedded server branching scenario.", needs_remote_host: false, scenario_file: false },
    Choice { name: "uac_pcap", description: "Embedded UAC scenario with PCAP media playback.", needs_remote_host: true, scenario_file: false },
    Choice { name: "custom", description: "Custom XML scenario file.", needs_remote_host: false, scenario_file: true },
];

/// The -t names and codes offered: SCTP where this build has it.
const TRANSPORTS: &[(&str, char)] = if cfg!(windows) {
    &[("udp", 'u'), ("tcp", 't'), ("tls", 'l')]
} else {
    &[("udp", 'u'), ("tcp", 't'), ("tls", 'l'), ("sctp", 's')]
};

/// Whether stdin and stdout are a terminal, for a bare launch.
pub fn wanted() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// The wizard on stdin and stdout: the command line, `program` first, or
/// None when cancelled.
pub fn run(program: &str) -> Option<Vec<String>> {
    Wizard { input: std::io::stdin().lock(), out: std::io::stdout() }.run(program)
}

struct Wizard<I, O> {
    input: I,
    out: O,
}

fn trim(s: &str) -> &str {
    s.trim_matches([' ', '\t', '\r', '\n'])
}

fn yes(s: &str) -> bool {
    matches!(s.to_ascii_lowercase().as_str(), "y" | "yes")
}

fn no(s: &str) -> bool {
    matches!(s.to_ascii_lowercase().as_str(), "n" | "no")
}

/// The -t value for a transport name or a -t value itself ("un", "ui"):
/// a socket per IP is for UDP only, as -t has it.
fn transport(answer: &str) -> Option<String> {
    let lowered = trim(answer).to_ascii_lowercase();
    TRANSPORTS.iter().find_map(|&(name, code)| {
        if lowered == name {
            return Some(format!("{code}1"));
        }
        let mut c = lowered.chars();
        match (c.next(), c.next(), c.next()) {
            (Some(first), Some(mode @ ('1' | 'n' | 'i')), None) if first == code && (mode != 'i' || code == 'u') => Some(lowered.clone()),
            _ => None,
        }
    })
}

/// An argument as a shell reads it: single-quoted unless plain.
fn quote(arg: &str) -> String {
    let plain = |b: u8| b.is_ascii_alphanumeric() || b"-_./:@%+=".contains(&b);
    if !arg.is_empty() && arg.bytes().all(plain) {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

impl<I: BufRead, O: Write> Wizard<I, O> {
    fn say(&mut self, text: &str) {
        let _ = self.out.write_all(text.as_bytes());
        let _ = self.out.flush();
    }

    /// An answer, trimmed, or `default` for an empty one; None on 'q',
    /// "quit", "exit" or the end of input.
    fn ask(&mut self, prompt: &str, default: Option<&str>) -> Option<String> {
        self.say(prompt);
        let mut line = String::new();
        if !matches!(self.input.read_line(&mut line), Ok(n) if n > 0) {
            self.say("\n");
            return None;
        }
        let answer = trim(&line);
        if matches!(answer.to_ascii_lowercase().as_str(), "q" | "quit" | "exit") {
            return None;
        }
        Some(match default {
            Some(d) if answer.is_empty() => d.to_string(),
            _ => answer.to_string(),
        })
    }

    fn run(&mut self, program: &str) -> Option<Vec<String>> {
        self.say("\nSIPp startup wizard\nPress Enter to accept defaults. Type 'q' to quit.\n\n");
        let scenario = loop {
            let mut list = String::from("Scenario:\n");
            for (i, s) in SCENARIOS.iter().enumerate() {
                list += &format!("  {}) {} - {}\n", i + 1, s.name, s.description);
            }
            self.say(&(list + "\n"));
            let lowered = self.ask("Choose a scenario [1]: ", Some("1"))?.to_ascii_lowercase();
            let number = if lowered.bytes().all(|b| b.is_ascii_digit()) { lowered.parse::<usize>().unwrap_or(0) } else { 0 };
            if let Some(s) = number.checked_sub(1).and_then(|i| SCENARIOS.get(i)).or_else(|| SCENARIOS.iter().find(|s| s.name == lowered)) {
                break s;
            }
            self.say("Unknown scenario choice. Please select one of the listed items.\n\n");
        };

        // A scenario file can be a client's or a server's.
        let (mut scenario_path, mut custom_client) = (String::new(), false);
        if scenario.scenario_file {
            loop {
                scenario_path = self.ask("Path to XML scenario file: ", None)?;
                if scenario_path.is_empty() {
                    self.say("A scenario path is required.\n");
                } else if std::fs::File::open(&scenario_path).is_err() {
                    self.say(&format!("Unable to read '{scenario_path}'. Try another path.\n"));
                } else {
                    break;
                }
            }
            custom_client = loop {
                let answer = self.ask("Does this scenario send calls to a remote host? [y/N]: ", Some("n"))?;
                if yes(&answer) {
                    break true;
                }
                if no(&answer) {
                    break false;
                }
                self.say("Please answer y or n.\n");
            };
        }
        let client = scenario.needs_remote_host || custom_client;

        let remote = if client { self.ask("Remote host[:port] [127.0.0.1]: ", Some("127.0.0.1"))? } else { String::new() };
        let names: Vec<&str> = TRANSPORTS.iter().map(|t| t.0).collect();
        let t = loop {
            if let Some(t) = transport(&self.ask(&format!("Transport [{}] (default udp): ", names.join("/")), Some("udp"))?) {
                break t;
            }
            self.say(if cfg!(windows) { "Unknown transport. Use udp, tcp, tls.\n" } else { "Unknown transport. Use udp, tcp, tls, or sctp.\n" });
        };
        // -s is the built-in client scenarios' request URI user.
        let service = if scenario.needs_remote_host { self.ask("Request URI user (-s) [service]: ", Some("service"))? } else { String::new() };
        let (mut rate, mut max_calls, mut limit) = (String::new(), String::new(), String::new());
        if client {
            rate = self.ask("Call rate (-r) [10]: ", Some("10"))?;
            max_calls = self.ask("Max calls (-m, blank for unlimited): ", None)?;
            limit = self.ask("Max simultaneous calls (-l, optional): ", None)?;
        }
        let extra = self.ask("Extra SIPp options (optional, space-separated, no quoting): ", None)?;

        let mut args = vec![program.to_string()];
        if !remote.is_empty() {
            args.push(remote);
        }
        if scenario.scenario_file {
            args.extend(["-sf".to_string(), scenario_path]);
        } else {
            args.extend(["-sn".to_string(), scenario.name.to_string()]);
        }
        args.extend(["-t".to_string(), t]);
        for (option, value) in [("-s", service), ("-r", rate), ("-m", max_calls), ("-l", limit)] {
            if !value.is_empty() {
                args.extend([option.to_string(), value]);
            }
        }
        args.extend(extra.split_whitespace().map(str::to_string));

        let command: Vec<String> = args.iter().map(|a| quote(a)).collect();
        self.say(&format!("\nCommand:\n  {}\n\n", command.join(" ")));
        let answer = self.ask("Run this command now? [Y/n]: ", Some("y"))?;
        if !yes(&answer) {
            self.say("Wizard cancelled.\n");
            return None;
        }
        Some(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wizard(input: &str) -> (Option<Vec<String>>, String) {
        let mut w = Wizard { input: input.as_bytes(), out: Vec::new() };
        let args = w.run("sipp");
        (args, String::from_utf8(w.out).unwrap())
    }

    #[test]
    fn defaults_make_a_uac() {
        let (args, out) = wizard("\n\n\n\n\n\n\n\n\n");
        assert_eq!(args.unwrap(), ["sipp", "127.0.0.1", "-sn", "uac", "-t", "u1", "-s", "service", "-r", "10"]);
        assert!(out.contains("\nCommand:\n  sipp 127.0.0.1 -sn uac -t u1 -s service -r 10\n\n"));
    }

    #[test]
    fn a_server_asks_no_peer() {
        let (args, out) = wizard("UAS\n tcp \n-p 5070  -trace_err\n\n");
        assert_eq!(args.unwrap(), ["sipp", "-sn", "uas", "-t", "t1", "-p", "5070", "-trace_err"]);
        assert!(!out.contains("Remote host"));
    }

    #[test]
    fn retries_and_cancels() {
        let (args, out) = wizard("9\n1\n10.0.0.1:5061\nti\nun\nbob\n5\n\n\nx y\nn\n");
        assert_eq!(args, None);
        assert!(out.contains("Unknown scenario choice. Please select one of the listed items.\n\n"));
        assert!(out.contains("Unknown transport. Use udp, tcp, tls"));
        assert!(out.contains("  sipp 10.0.0.1:5061 -sn uac -t un -s bob -r 5 x y\n"));
        assert!(out.ends_with("Wizard cancelled.\n"));
        assert_eq!(wizard("2\nQuit\n").0, None);
        let (args, out) = wizard("custom\n");
        assert_eq!(args, None);
        assert!(out.ends_with("Path to XML scenario file: \n"));
    }

    #[test]
    fn a_scenario_file() {
        let (args, out) = wizard("7\n\n/nonexistent.xml\nCargo.toml\nmaybe\ny\n\n\n\n100\n\n\n\n");
        assert_eq!(args.unwrap(), ["sipp", "127.0.0.1", "-sf", "Cargo.toml", "-t", "u1", "-r", "10", "-m", "100"]);
        assert!(out.contains("A scenario path is required.\n"));
        assert!(out.contains("Unable to read '/nonexistent.xml'. Try another path.\n"));
        assert!(out.contains("Please answer y or n.\n"));
        assert!(!out.contains("Request URI user"));
    }

    #[test]
    fn quotes_as_a_shell_reads() {
        assert_eq!(quote("-key"), "-key");
        assert_eq!(quote(""), "''");
        assert_eq!(quote("it's"), "'it'\\''s'");
        assert_eq!(quote("a b"), "'a b'");
    }
}

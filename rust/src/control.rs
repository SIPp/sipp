//! SIPp's run-time controls: the keys and the "c" commands, from the
//! terminal or the UDP control socket (-cp, else the first free of
//! 8888-8947).

use std::net::{IpAddr, SocketAddr, UdpSocket};

/// What a key or command asks the engine for.
#[derive(Debug, PartialEq)]
pub enum Request {
    /// 1-9: the screen to show.
    Screen(u8),
    /// +, -, * and /: the rate (or users) by this many, times -rate_scale.
    Rate(f64),
    PauseTraffic,
    DumpScreens,
    /// q: no new calls; again, as Q, abort them.
    Quit,
    QuitNow,
    SetRate(f64),
    SetRateScale(f64),
    SetUsers(u32),
    SetLimit(usize),
    SetHide(bool),
    Trace(String, bool),
    /// set display main: the only scenario there is.
    Nothing,
    DumpTasks,
    DumpVariables,
    ResetStats,
}

/// process_key().
pub fn key(c: u8) -> Option<Request> {
    Some(match c {
        b'1'..=b'9' => Request::Screen(c - b'0'),
        b'+' => Request::Rate(1.0),
        b'-' => Request::Rate(-1.0),
        b'*' => Request::Rate(10.0),
        b'/' => Request::Rate(-10.0),
        b'p' => Request::PauseTraffic,
        b's' => Request::DumpScreens,
        b'q' => Request::Quit,
        b'Q' => Request::QuitNow,
        _ => return None,
    })
}

/// process_command(): the request, or the warning SIPp gives instead.
pub fn command(line: &str) -> Result<Request, String> {
    let line = line.trim();
    let Some((cmd, rest)) = line.split_once(' ').map(|(c, r)| (c, r.trim())) else {
        return Err(format!("The {line} command requires at least one argument"));
    };
    match cmd {
        "set" => {
            let Some((what, value)) = rest.split_once(' ').map(|(w, v)| (w, v.trim())) else {
                return Err("The set command requires two arguments (attribute and value)".into());
            };
            let bad = |kind: &str| format!("Invalid {kind} value: \"{value}\"");
            match what {
                "rate" => value.parse().map(Request::SetRate).map_err(|_| bad("rate")),
                "rate-scale" => value.parse().map(Request::SetRateScale).map_err(|_| bad("rate-scale")),
                "users" => value.parse().map(Request::SetUsers).map_err(|_| bad("users")),
                "limit" => value.parse().map(Request::SetLimit).map_err(|_| bad("limit")),
                "hide" => match value {
                    "true" => Ok(Request::SetHide(true)),
                    "false" => Ok(Request::SetHide(false)),
                    _ => Err(format!("Invalid bool: {value}")),
                },
                "display" if value == "main" => Ok(Request::Nothing),
                "display" => Err(format!("Unknown display scenario: {value}")),
                _ => Err(format!("Unknown set attribute: {what}")),
            }
        }
        "trace" => {
            let Some((log, onoff)) = rest.split_once(' ').map(|(l, o)| (l, o.trim())) else {
                return Err("The trace command requires two arguments (log and [on|off])".into());
            };
            let on = match onoff {
                "on" | "true" => true,
                "off" | "false" => false,
                _ => return Err("The trace command's second argument must be on or off.".into()),
            };
            match log {
                "error" | "logs" | "messages" | "shortmessages" => Ok(Request::Trace(log.to_string(), on)),
                _ => Err(format!("Unknown log file: {log}")),
            }
        }
        "dump" => match rest {
            "tasks" => Ok(Request::DumpTasks),
            "variables" => Ok(Request::DumpVariables),
            _ => Err(format!("Unknown dump type: {rest}")),
        },
        "reset" => match rest {
            "stats" => Ok(Request::ResetStats),
            _ => Err(format!("Unknown reset type: {rest}")),
        },
        _ => Err(format!("Unrecognized command: \"{cmd}\"")),
    }
}

/// setup_ctrl_socket(): -cp's port, or the first of 60 from 8888. Without
/// -cp, finding none is only a warning, as in SIPp.
pub fn socket(ip: Option<IpAddr>, port: Option<u16>) -> Result<UdpSocket, (Option<u16>, std::io::Error)> {
    let ip = ip.unwrap_or(IpAddr::from([0, 0, 0, 0]));
    let (first, last) = port.map_or((8888, 8947), |p| (p, p));
    let mut error = std::io::Error::other("no port");
    for p in first..=last {
        match UdpSocket::bind(SocketAddr::new(ip, p)) {
            Ok(s) => {
                let _ = s.set_nonblocking(true);
                return Ok(s);
            }
            Err(e) => error = e,
        }
    }
    Err((port, error))
}

/// A datagram on the control socket: a key, or "c" and a command.
pub enum Input {
    Key(u8),
    Command(String),
}

pub fn datagram(buf: &[u8]) -> Option<Input> {
    match buf.first()? {
        b'c' => Some(Input::Command(crate::raw::text(&buf[1..]).into_owned())),
        &k => Some(Input::Key(k)),
    }
}

/// The terminal in SIPp's cbreak mode, non-blocking, restored on drop.
pub struct Keyboard {
    term: crate::sys::Terminal,
    /// A "c" command being typed.
    command: Option<String>,
}

impl Keyboard {
    /// SIPp's setup_stdin_socket(): stdin non-blocking, a terminal also
    /// without line buffering or echo.
    pub fn open() -> Option<Keyboard> {
        Some(Keyboard { term: crate::sys::Terminal::open()?, command: None })
    }

    /// What was typed since the last call.
    pub fn read(&mut self) -> Vec<Input> {
        let mut buf = [0u8; 64];
        let mut out = Vec::new();
        let n = self.term.read(&mut buf);
        for &c in &buf[..n] {
            match self.command.as_mut() {
                Some(cmd) if c == b'\n' || c == b'\r' => {
                    out.push(Input::Command(std::mem::take(cmd)));
                    self.command = None;
                }
                // Backspace or delete.
                Some(cmd) if c == 0x7f || c == 0x08 => {
                    cmd.pop();
                }
                Some(cmd) => cmd.push(c as char),
                None if c == b'c' => self.command = Some(String::new()),
                None => out.push(Input::Key(c)),
            }
        }
        out
    }

    /// The command being typed, for the screen's "Command:" line.
    pub fn typing(&self) -> Option<&str> {
        self.command.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_commands_as_sipp() {
        assert_eq!(key(b'*'), Some(Request::Rate(10.0)));
        assert_eq!(key(b'3'), Some(Request::Screen(3)));
        assert_eq!(key(b'x'), None);
        assert_eq!(command("set rate 42.5"), Ok(Request::SetRate(42.5)));
        assert_eq!(command(" trace messages on "), Ok(Request::Trace("messages".into(), true)));
        assert_eq!(command("reset stats"), Ok(Request::ResetStats));
        assert_eq!(command("set rate x"), Err("Invalid rate value: \"x\"".into()));
        assert_eq!(command("dump"), Err("The dump command requires at least one argument".into()));
    }
}

//! SIPp's screens, as it prints them when a run ends and in -trace_screen:
//! the scenario with its per-message counts, the statistics, and the
//! repartitions.

use crate::pcap::PcapMedia;
use crate::scenario::{Action, Arith, Compare, Expect, Num, Op, Operand, PauseLen, Scenario, Source, Stop, StrOp, StreamSource};
use crate::stat::Stats;
use std::time::Duration;

/// What the scenario screen shows besides the statistics.
pub struct Info<'a> {
    pub server: bool,
    pub users: Option<u32>,
    pub rate: f64,
    pub rate_period: Duration,
    /// -d.
    pub duration: Duration,
    pub local_port: u16,
    pub elapsed: Duration,
    pub remote: String,
    pub transport: &'a str,
    pub max_calls: Option<u64>,
    pub limit: usize,
    /// Calls in the run now, and how many of them are in a <pause>.
    pub running: usize,
    pub paused: usize,
    /// SIPp's last_woken_calls.
    pub woken: u64,
    pub auto_answer: bool,
    pub open_sockets: usize,
    /// The connections' failed writes and reads.
    pub net_errors: (u64, u64),
    /// SIPp's rtp_stream threads, and whether -rtp_echo is on.
    pub rtp_threads: u64,
    pub rtp_echo: bool,
    /// -lost or a lost= attribute: the Lost column.
    pub lose_packets: bool,
    /// Engine loops in the screen's period.
    pub loops: u64,
    /// What the footer says the run is doing.
    pub state: State,
    /// The last warning or error, for the "Last Error" line.
    pub last_error: Option<&'a str>,
    /// A 3PCC role's footer, for a run with no other to show.
    pub third_party: Option<&'static str>,
}

/// SIPp's quitting and paused flags, as the footer shows them.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum State {
    #[default]
    Running,
    Paused,
    /// quitting 1-10: a soft exit, waiting for the calls to end.
    Waiting,
    /// quitting 11 and up: a forced exit.
    Forcing,
}

/// get_lines() for the scenario screen, footer included.
pub fn scenario(sc: &Scenario, st: &Stats, i: &Info, last: bool) -> Vec<String> {
    let mut l = vec!["------------------------------ Scenario Screen -------- [1-9]: Change Screen --".to_string()];
    let total = st.total_created();
    let secs = i.elapsed.as_millis() as u64;
    if i.server {
        l.push("  Port   Total-time  Total-calls  Transport".into());
        l.push(format!("  {:<5} {:>6}.{:02} s     {:>8}  {}", i.local_port, secs / 1000, secs % 1000 / 10, total, i.transport));
    } else if let Some(u) = i.users {
        l.push("  Users (length)   Port   Total-time  Total-calls  Remote-host".into());
        l.push(format!(
            "  {u} ({} ms)   {:<5} {:>6}.{:02} s     {:>8}  {:.20}({})",
            i.duration.as_millis(),
            i.local_port,
            secs / 1000,
            secs % 1000 / 10,
            total,
            i.remote,
            i.transport
        ));
    } else {
        l.push("  Call rate (length)   Port   Total-time  Total-calls  Remote-host".into());
        l.push(format!(
            "  {:3.1}({} ms)/{:5.3}s   {:<5} {:>6}.{:02} s     {:>8}  {:.20}({})",
            i.rate,
            i.duration.as_millis(),
            i.rate_period.as_secs_f64(),
            i.local_port,
            secs / 1000,
            secs % 1000 / 10,
            total,
            i.remote,
            i.transport
        ));
    }
    l.push(String::new());
    let (period_calls, period_ms) = st.display_period();
    let left = match i.max_calls {
        Some(m) if total >= m => format!("Call limit {m} hit, {:.1} s period ", period_ms as f64 / 1000.0),
        _ => format!("{period_calls} new calls during {}.{:03} s period", period_ms / 1000, period_ms % 1000),
    };
    let right = format!("{} ms scheduler resolution", period_ms / i.loops.max(1));
    l.push(format!("  {:<38.38}  {:<37.37}", left, right));
    let calls = if i.server { format!("{} calls", st.current) } else { format!("{} calls (limit {})", st.current, i.limit) };
    l.push(format!("  {:<38}  Peak was {} calls, after {} s", calls, st.peak.0, st.peak.1));
    l.push(format!("  {} Running, {} Paused, {} Woken up", i.running, i.paused, i.woken));
    let dead = format!("{} dead call msg (discarded)", st.dead_calls());
    if i.server {
        l.push(format!("  {:<38}", dead));
    } else {
        l.push(format!("  {:<38}  {} out-of-call msg (discarded)", dead, st.out_of_calls()));
    }
    if i.auto_answer {
        l.push(format!("  {} requests auto-answered", st.auto_answers()));
    }
    l.push(format!("  {:<38}  {}/{}/{} {} errors (send/recv/cong)", format!("{} open sockets", i.open_sockets), i.net_errors.0, i.net_errors.1, 0, i.transport));
    l.extend(crate::media::counters::screen_lines(i.rtp_threads, i.rtp_echo));
    l.push(String::new());
    l.push(if i.lose_packets {
        "                                 Messages  Retrans   Timeout   Unexp.    Lost".into()
    } else {
        "                                 Messages  Retrans   Timeout   Unexpected-Msg".into()
    });
    for (index, step) in sc.steps.iter().enumerate() {
        if step.hide {
            continue;
        }
        let c = &st.steps[index];
        let lost = if i.lose_packets && c.lost > 0 { c.lost.to_string() } else { String::new() };
        let rtd = match (step.start_rtd.first(), step.stop_rtd.first()) {
            (Some(r), _) => format!(" B-RTD{} ", r + 1),
            (None, Some(r)) => format!(" E-RTD{} ", r + 1),
            _ => "        ".into(),
        };
        let row = match &step.op {
            Op::Send { msg, retrans_ms, .. } => {
                let what = match msg.response_code() {
                    Some(code) => code.to_string(),
                    None => msg.method().unwrap_or("").to_string(),
                };
                let arrow = if i.server { format!("  <---------- {:<10} ", what) } else { format!("  {:>10} ----------> ", what) };
                let counts = match retrans_ms {
                    Some(_) => format!("{:<9} {:<9} {:<9} {:<9} {:<9}", c.sent, c.sent_retrans, c.timeouts, "", lost),
                    None => format!("{:<9} {:<9} {:<9} {:<9} {:<9}", c.sent, c.sent_retrans, "", "", lost),
                };
                truncate(format!("{arrow}{rtd}{counts}"), 99)
            }
            // Warned about by the caller, as SIPp as it draws it.
            Op::Recv { expect: Expect::Nothing, .. } => "            [ recv? ]              ".into(),
            Op::Recv { expect, shown, .. } => {
                let what = shown.clone().unwrap_or_else(|| match expect {
                    Expect::Response(code) => code.to_string(),
                    Expect::ResponseRe(re) | Expect::RequestRe(re) => re.as_str().to_string(),
                    Expect::Request(m) => m.clone(),
                    Expect::Nothing => unreachable!(),
                });
                let arrow = if i.server { format!("  ----------> {:<10} ", what) } else { format!("  {:>10} <---------- ", what) };
                let counts = format!("{:<9} {:<9} {:<9} {:<9} {:<9}", c.recv, c.recv_retrans, c.timeouts, c.unexpected, lost);
                truncate(format!("{arrow}{rtd}{counts}"), 99)
            }
            Op::Pause(len) | Op::Timewait(len) => {
                let desc = match len {
                    PauseLen::Dist(d) => d.describe(),
                    PauseLen::Var(v) => format!("${v}"),
                    PauseLen::Default => crate::dist::time_string(i.duration.as_millis() as f64),
                };
                let desc: String = desc.chars().take(23).collect();
                let len = desc.len().max(9);
                let left = if i.server {
                    format!("  [{:>9}] Pause{}", desc, " ".repeat(23usize.saturating_sub(len)))
                } else {
                    format!("       Pause [{:>9}]{}", desc, " ".repeat(18usize.saturating_sub(len)))
                };
                format!("{}{:<9}                     {:<9}", truncate(left, 39), c.sessions, c.unexpected)
            }
            Op::Nop => match &step.display {
                Some(d) => format!(" {d}"),
                None => "              [ NOP ]              ".into(),
            },
            Op::RecvCmd { .. } => format!("    [ Received Command ]         {:<9} {:<9} {:<9} {:<9}", c.cmds, "", "", ""),
            Op::SendCmd { .. } => format!("        [ Sent Command ]         {:<9} {:<9}           {:<9}", c.cmds, "", ""),
        };
        l.push(truncate(format!("{index:<2}:{row}"), 120));
        if step.crlf {
            l.push(String::new());
        }
    }
    l.extend(tail(i, last));
    l
}

/// The lines under every screen, as get_lines(): the last error unless
/// the run ended, then the footer.
fn tail(i: &Info, last: bool) -> Vec<String> {
    let mut l = Vec::new();
    if let Some(e) = i.last_error.filter(|_| !last) {
        // Past the time, which ends with the first ": " (an -rfc3339
        // offset has a colon of its own).
        let text = e.split_once(": ").map_or(e, |(_, t)| t).trim_start();
        let text: String = text.chars().take(60).collect();
        l.push(format!("Last Error: {text}..."));
    }
    l.push(footer(i, last));
    l
}

fn footer(i: &Info, last: bool) -> String {
    if last {
        "------------------------------ Test Terminated --------------------------------".into()
    } else if i.state == State::Waiting {
        "------- Waiting for active calls to end. Press [q] again to force exit. -------".into()
    } else if i.state == State::Forcing {
        "-------------------------------- Forcing quit ---------------------------------".into()
    } else if i.state == State::Paused {
        "----------------- Traffic Paused - Press [p] again to resume ------------------".into()
    } else if let Some(f) = i.third_party {
        f.into()
    } else if i.server {
        "------------------------------ SIPp Server Mode -------------------------------".into()
    } else {
        "------ [+|-|*|/]: Adjust rate ---- [q]: Soft exit ---- [p]: Pause traffic -----".into()
    }
}

/// The statistics screen, with its header and footer.
pub fn statistics(st: &Stats, i: &Info, last: bool) -> Vec<String> {
    let mut l = vec!["----------------------------- Statistics Screen ------- [1-9]: Change Screen --".to_string()];
    l.extend(st.stats_screen());
    l.extend(tail(i, last));
    l
}

/// Screen `n` of the keys 1-9: scenario, statistics, repartition,
/// variables, TDM map, then the other response times' repartitions.
pub fn by_number(n: u8, sc: &Scenario, st: &Stats, map: &crate::tdm::TdmMap, i: &Info, last: bool) -> Vec<String> {
    match n {
        2 => statistics(st, i, last),
        3 => {
            let mut l = vec!["---------------------------- Repartition Screen ------- [1-9]: Change Screen --".to_string()];
            l.extend(st.repartition_screen(1));
            l.extend(tail(i, last));
            l
        }
        4 => variables(sc, i, last),
        5 => tdm(sc, map, i, last),
        6..=9 => {
            let which = (n - 6 + 2) as usize;
            let mut l = vec![format!("--------------------------- Repartition {which} Screen ------ [1-9]: Change Screen --")];
            l.extend(st.repartition_screen(which));
            l.extend(tail(i, last));
            l
        }
        _ => scenario(sc, st, i, last),
    }
}

/// Whether by_number() draws the scenario screen.
pub fn is_scenario(n: u8) -> bool {
    !(2..=9).contains(&n)
}

/// print_closing_stats(): the screen shown, then the statistics.
pub fn closing(n: u8, sc: &Scenario, st: &Stats, map: &crate::tdm::TdmMap, i: &Info) -> Vec<String> {
    let mut l = by_number(n, sc, st, map, i, true);
    if n != 2 {
        l.extend(statistics(st, i, true));
    }
    l
}

/// print_screens(), for -trace_screen: every screen, the run still on.
pub fn all(sc: &Scenario, st: &Stats, i: &Info) -> Vec<String> {
    let mut l = scenario(sc, st, i, false);
    l.extend(statistics(st, i, false));
    l.push("---------------------------- Repartition Screen ------- [1-9]: Change Screen --".into());
    l.extend(st.repartition_screen(1));
    l.extend(tail(i, false));
    for which in 2..=st.rtd_names().len() {
        l.push(format!("--------------------------- Repartition {which} Screen ------ [1-9]: Change Screen --"));
        l.extend(st.repartition_screen(which));
        l.extend(tail(i, false));
    }
    l
}

/// draw_vars_screen(): each message's actions, as SIPp describes them.
pub fn variables(sc: &Scenario, i: &Info, last: bool) -> Vec<String> {
    let mut l = vec!["----------------------------- Variables Screen -------- [1-9]: Change Screen --".to_string()];
    l.push("Action defined Per Message :".into());
    let mut found = false;
    for (index, step) in sc.steps.iter().enumerate() {
        if step.actions.is_empty() {
            continue;
        }
        let kind = match step.op {
            Op::Recv { .. } => " (Receive Message)",
            Op::RecvCmd { .. } => " (Receive Command Message)",
            _ => "",
        };
        l.push(truncate(format!("=> Message[{index}]{kind} - [{}] action(s) defined :", step.actions.len()), 79));
        for (j, a) in step.actions.iter().enumerate() {
            l.push(truncate(format!("   --> action[{j}] = {}", describe(a)), 79));
            found = true;
        }
    }
    if !found {
        l.push("=> No action found on any messages".into());
    }
    l.push(String::new());
    // To the messages + 6 lines.
    while l.len() < sc.steps.len() + 6 {
        l.push(String::new());
    }
    l.extend(tail(i, last));
    l
}

/// draw_tdm_screen().
pub fn tdm(sc: &Scenario, map: &crate::tdm::TdmMap, i: &Info, last: bool) -> Vec<String> {
    let mut l = vec!["------------------------------ TDM map Screen --------- [1-9]: Change Screen --".to_string()];
    l.extend(map.screen(sc.steps.len()));
    l.extend(tail(i, last));
    l
}

/// CAction::printInfo(), with SIPp's action numbers (of a build with pcap
/// play).
fn describe(a: &Action) -> String {
    let num = |n: &Num| match n {
        Num::Value(v) => *v,
        Num::Var(_) => 0.0,
    };
    let var_of = |n: &Num| match n {
        Num::Var(v) => v.clone(),
        Num::Value(_) => String::new(),
    };
    let text = |t: &crate::template::Template| format!("{:<32.32}", t.source);
    match a {
        Action::Ereg { re, source, check, assign_to } => {
            let var = assign_to.first().map_or("", String::as_str);
            let place = match source {
                Source::Msg => "Full Msg".to_string(),
                Source::Hdr { header, .. } => format!("Header-{header}"),
                Source::Body | Source::Var(_) => "Header-".to_string(),
            };
            format!(
                "Type[1] - regexp[{}] where[{place}] - checkIt[{}] - checkItInverse[{}] - ${var}",
                re.as_str(),
                check.check_it as u8,
                check.inverse as u8
            )
        }
        Action::Assign { var, value } => format!("Type[3] - assign varId[{var}] {:.6}", num(value)),
        Action::Sample { var, dist } => {
            format!("Type[4] - sample varId[{var}] {}", dist.text().chars().take(39).collect::<String>())
        }
        Action::AssignStr { var, value } => format!("Type[5] - string assign varId[{var}] [{}]", text(value)),
        Action::Index(var) => format!("Type[6] - assign index[{var}]"),
        Action::GetTimeOfDay { sec, usec } => format!("Type[7] - assign gettimeofday[{sec}, {usec}]"),
        Action::Jump(n) => format!("Type[8] - jump varInId[{}] {:.6}", var_of(n), num(n)),
        Action::Lookup { .. } => "Type[9] - unknown action type ... ".into(),
        Action::Insert { .. } => "Type[10] - unknown action type ... ".into(),
        Action::Replace { .. } => "Type[11] - unknown action type ... ".into(),
        Action::PauseRestore(n) => format!("Type[12] - restore pause varInId[{}] {:.6}", var_of(n), num(n)),
        Action::Log(t) => format!("Type[13] - message[{}]", text(t)),
        Action::Warning(t) => format!("Type[14] - warning[{}]", text(t)),
        Action::Error(t) => format!("Type[15] - error[{}]", text(t)),
        Action::Exec(t) => format!("Type[16] - command[{}]", text(t)),
        Action::Lua(t) => format!("Type[56] - lua[{}]", text(t)),
        Action::Verify(t) => format!("Type[17] - verify[{}]", text(t)),
        Action::Stop(s) => {
            let what = match s {
                Stop::Call => "stop_call",
                Stop::Gracefully => "stop_gracefully",
                Stop::Now => "stop_now",
            };
            format!("Type[18] - intcmd[{what:<32.32}]")
        }
        Action::Arith { op, var, rhs } => {
            let (n, what) = match op {
                Arith::Add => (19, "add"),
                Arith::Subtract => (20, "subtract"),
                Arith::Multiply => (21, "multiply"),
                Arith::Divide => (22, "divide"),
            };
            format!("Type[{n}] - {what} varId[{var}] {:.6}", num(rhs))
        }
        Action::Test { assign_to, var, compare, rhs, .. } => {
            let cmp = match compare {
                Compare::Equal => "==",
                Compare::NotEqual => "!=",
                Compare::Greater => ">",
                Compare::Less => "<",
                Compare::GreaterEqual => ">=",
                Compare::LessEqual => "<=",
            };
            let value = match rhs {
                Operand::Value(v) => v.trim().parse().unwrap_or(0.0),
                Operand::Var(_) => 0.0,
            };
            format!("Type[23] - test varId[{}] varInId[{var}] {cmp} {value:.6}", assign_to.as_deref().unwrap_or(""))
        }
        Action::ToDouble { to, .. } => format!("Type[24] - toDouble varId[{to}]"),
        Action::Strcmp { .. } => "Type[25] - unknown action type ... ".into(),
        Action::Str { op, var } => match op {
            StrOp::Trim => format!("Type[26] - trim varId[{var}]"),
            StrOp::UrlDecode => format!("Type[27] - urldecode varId[{var}]"),
            StrOp::UrlEncode => format!("Type[28] - urlencode varId[{var}]"),
        },
        Action::VerifyAuth { .. } => "Type[29] - unknown action type ... ".into(),
        Action::SetDest { .. } => "Type[30] - unknown action type ... ".into(),
        Action::CloseCon => "Type[31] - unknown action type ... ".into(),
        Action::PlayPcap { kind, file, .. } => {
            let n = match kind {
                PcapMedia::Audio => 32,
                PcapMedia::Image => 33,
                PcapMedia::Video => 34,
                PcapMedia::Text => 35,
            };
            format!("Type[{n}] - file[{file}]")
        }
        Action::PlayDtmf(t) => format!("Type[36] - play DTMF digits [{}]", t.source),
        Action::RtpPause { video: false } => "Type[37] - rtp_stream pause".into(),
        Action::RtpResume { video: false } => "Type[38] - rtp_stream resume".into(),
        Action::RtpWait { timeout_ms } => format!("Type[39] - rtp_stream wait [timeout={timeout_ms}]"),
        Action::RtpStats { video, vars } => format!("Type[40] - rtp_stats {} [{}]", if *video { "video" } else { "audio" }, vars[0]),
        Action::RtpDtmf { var, payload_type } => format!("Type[41] - rtp_dtmf payload type {payload_type} [{var}]"),
        Action::RtpEcho(_) => "Type[43] - unknown action type ... ".into(),
        Action::Unknown => "Type[0] - unknown action type ... ".into(),
        Action::RtpPause { video: true } => "Type[47] - rtp_stream pausevpattern".into(),
        Action::RtpResume { video: true } => "Type[48] - rtp_stream resumevpattern".into(),
        Action::RtpStream { source, video, loops, codec } => {
            let (n, what, file, id) = match (source, video) {
                (StreamSource::File(f), _) => (42, "playfile", f.source.clone(), 0),
                (StreamSource::Pattern(p), false) => (46, "playapattern", String::new(), *p),
                (StreamSource::Pattern(p), true) => (49, "playvpattern", String::new(), *p),
            };
            let ms = codec.interval.as_millis();
            format!(
                "Type[{n}] - rtp_stream {what} file {file} pattern_id {id} loop={loops} payload {} bytes per packet={} ms per packet={ms} ticks per packet={}",
                codec.payload, codec.bytes, codec.ticks
            )
        }
        Action::MediaEcho { video, on, update, .. } => match (video, on, update) {
            (false, true, true) => "Type[50] - rtp_stream rtpecho updateaudio".into(),
            (false, true, false) => "Type[51] - rtp_stream rtpecho startaudio".into(),
            (false, false, _) => "Type[52] - rtp_stream rtpecho stopaudio".into(),
            (true, true, true) => "Type[53] - rtp_stream rtpecho updatevideo".into(),
            (true, true, false) => "Type[54] - rtp_stream rtpecho startvideo".into(),
            (true, false, _) => "Type[55] - rtp_stream rtpecho stopvideo".into(),
        },
    }
}

/// snprintf()'s cut, at a character boundary.
fn truncate(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut at = max;
        while !s.is_char_boundary(at) {
            at -= 1;
        }
        s.truncate(at);
    }
    s
}

/// print_count_file(): the -trace_counts header, or a row; or what it
/// wrote of it before a <recv> without request or response, which SIPp
/// fails on ("Unknown count file message type:").
pub fn counts(sc: &Scenario, st: Option<&Stats>, d: &str, rfc3339: bool, lose_packets: bool) -> Result<String, String> {
    let mut out = match st {
        None => format!("CurrentTime{d}ElapsedTime{d}"),
        Some(st) => {
            let now = std::time::SystemTime::now();
            let ms = now.duration_since(st.start()).unwrap_or_default().as_millis() as u64;
            format!("{}{d}{}{d}", crate::stat::format_time(now, rfc3339), crate::stat::hhmmss_us(ms))
        }
    };
    for (index, step) in sc.steps.iter().enumerate() {
        if step.hide {
            continue;
        }
        let c = st.map(|st| st.steps[index].clone()).unwrap_or_default();
        let cols: Vec<(String, u64)> = match &step.op {
            Op::Send { msg, retrans_ms, .. } => {
                let what = match msg.response_code() {
                    Some(code) => code.to_string(),
                    None => msg.method().unwrap_or("").to_string(),
                };
                let mut v = vec![(format!("{index}_{what}_Sent"), c.sent), (format!("{index}_{what}_Retrans"), c.sent_retrans)];
                if retrans_ms.is_some() {
                    v.push((format!("{index}_{what}_Timeout"), c.timeouts));
                }
                if lose_packets {
                    v.push((format!("{index}_{what}_Lost"), c.lost));
                }
                v
            }
            Op::Recv { expect: Expect::Nothing, .. } => return Err(out),
            Op::Recv { expect, shown, .. } => {
                let what = shown.clone().unwrap_or_else(|| match expect {
                    Expect::Response(code) => code.to_string(),
                    Expect::ResponseRe(re) | Expect::RequestRe(re) => re.as_str().to_string(),
                    Expect::Request(m) => m.clone(),
                    Expect::Nothing => unreachable!(),
                });
                let mut v = vec![
                    (format!("{index}_{what}_Recv"), c.recv),
                    (format!("{index}_{what}_Retrans"), c.recv_retrans),
                    (format!("{index}_{what}_Timeout"), c.timeouts),
                    (format!("{index}_{what}_Unexp"), c.unexpected),
                ];
                if lose_packets {
                    v.push((format!("{index}_{what}_Lost"), c.lost));
                }
                v
            }
            Op::Pause(_) | Op::Timewait { .. } => {
                vec![(format!("{index}_Pause_Sessions"), c.sessions.max(0) as u64), (format!("{index}_Pause_Unexp"), c.unexpected)]
            }
            Op::Nop => Vec::new(),
            Op::RecvCmd { .. } => vec![(format!("{index}_RecvCmd"), c.cmds), (format!("{index}_RecvCmd_Timeout"), c.timeouts)],
            Op::SendCmd { .. } => vec![(format!("{index}_SendCmd"), c.cmds)],
        };
        for (name, n) in cols {
            out += &if st.is_some() { format!("{n}{d}") } else { format!("{name}{d}") };
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(state: State, last_error: Option<&str>) -> Info<'_> {
        Info {
            server: false,
            users: None,
            rate: 10.0,
            rate_period: Duration::from_secs(1),
            duration: Duration::ZERO,
            local_port: 5060,
            elapsed: Duration::ZERO,
            remote: "127.0.0.1:5060".into(),
            transport: "UDP",
            max_calls: None,
            limit: 0,
            running: 0,
            paused: 0,
            woken: 0,
            auto_answer: false,
            open_sockets: 1,
            net_errors: (0, 0),
            rtp_threads: 0,
            rtp_echo: false,
            lose_packets: false,
            loops: 0,
            state,
            last_error,
            third_party: None,
        }
    }

    #[test]
    fn screen_file_footers_follow_the_quit_state_as_get_lines() {
        let sc = crate::scenario::parse(crate::scenario::UAC, &Default::default(), 0).unwrap();
        let st = Stats::new(&sc.layout);
        let err = "2026-09-28\t04:04:41.676798\t1790557481.676798: Aborted call with Call-ID '19-1@127.0.0.1'";
        let tails = |i: &Info| -> Vec<String> { all(&sc, &st, i).into_iter().filter(|l| l.starts_with("Last Error") || l.starts_with("-------")).collect() };
        let waiting = tails(&info(State::Waiting, Some(err)));
        assert!(waiting.contains(&"Last Error: Aborted call with Call-ID '19-1@127.0.0.1'...".to_string()));
        assert!(waiting.contains(&"------- Waiting for active calls to end. Press [q] again to force exit. -------".to_string()));
        assert!(!waiting.iter().any(|l| l.contains("Test Terminated")));
        let forcing = tails(&info(State::Forcing, None));
        assert!(forcing.contains(&"-------------------------------- Forcing quit ---------------------------------".to_string()));
        assert!(!forcing.iter().any(|l| l.starts_with("Last Error")));
        // print_closing_stats(): no last error, and the run terminated.
        let i = info(State::Forcing, Some(err));
        let closing = closing(1, &sc, &st, &crate::tdm::TdmMap::default(), &i);
        assert!(!closing.iter().any(|l| l.starts_with("Last Error")));
        assert_eq!(closing.last().unwrap(), "------------------------------ Test Terminated --------------------------------");
    }

    #[test]
    fn last_error_past_any_time() {
        for time in ["2026-09-28\t04:04:41.676798\t1790557481.676798", "2026-09-28T04:04:41.676798Z", "2026-09-28T04:04:41.676798+03:00"] {
            let e = format!("{time}: the last error");
            assert_eq!(tail(&info(State::Running, Some(&e)), false)[0], "Last Error: the last error...");
        }
    }

    #[test]
    fn variables_screen_pads_to_the_messages_and_6() {
        let pauses = "<pause milliseconds=\"1\"/>".repeat(19);
        let xml = format!("<scenario name=\"p\"><nop/>{pauses}</scenario>");
        let sc = crate::scenario::parse(&xml, &Default::default(), 0).unwrap();
        assert_eq!(sc.steps.len(), 20);
        let i = info(State::Running, None);
        let lines = variables(&sc, &i, false);
        assert_eq!(lines.len() - tail(&i, false).len(), 26, "{lines:?}");
    }
}

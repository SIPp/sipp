//! SIPp's CStat: call counters, response times (RTDs), call lengths and
//! generic counters, cumulative (C) and per -trace_stat period (P), and the
//! -trace_stat CSV they fill, in SIPp's format.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Why a call failed, in the order of the CSV's Failed* columns. Some
/// never happen here (sends don't block), but keep their columns.
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum Fail {
    CannotSendMessage,
    MaxUdpRetrans,
    TcpConnect,
    TcpClosed,
    UnexpectedMessage,
    CallRejected,
    CmdNotSent,
    RegexpDoesntMatch,
    RegexpShouldntMatch,
    RegexpHdrNotFound,
    OutboundCongestion,
    TimeoutOnRecv,
    TimeoutOnSend,
    TestDoesntMatch,
    TestShouldntMatch,
    StrcmpDoesntMatch,
    StrcmpShouldntMatch,
}

const FAIL_NAMES: [&str; 17] = [
    "CannotSendMessage",
    "MaxUDPRetrans",
    "TcpConnect",
    "TcpClosed",
    "UnexpectedMessage",
    "CallRejected",
    "CmdNotSent",
    "RegexpDoesntMatch",
    "RegexpShouldntMatch",
    "RegexpHdrNotFound",
    "OutboundCongestion",
    "TimeoutOnRecv",
    "TimeoutOnSend",
    "TestDoesntMatch",
    "TestShouldntMatch",
    "StrcmpDoesntMatch",
    "StrcmpShouldntMatch",
];

/// Count, sum and sum of squares of millisecond values.
#[derive(Debug, Default, Clone)]
struct Mean {
    count: u64,
    sum: u64,
    sumsq: u64,
}

impl Mean {
    fn add(&mut self, ms: u64) {
        self.count += 1;
        self.sum += ms;
        self.sumsq += ms * ms;
    }

    fn mean(&self) -> f64 {
        if self.count == 0 { 0.0 } else { self.sum as f64 / self.count as f64 }
    }

    /// The sample standard deviation, as computeStdev().
    fn stdev(&self) -> f64 {
        if self.count <= 1 {
            return 0.0;
        }
        let n = self.count as f64;
        ((n * self.sumsq as f64 - (self.sum as f64) * (self.sum as f64)) / (n * (n - 1.0))).sqrt()
    }
}

/// One set of counters: the run's (C) or the current period's (P).
#[derive(Debug, Default, Clone)]
struct Counters {
    incoming: u64,
    outgoing: u64,
    successful: u64,
    failed: u64,
    fails: [u64; 17],
    out_of_call: u64,
    dead_call: u64,
    retransmissions: u64,
    auto_answered: u64,
    warnings: u64,
    fatal_errors: u64,
    rtd: Vec<Mean>,
    call_length: Mean,
    generic: Vec<u64>,
}

/// A <ResponseTimeRepartition> or <CallLengthRepartition> table: sorted
/// borders, and the count below each, then at or above the last, both
/// cumulative and since the last -trace_stat dump.
#[derive(Debug, Clone)]
pub struct Repartition {
    borders: Vec<u64>,
    counts: Vec<u64>,
    periodic: Vec<u64>,
}

impl Repartition {
    pub fn new(mut borders: Vec<u64>) -> Option<Repartition> {
        if borders.is_empty() {
            return None;
        }
        borders.sort_unstable();
        let counts = vec![0; borders.len() + 1];
        Some(Repartition { borders, periodic: counts.clone(), counts })
    }

    fn add(&mut self, ms: u64) {
        let i = self.borders.iter().position(|&b| ms < b).unwrap_or(self.borders.len());
        self.counts[i] += 1;
        self.periodic[i] += 1;
    }

    /// The (P) columns of the ranges, then their (C) ones.
    fn header(&self, name: &str, d: &str) -> String {
        let mut s = format!("{name}{d}");
        for kind in ["(P)", "(C)"] {
            for b in &self.borders {
                s += &format!("{name}_<{b}{kind}{d}");
            }
            s += &format!("{name}_>={}{kind}{d}", self.borders.last().unwrap());
        }
        s
    }

    fn row(&self, d: &str) -> String {
        let mut s = d.to_string();
        for c in self.periodic.iter().chain(&self.counts) {
            s += &format!("{c}{d}");
        }
        s
    }
}

/// A scenario step's counters, for the screens and -trace_counts.
#[derive(Debug, Default, Clone)]
pub struct StepCounts {
    pub sent: u64,
    pub sent_retrans: u64,
    pub recv: u64,
    pub recv_retrans: u64,
    pub timeouts: u64,
    pub unexpected: u64,
    pub lost: u64,
    /// Calls that went into this <pause> (SIPp's sessions, never lowered).
    pub sessions: i64,
    pub cmds: u64,
}

/// What the scenario declares for the statistics.
#[derive(Debug, Default, Clone)]
pub struct Layout {
    pub steps: usize,
    /// RTD names in the order they first appear ("1" for rtd="true").
    pub rtds: Vec<String>,
    /// counter= names, likewise.
    pub counters: Vec<String>,
    /// <ResponseTimeRepartition>, for the RTDs defined before it.
    pub response_times: Option<(Vec<u64>, usize)>,
    pub call_lengths: Option<Vec<u64>>,
}

pub struct Stats {
    c: Counters,
    p: Counters,
    /// The screen's period (PD), a refresh long.
    d: Counters,
    display_start: SystemTime,
    pub current: u64,
    /// The most calls at once, and when (seconds into the run).
    pub peak: (u64, u64),
    pub steps: Vec<StepCounts>,
    /// Codes of the unexpected responses since the last -trace_error_codes line.
    pub error_codes: Vec<u16>,
    /// -trace_rtt's pending lines: when (ms into the run), the response
    /// time in ms, and the RTD.
    pub rtts: Vec<(f64, f64, usize)>,
    rtd_names: Vec<String>,
    counter_names: Vec<String>,
    response_reps: Vec<Option<Repartition>>,
    call_rep: Option<Repartition>,
    start: SystemTime,
    period_start: SystemTime,
    /// -rfc3339 timestamps.
    pub rfc3339: bool,
    /// -stat_delimiter.
    pub delimiter: String,
    /// What the per-second report shows besides the CSV.
    pub unexpected: u64,
    pub timeouts: u64,
    /// Warnings logged when the period began.
    warnings_base: u64,
}

impl Default for Stats {
    fn default() -> Stats {
        Stats::new(&Layout::default())
    }
}

impl Stats {
    pub fn new(layout: &Layout) -> Stats {
        let zero = Counters { rtd: vec![Mean::default(); layout.rtds.len()], generic: vec![0; layout.counters.len()], ..Default::default() };
        let response_reps = (0..layout.rtds.len())
            .map(|i| layout.response_times.as_ref().filter(|(_, known)| i < *known).and_then(|(b, _)| Repartition::new(b.clone())))
            .collect();
        let now = SystemTime::now();
        Stats {
            c: zero.clone(),
            p: zero.clone(),
            d: zero,
            display_start: SystemTime::now(),
            current: 0,
            peak: (0, 0),
            steps: vec![StepCounts::default(); layout.steps],
            error_codes: Vec::new(),
            rtts: Vec::new(),
            rtd_names: layout.rtds.clone(),
            counter_names: layout.counters.clone(),
            response_reps,
            call_rep: layout.call_lengths.clone().and_then(Repartition::new),
            start: now,
            period_start: now,
            rfc3339: false,
            delimiter: ";".into(),
            unexpected: 0,
            timeouts: 0,
            warnings_base: 0,
        }
    }

    fn both(&mut self, f: impl Fn(&mut Counters)) {
        f(&mut self.c);
        f(&mut self.p);
        f(&mut self.d);
    }

    /// Starts a new screen period.
    pub fn new_display_period(&mut self) {
        self.d = Counters { rtd: vec![Mean::default(); self.rtd_names.len()], generic: vec![0; self.counter_names.len()], ..Default::default() };
        self.display_start = SystemTime::now();
    }

    pub fn created(&mut self, incoming: bool) {
        self.current += 1;
        if self.current > self.peak.0 {
            let secs = SystemTime::now().duration_since(self.start).unwrap_or_default().as_secs();
            self.peak = (self.current, secs);
        }
        self.both(|c| if incoming { c.incoming += 1 } else { c.outgoing += 1 });
    }

    /// A call is over: successful, failed (and why), or neither.
    pub fn ended(&mut self, ok: Option<bool>, why: Option<Fail>, length: Duration) {
        self.current = self.current.saturating_sub(1);
        let ms = length.as_millis() as u64;
        self.both(|c| {
            match ok {
                Some(true) => c.successful += 1,
                Some(false) => c.failed += 1,
                None => {}
            }
            if let (Some(false), Some(w)) = (ok, why) {
                c.fails[w as usize] += 1;
            }
            c.call_length.add(ms);
        });
        if let Some(r) = self.call_rep.as_mut() {
            r.add(ms);
        }
    }

    pub fn retransmission(&mut self) {
        self.both(|c| c.retransmissions += 1);
    }
    pub fn out_of_call(&mut self) {
        self.both(|c| c.out_of_call += 1);
    }
    pub fn dead_call(&mut self) {
        self.both(|c| c.dead_call += 1);
    }
    pub fn auto_answered(&mut self) {
        self.both(|c| c.auto_answered += 1);
    }
    /// The log's warning count so far.
    pub fn sync_warnings(&mut self, total: u64) {
        self.c.warnings = total;
        self.p.warnings = total - self.warnings_base.min(total);
    }
    pub fn fatal_error(&mut self) {
        self.both(|c| c.fatal_errors += 1);
    }
    pub fn counter(&mut self, i: usize) {
        self.both(|c| c.generic[i] += 1);
    }

    /// A response time for RTD `i`, in whole milliseconds as SIPp keeps it;
    /// `at` is when it ended, into the run.
    pub fn rtd(&mut self, i: usize, elapsed: Duration, at: Duration) {
        self.rtts.push((at.as_micros() as f64 / 1000.0, elapsed.as_micros() as f64 / 1000.0, i));
        let ms = elapsed.as_micros() as u64 / 1000;
        self.both(|c| c.rtd[i].add(ms));
        if let Some(r) = self.response_reps[i].as_mut() {
            r.add(ms);
        }
    }

    pub fn rtd_names(&self) -> &[String] {
        &self.rtd_names
    }

    pub fn start(&self) -> SystemTime {
        self.start
    }

    /// reset stats: the cumulative counters start again, from now.
    pub fn reset_cumulative(&mut self) {
        self.c = Counters { rtd: vec![Mean::default(); self.rtd_names.len()], generic: vec![0; self.counter_names.len()], ..Default::default() };
        self.start = SystemTime::now();
        self.warnings_base = 0;
    }

    /// Starts a new -trace_stat period.
    pub fn new_period(&mut self) {
        let zero = Counters { rtd: vec![Mean::default(); self.rtd_names.len()], generic: vec![0; self.counter_names.len()], ..Default::default() };
        self.p = zero;
        self.period_start = SystemTime::now();
        self.warnings_base = self.c.warnings;
        for r in self.response_reps.iter_mut().chain([&mut self.call_rep]).flatten() {
            r.periodic.iter_mut().for_each(|c| *c = 0);
        }
    }

    pub fn csv_header(&self) -> String {
        let d = &self.delimiter;
        let mut cols: Vec<String> = [
            "StartTime", "LastResetTime", "CurrentTime", "ElapsedTime(P)", "ElapsedTime(C)", "TargetRate",
            "CallRate(P)", "CallRate(C)", "IncomingCall(P)", "IncomingCall(C)", "OutgoingCall(P)", "OutgoingCall(C)",
            "TotalCallCreated", "CurrentCall", "SuccessfulCall(P)", "SuccessfulCall(C)", "FailedCall(P)", "FailedCall(C)",
        ]
        .map(String::from)
        .into();
        for f in FAIL_NAMES {
            cols.push(format!("Failed{f}(P)"));
            cols.push(format!("Failed{f}(C)"));
        }
        for n in ["OutOfCallMsgs", "DeadCallMsgs", "Retransmissions", "AutoAnswered", "Warnings", "FatalErrors", "WatchdogMajor", "WatchdogMinor"] {
            cols.push(format!("{n}(P)"));
            cols.push(format!("{n}(C)"));
        }
        for r in &self.rtd_names {
            cols.extend([format!("ResponseTime{r}(P)"), format!("ResponseTime{r}(C)")]);
            cols.extend([format!("ResponseTime{r}StDev(P)"), format!("ResponseTime{r}StDev(C)")]);
        }
        cols.extend(["CallLength(P)", "CallLength(C)", "CallLengthStDev(P)", "CallLengthStDev(C)"].map(String::from));
        for n in &self.counter_names {
            // A numeric counter name gets a prefix, as findCounter() gives it.
            let n = if n.bytes().all(|b| b.is_ascii_digit()) { format!("GenericCounter{n}") } else { n.clone() };
            cols.extend([format!("{n}(P)"), format!("{n}(C)")]);
        }
        let mut s: String = cols.iter().map(|c| format!("{c}{d}")).collect();
        for (r, rep) in self.rtd_names.iter().zip(&self.response_reps) {
            if let Some(rep) = rep {
                s += &rep.header(&format!("ResponseTimeRepartition{r}"), d);
            }
        }
        if let Some(rep) = &self.call_rep {
            s += &rep.header("CallLengthRepartition", d);
        }
        s
    }

    /// A row as dumpData() writes it; `target` is the rate, or the -users count.
    pub fn csv_row(&self, target: Target) -> String {
        let d = &self.delimiter;
        let now = SystemTime::now();
        let ms = |since: SystemTime| now.duration_since(since).unwrap_or_default().as_millis() as u64;
        let (global, local) = (ms(self.start), ms(self.period_start));
        let rate = |calls: u64, ms: u64| if ms > 0 { 1000.0 * calls as f32 / ms as f32 } else { 0.0 };
        let (c, p) = (&self.c, &self.p);
        let mut v: Vec<String> = vec![
            format_time(self.start, self.rfc3339),
            format_time(self.period_start, self.rfc3339),
            format_time(now, self.rfc3339),
            hhmmss(local),
            hhmmss(global),
            match target {
                Target::Rate(r) => format!("{r:.3}"),
                Target::Users(u) => u.to_string(),
            },
            format!("{:.3}", rate(p.incoming + p.outgoing, local)),
            format!("{:.3}", rate(c.incoming + c.outgoing, global)),
        ];
        v.extend([p.incoming, c.incoming, p.outgoing, c.outgoing, c.incoming + c.outgoing, self.current].map(|n| n.to_string()));
        v.extend([p.successful, c.successful, p.failed, c.failed].map(|n| n.to_string()));
        for i in 0..FAIL_NAMES.len() {
            v.extend([p.fails[i], c.fails[i]].map(|n| n.to_string()));
        }
        for (pn, cn) in [
            (p.out_of_call, c.out_of_call),
            (p.dead_call, c.dead_call),
            (p.retransmissions, c.retransmissions),
            (p.auto_answered, c.auto_answered),
            (p.warnings, c.warnings),
            (p.fatal_errors, c.fatal_errors),
            (0, 0),
            (0, 0),
        ] {
            v.extend([pn, cn].map(|n| n.to_string()));
        }
        for i in 0..self.rtd_names.len() {
            v.extend([p.rtd[i].mean(), c.rtd[i].mean(), p.rtd[i].stdev(), c.rtd[i].stdev()].map(|x| hhmmss_us(x as u64)));
        }
        v.extend([p.call_length.mean(), c.call_length.mean(), p.call_length.stdev(), c.call_length.stdev()].map(|x| hhmmss_us(x as u64)));
        for i in 0..self.counter_names.len() {
            v.extend([p.generic[i], c.generic[i]].map(|n| n.to_string()));
        }
        let mut s: String = v.iter().map(|x| format!("{x}{d}")).collect();
        for rep in self.response_reps.iter().flatten() {
            s += &rep.row(d);
        }
        if let Some(rep) = &self.call_rep {
            s += &rep.row(d);
        }
        s
    }
}

impl Stats {
    /// draw_stats_screen().
    pub fn stats_screen(&self) -> Vec<String> {
        let now = SystemTime::now();
        let ms = |since: SystemTime| now.duration_since(since).unwrap_or_default().as_millis() as u64;
        let (global, local) = (ms(self.start), ms(self.display_start));
        let rate = |calls: u64, ms: u64| if ms > 0 { 1000.0 * calls as f32 / ms as f32 } else { 0.0 };
        let (c, d) = (&self.c, &self.d);
        let cross = "-------------------------+---------------------------+--------------------------".to_string();
        let txt = |t: &str, v: &str| format!("  {:<22.22} | {:<52.52} ", t, v);
        let txt_col = |t: &str, v1: &str, v2: &str| format!("  {:<22.22} | {:<25.25} | {:<24.24} ", t, v1, v2);
        let two = |t: &str, v1: u64, v2: u64| format!("  {:<22.22} | {:>8}                  | {:>8}                 ", t, v1, v2);
        let mut l = vec![
            txt("Start Time  ", &format_time(self.start, false)),
            txt("Last Reset Time", &format_time(self.display_start, false)),
            txt("Current Time", &format_time(now, false)),
            cross.clone(),
            "  Counter Name           | Periodic value            | Cumulative value".to_string(),
            cross.clone(),
            txt_col("Elapsed Time", &hhmmss_us(local), &hhmmss_us(global)),
            format!(
                "  {:<22.22} | {:>8.3} cps              | {:>8.3} cps             ",
                "Call Rate",
                rate(d.incoming + d.outgoing, local),
                rate(c.incoming + c.outgoing, global)
            ),
            cross.clone(),
            two("Incoming calls created", d.incoming, c.incoming),
            two("Outgoing calls created", d.outgoing, c.outgoing),
            format!("  {:<22.22} |                           | {:>8}                 ", "Total Calls created", c.incoming + c.outgoing),
            format!("  {:<22.22} | {:>8}                  |                          ", "Current Calls", self.current),
        ];
        if !self.counter_names.is_empty() {
            l.push(cross.clone());
        }
        for (i, n) in self.counter_names.iter().enumerate() {
            l.push(two(&format!("Counter {n}"), d.generic[i], c.generic[i]));
        }
        l.push(cross.clone());
        l.push(two("Successful call", d.successful, c.successful));
        l.push(two("Failed call", d.failed, c.failed));
        l.push(cross);
        for (i, n) in self.rtd_names.iter().enumerate() {
            l.push(txt_col(&format!("Response Time {n}"), &hhmmss_us(d.rtd[i].mean() as u64), &hhmmss_us(c.rtd[i].mean() as u64)));
        }
        l.push(txt_col("Call Length", &hhmmss_us(d.call_length.mean() as u64), &hhmmss_us(c.call_length.mean() as u64)));
        l
    }

    /// draw_repartition_screen(): RTD `which` (from 1), and call lengths with the first.
    pub fn repartition_screen(&self, which: usize) -> Vec<String> {
        let info = |t: &str| format!("  {:<77.77}", t);
        let detailed = |rep: Option<&Repartition>, l: &mut Vec<String>| match rep {
            Some(r) => {
                for (i, b) in r.borders.iter().enumerate() {
                    let low = if i == 0 { 0 } else { r.borders[i - 1] };
                    l.push(format!("    {:>10} ms <= n < {:>10} ms : {:>10}", low, b, r.counts[i]));
                }
                l.push(format!("    {:>14.14} n >= {:>10} ms : {:>10}", "", r.borders.last().unwrap(), r.counts[r.borders.len()]));
            }
            None => l.push(info("  <No repartion defined>")),
        };
        let mut l = Vec::new();
        if which > self.rtd_names.len() {
            l.push(info("  <No repartion defined>"));
            return l;
        }
        l.push(info(&format!("Average Response Time Repartition {}", self.rtd_names[which - 1])));
        detailed(self.response_reps[which - 1].as_ref(), &mut l);
        if which == 1 {
            l.push(info("Average Call Length Repartition"));
            detailed(self.call_rep.as_ref(), &mut l);
        }
        l
    }

    pub fn dead_calls(&self) -> u64 {
        self.c.dead_call
    }
    pub fn out_of_calls(&self) -> u64 {
        self.c.out_of_call
    }
    pub fn auto_answers(&self) -> u64 {
        self.c.auto_answered
    }
    /// Calls created in the screen's period, and how long it has been.
    pub fn display_period(&self) -> (u64, u64) {
        let ms = SystemTime::now().duration_since(self.display_start).unwrap_or_default().as_millis() as u64;
        (self.d.incoming + self.d.outgoing, ms)
    }
    pub fn total_created(&self) -> u64 {
        self.c.incoming + self.c.outgoing
    }
}

pub enum Target {
    Rate(f64),
    Users(u32),
}

/// msToHHMMSS().
fn hhmmss(ms: u64) -> String {
    let s = ms / 1000;
    format!("{:02}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60)
}

/// msToHHMMSSus(): the milliseconds as microseconds after the seconds.
pub fn hhmmss_us(ms: u64) -> String {
    let s = ms / 1000;
    format!("{:02}:{:02}:{:02}:{:06}", s / 3600, s / 60 % 60, s % 60, (ms % 1000) * 1000)
}

/// formatTime(): local time with a tab, then the epoch, or RFC 3339 with
/// the UTC offset.
pub fn format_time(t: SystemTime, rfc3339: bool) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let usec = d.subsec_micros();
    let (tm, off) = crate::sys::localtime(d.as_secs() as i64);
    let date = format!("{:04}-{:02}-{:02}", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
    let time = format!("{:02}:{:02}:{:02}.{usec:06}", tm.tm_hour, tm.tm_min, tm.tm_sec);
    if rfc3339 {
        let zone = if off == 0 { "Z".to_string() } else { format!("{:+03}:{:02}", off / 3600, (off / 60).abs() % 60) };
        format!("{date}T{time}{zone}")
    } else {
        format!("{date}\t{time}\t{:010}.{usec:06}", d.as_secs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn means_deviations_and_repartitions_as_sipp() {
        let mut m = Mean::default();
        for v in [10, 20, 30] {
            m.add(v);
        }
        assert_eq!((m.mean(), m.stdev()), (20.0, 10.0));
        let mut r = Repartition::new(vec![20, 10]).unwrap();
        for v in [5, 10, 19, 20, 1000] {
            r.add(v);
        }
        assert_eq!(r.counts, vec![1, 2, 2]);
        assert_eq!(r.header("X", ";"), "X;X_<10(P);X_<20(P);X_>=20(P);X_<10(C);X_<20(C);X_>=20(C);");
        assert_eq!(r.row(";"), ";1;2;2;1;2;2;");
        assert_eq!((hhmmss(3_723_000), hhmmss_us(2)), ("01:02:03".to_string(), "00:00:00:002000".to_string()));
    }

    #[test]
    fn header_has_sipps_columns() {
        let layout = Layout {
            steps: 1,
            rtds: vec!["1".into()],
            counters: vec!["7".into(), "reg".into()],
            response_times: Some((vec![10, 20], 1)),
            call_lengths: Some(vec![100]),
        };
        let s = Stats::new(&layout);
        let h = s.csv_header();
        assert!(h.starts_with("StartTime;LastResetTime;CurrentTime;ElapsedTime(P);"));
        assert!(h.contains(";FailedCannotSendMessage(P);FailedCannotSendMessage(C);"));
        assert!(h.contains(";WatchdogMinor(C);ResponseTime1(P);ResponseTime1(C);ResponseTime1StDev(P);"));
        assert!(h.contains(";CallLengthStDev(C);GenericCounter7(P);GenericCounter7(C);reg(P);reg(C);"));
        assert!(h.ends_with(";ResponseTimeRepartition1;ResponseTimeRepartition1_<10(P);ResponseTimeRepartition1_<20(P);ResponseTimeRepartition1_>=20(P);ResponseTimeRepartition1_<10(C);ResponseTimeRepartition1_<20(C);ResponseTimeRepartition1_>=20(C);CallLengthRepartition;CallLengthRepartition_<100(P);CallLengthRepartition_>=100(P);CallLengthRepartition_<100(C);CallLengthRepartition_>=100(C);"));
        assert_eq!(h.split(';').count(), s.csv_row(Target::Rate(10.0)).split(';').count());
    }

    #[test]
    fn repartitions_have_periodic_and_cumulative_columns() {
        let mut s = Stats::new(&Layout { call_lengths: Some(vec![20, 10]), ..Default::default() });
        s.ended(None, None, Duration::from_millis(5));
        s.ended(None, None, Duration::from_millis(25));
        assert!(s.csv_row(Target::Rate(10.0)).ends_with(";;1;0;1;1;0;1;"));
        s.new_period();
        s.ended(None, None, Duration::from_millis(15));
        assert!(s.csv_row(Target::Rate(10.0)).ends_with(";;0;1;0;1;1;1;"));
    }
}

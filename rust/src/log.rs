//! -trace_msg / -trace_err / -trace_logs output, in SIPp's formats.

use std::collections::VecDeque;
use std::fs::File;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

/// -max_log_size, -ringbuffer_size and -ringbuffer_files, and what the
/// rotated files are named after.
#[derive(Default, Clone)]
pub struct Limits {
    pub max_size: u64,
    pub ring_size: u64,
    pub ring_files: usize,
    pub scenario: String,
    pub pid: u32,
}

impl Limits {
    /// rotatef()'s <scenario>_<pid>_<name>_<start>[.<n>].log.
    fn rotated(&self, name: &str, start: u64, n: u32) -> String {
        match n {
            0 => format!("{}_{}_{name}_{start}.log", self.scenario, self.pid),
            n => format!("{}_{}_{name}_{start}.{n}.log", self.scenario, self.pid),
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// A log file, with what SIPp's logfile_info keeps to limit and rotate it.
#[derive(Default)]
pub struct Sink {
    pub file: Option<File>,
    pub path: String,
    name: &'static str,
    count: u64,
    /// When the file was opened, and the rotated files kept.
    start: u64,
    rotated: VecDeque<(u64, u32)>,
    /// Whether the next open truncates the file rather than adds to it:
    /// -X_overwrite false and "trace X off" have it added to once.
    pub overwrite: bool,
}

impl Sink {
    /// A log not open yet: rotate() opens it.
    pub fn new(path: String, name: &'static str, overwrite: bool) -> Sink {
        Sink { path, name, overwrite, ..Default::default() }
    }

    pub fn is_open(&self) -> bool {
        self.file.is_some()
    }

    /// log_off(): "trace X off" closes the file, for the next open to add
    /// to it.
    pub fn off(&mut self) {
        if self.file.take().is_some() {
            self.overwrite = false;
        }
    }

    /// _trace(): the text, then -max_log_size closes the file (until a
    /// "trace X on") and -ringbuffer_size rotates it.
    fn write(&mut self, lim: &Limits, text: &str) {
        let Some(f) = self.file.as_mut() else { return };
        let text = crate::raw::bytes(text);
        let _ = f.write_all(&text);
        self.count += text.len() as u64;
        if lim.max_size > 0 && self.count > lim.max_size {
            self.file = None;
        }
        if lim.ring_size > 0 && self.count > lim.ring_size {
            self.reopen(lim);
            self.count = 0;
        }
    }

    /// rotatef(): a log that can't be opened again ends the run, as
    /// SIPp's ERROR(), but for the -trace_err file, which the next
    /// warning opens (or exits on).
    fn reopen(&mut self, lim: &Limits) {
        if self.rotate(lim).is_err() && self.name != "errors" {
            defer_fatal(format!("Unable to create '{}'", self.path));
        }
    }

    /// rotatef(): with -ringbuffer_files the file opened before, even one
    /// "trace X off" closed, is renamed (the oldest one past the count
    /// removed); then the file is opened, truncated unless it is to be
    /// added to, or could not be renamed away.
    pub fn rotate(&mut self, lim: &Limits) -> std::io::Result<()> {
        self.file = None;
        if lim.ring_files > 0 {
            if self.rotated.len() == lim.ring_files {
                if let Some((start, n)) = self.rotated.pop_front() {
                    let _ = std::fs::remove_file(lim.rotated(self.name, start, n));
                }
            }
            if self.start != 0 {
                let n = match self.rotated.back() {
                    Some(&(start, n)) if start == self.start => n + 1,
                    _ => 0,
                };
                self.rotated.push_back((self.start, n));
                if std::fs::rename(&self.path, lim.rotated(self.name, self.start, n)).is_err() {
                    self.rotated.pop_back();
                    self.overwrite = false;
                }
            }
        }
        self.start = now_secs();
        let overwrite = std::mem::replace(&mut self.overwrite, true);
        let file = std::fs::OpenOptions::new().create(true).write(true).truncate(overwrite).append(!overwrite).open(crate::raw::os(&self.path))?;
        self.file = Some(file);
        Ok(())
    }
}

thread_local! {
    /// Warnings raised where no Log is at hand, such as FileContents'
    /// as a [fieldN] is rendered, and a fatal error from there: the
    /// warnings are written before the next one, and after each event.
    static DEFERRED: std::cell::RefCell<(Vec<String>, Option<String>)> = const { std::cell::RefCell::new((Vec::new(), None)) };
}

pub fn defer_warning(text: String) {
    DEFERRED.with_borrow_mut(|d| d.0.push(text));
}

/// The warnings of the RTP threads, written as the engine's deferred ones.
static THREAD_DEFERRED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

pub fn defer_thread_warning(text: String) {
    THREAD_DEFERRED.lock().unwrap().push(text);
}

/// SIPp's ERROR() where no Log is at hand: the run ends with it.
pub fn defer_fatal(text: String) {
    DEFERRED.with_borrow_mut(|d| {
        d.1.get_or_insert(text);
    });
}

pub fn fatal_deferred() -> bool {
    DEFERRED.with_borrow(|d| d.1.is_some())
}

pub fn take_deferred_fatal() -> Option<String> {
    DEFERRED.with_borrow_mut(|d| d.1.take())
}

/// SIGXFSZ, which manage_oversized_file() handles once: 1 raised, 2
/// handled.
static OVERSIZED: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// The SIGXFSZ handler's: only an atomic store. Windows has no SIGXFSZ.
#[cfg(unix)]
pub fn oversized() {
    use std::sync::atomic::Ordering::Relaxed;
    let _ = OVERSIZED.compare_exchange(0, 1, Relaxed, Relaxed);
}

#[derive(Default)]
pub struct Log {
    pub messages: Sink,
    /// -trace_err's file, opened on the next warning while print_all is
    /// set, as SIPp's print_all_responses.
    pub errors: Sink,
    pub print_all: bool,
    pub logs: Sink,
    /// -trace_shortmsg: a line per message.
    pub short: Sink,
    /// -trace_calldebug: the history of each call aborted on a failure.
    pub calldebug: Sink,
    pub limits: Limits,
    pub last_warning: Option<String>,
    /// -rfc3339: warnings' timestamps.
    pub rfc3339: bool,
    /// -callid_slash_ign: -trace_shortmsg keeps what comes before '///'.
    pub callid_slash_ign: bool,
    /// Warnings so far, for the statistics.
    pub warnings: u64,
    /// Warnings and errors so far, and the -trace_err file they went to:
    /// SIPp's total_errors and screen_logfile, for print_errors().
    total: u64,
    error_file: Option<String>,
    /// last_warning is on stderr already: print_errors() leaves it out.
    shown: bool,
    /// The -trace_err file could not be created: SIPp exits with the
    /// warning it was for.
    pub dead: bool,
    /// A file past the size limit: the statistics and RTT files are
    /// written no more either.
    pub stop_stats: bool,
}

/// UTC now: days since 1970-01-01, seconds into the day, microseconds.
fn now_utc() -> (i64, i64, u32) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs() as i64;
    (secs.div_euclid(86400), secs.rem_euclid(86400), now.subsec_micros())
}

/// Year, month, day from days since 1970-01-01 (Howard Hinnant's algorithm).
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

/// [date]: strftime("%a, %d %b %Y %T GMT").
pub fn http_date() -> String {
    let (days, rem, _) = now_utc();
    let (year, month, day) = civil(days);
    let wday = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][days.rem_euclid(7) as usize];
    let mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][month as usize - 1];
    format!("{wday}, {day:02} {mon} {year} {:02}:{:02}:{:02} GMT", rem / 3600, rem % 3600 / 60, rem % 60)
}

impl Log {
    /// The trace command, as SIPp's process_trace(): a log on, opened as
    /// rotatef() does, or off as log_off().
    pub fn trace(&mut self, log: &str, on: bool) {
        let sink = match log {
            "messages" => &mut self.messages,
            "logs" => &mut self.logs,
            "shortmessages" => &mut self.short,
            _ => {
                // error: -trace_err's file, opened again on the next warning.
                self.print_all = on;
                if !on {
                    self.errors.off();
                }
                return;
            }
        };
        if on && !sink.is_open() {
            sink.reopen(&self.limits);
        } else if !on {
            sink.off();
        }
    }

    /// manage_oversized_file(), the first time a file went past the size
    /// limit (SIGXFSZ): a note of it in <scenario>_<pid>_traces_oversized.log,
    /// and no more -trace_msg and -trace_logs (until a trace command).
    pub fn check_oversized(&mut self) {
        use std::sync::atomic::Ordering::Relaxed;
        if OVERSIZED.compare_exchange(1, 2, Relaxed, Relaxed).is_err() {
            return;
        }
        let path = format!("{}_{}_traces_oversized.log", self.limits.scenario, self.limits.pid);
        match File::create(&path) {
            Ok(mut f) => {
                let now = crate::stat::format_time(SystemTime::now(), self.rfc3339);
                let _ = write!(f, "-------------------------------------------- {now}\nMax file size reached - no more logs\n");
            }
            Err(e) => {
                let n = e.raw_os_error().unwrap_or(0);
                defer_fatal(format!("Unable to open oversized log file, errno = {n} ({})", crate::net::os_error(&e)));
                return;
            }
        }
        self.messages.file = None;
        self.logs.file = None;
        self.stop_stats = true;
    }

    fn short(&mut self, dir: &str, msg: &str, control: bool) {
        if !self.short.is_open() {
            return;
        }
        // A 3PCC command has no start line: its headers begin at once.
        let full = format!("CMD\r\n{msg}");
        let msg_ = if control { full.as_str() } else { msg };
        let header = |name: &str| crate::sip::header(msg_, name).unwrap_or("");
        // get_call_id()'s.
        let id = if control { header("Call-ID") } else { crate::sip::call_id(msg).unwrap_or("") };
        let id = match id.split_once("///") {
            Some((_, r)) if !self.callid_slash_ign => r,
            _ => id,
        };
        let line = format!(
            "{}\t{dir}\t{id}\tCSeq:{}\t{}\n",
            crate::stat::format_time(SystemTime::now(), self.rfc3339),
            crate::sip::header_content(msg_, "CSeq"),
            msg.lines().next().unwrap_or("")
        );
        self.short.write(&self.limits, &line);
    }

    fn message(&mut self, dir: &str, transport: &str, msg: &str) {
        self.check_oversized();
        let control = transport.ends_with("control");
        self.short(if dir == "sent" { "S" } else { "R" }, msg, control);
        if self.messages.is_open() {
            // A command has the ESC that ends it on the wire, which the
            // count has and a sent one shows.
            let len = crate::raw::len(msg) + usize::from(control);
            let esc = if control && dir == "sent" { "\x1b" } else { "" };
            let text = format!(
                "----------------------------------------------- {}\n{transport} message {dir} [{len}] bytes:\n\n{msg}{esc}\n",
                crate::stat::format_time(SystemTime::now(), true),
            );
            self.messages.write(&self.limits, &text);
        }
    }

    pub fn sent(&mut self, transport: &str, msg: &str) {
        self.message("sent", transport, msg);
    }

    /// A message that failed to go, in -trace_msg as SIPp's write().
    pub fn send_error(&mut self, transport: &str, msg: &str) {
        self.check_oversized();
        if self.messages.is_open() {
            let text = format!(
                "----------------------------------------------- {}\nError sending {transport} message:\n\n{msg}\n",
                crate::stat::format_time(SystemTime::now(), true),
            );
            self.messages.write(&self.limits, &text);
        }
    }

    /// A message only partly written, in -trace_msg as SIPp's write():
    /// the rest waits, and is not traced when it goes.
    pub fn truncated(&mut self, transport: &str, sent: usize, msg: &str) {
        self.check_oversized();
        if self.messages.is_open() {
            let text = format!(
                "----------------------------------------------- {}\nTruncation sending {transport} message ({sent} of {} sent):\n\n{msg}\n",
                crate::stat::format_time(SystemTime::now(), true),
                crate::raw::len(msg),
            );
            self.messages.write(&self.limits, &text);
        }
    }

    pub fn received(&mut self, transport: &str, msg: &str) {
        self.message("received", transport, msg);
    }

    /// TRACE_MSG(): a note of SIPp's own in the -trace_msg file.
    pub fn trace_msg(&mut self, text: &str) {
        self.check_oversized();
        if self.messages.is_open() {
            self.messages.write(&self.limits, text);
        }
    }

    pub fn warning(&mut self, text: &str) {
        self.flush_deferred();
        self.warnings += 1;
        self.write_error(text);
    }

    /// The warnings defer_warning() kept.
    pub fn flush_deferred(&mut self) {
        let threads = std::mem::take(&mut *THREAD_DEFERRED.lock().unwrap());
        for text in threads.into_iter().chain(DEFERRED.with_borrow_mut(|d| std::mem::take(&mut d.0))) {
            self.warnings += 1;
            self.write_error(&text);
        }
    }

    /// A fatal error goes to the -trace_err file as SIPp's ERROR() does,
    /// counted as such rather than as a warning, for print_errors() to
    /// print.
    pub fn error(&mut self, text: &str) {
        self.flush_deferred();
        self.write_error(text);
        // Without a -trace_err file, stderr gets it now, once.
        if !self.errors.is_open() {
            if let Some(line) = &self.last_warning {
                crate::raw::eprintln(line);
                self.shown = true;
            }
        }
    }

    /// SIPp's print_errors() on exit: the last warning or error, and
    /// whether there were more. Without -trace_err, that is all of them
    /// that stderr gets.
    pub fn print_errors(&self) {
        let Some(last) = self.last_warning.as_ref().filter(|_| self.total > 0) else { return };
        if !self.shown {
            crate::raw::eprintln(last);
        }
        if self.total > 1 {
            match &self.error_file {
                Some(path) => eprintln!("There were more errors, see '{path}' file"),
                None => eprintln!("There were more errors, enable -trace_err to log them."),
            }
        }
    }

    fn write_error(&mut self, text: &str) {
        self.total += 1;
        let mut line = format!("{}: {text}", self.stamp());
        if !self.errors.is_open() && self.print_all {
            // SIPp's screen_logfile, even when it could not be created.
            self.error_file = Some(self.errors.path.clone());
            match self.errors.rotate(&self.limits) {
                Ok(()) => {
                    if let Some(f) = self.errors.file.as_mut() {
                        let _ = writeln!(f, "The following events occurred:");
                    }
                }
                Err(e) => {
                    // The reason joins the warning, which print_errors()
                    // shows as the run ends.
                    line += &format!("Unable to create '{}': {}.\n", self.errors.path, crate::net::os_error(&e));
                    self.print_all = false;
                    self.dead = true;
                }
            }
        }
        if self.errors.is_open() {
            self.errors.write(&self.limits, &format!("{line}\n"));
            // -max_log_size: SIPp stops reporting warnings, until "trace
            // error on" adds them to the file again.
            if self.limits.max_size > 0 && !self.errors.is_open() {
                self.print_all = false;
                self.errors.overwrite = false;
            }
        }
        self.last_warning = Some(line);
        self.shown = false;
    }

    /// A call's history, as SIPp's abortCall() writes it.
    pub fn call_debug(&mut self, id: &str, history: &str) {
        if self.calldebug.is_open() {
            let text = format!("-------------------------------------------------------------------------------\nCall debugging information for call {id}:\n{history}");
            self.calldebug.write(&self.limits, &text);
        }
    }

    /// A line of a call's history: the time, then what happened.
    pub fn stamp(&self) -> String {
        crate::stat::format_time(SystemTime::now(), self.rfc3339)
    }

    pub fn log(&mut self, text: &str) {
        self.check_oversized();
        if self.logs.is_open() {
            self.logs.write(&self.limits, &format!("{text}\n"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A log opened as SIPp opens it once the scenario is loaded.
    fn opened(path: &str, overwrite: bool, lim: &Limits) -> Sink {
        let mut sink = Sink::new(path.to_string(), "messages", overwrite);
        sink.rotate(lim).unwrap();
        sink
    }

    fn read(path: &str) -> String {
        std::fs::read_to_string(path).unwrap()
    }

    #[test]
    fn ring_keeps_the_last_files() {
        let dir = std::env::temp_dir().join(format!("sipp-rs-ring-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t_messages.log").to_string_lossy().into_owned();
        let lim = Limits { ring_size: 10, ring_files: 2, scenario: dir.join("t").to_string_lossy().into_owned(), pid: 1, ..Default::default() };
        let mut sink = opened(&path, true, &lim);
        for i in 0..5 {
            sink.write(&lim, &format!("line {i} of twelve\n"));
        }
        let mut names: Vec<String> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        // Five rotations: the last two kept, and the file being written.
        assert!(names.iter().any(|n| n == "t_messages.log"));
        assert_eq!(names.iter().filter(|n| n.starts_with("t_1_messages_")).count(), 2, "{names:?}");
        let mut max = opened(&path, true, &Limits::default());
        max.write(&Limits { max_size: 5, ..Default::default() }, "past the limit\n");
        assert!(!max.is_open());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_log_not_overwritten_is_added_to_once() {
        let dir = std::env::temp_dir().join(format!("sipp-rs-append-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("m.log").to_string_lossy().into_owned();
        std::fs::write(&path, "old\n").unwrap();
        let lim = Limits::default();
        // -message_overwrite false: the first open adds to the file.
        let mut sink = opened(&path, false, &lim);
        sink.write(&lim, "new\n");
        assert_eq!(read(&path), "old\nnew\n");
        // A later one truncates it, unless "trace messages off" closed it.
        sink.rotate(&lim).unwrap();
        sink.write(&lim, "a\n");
        assert_eq!(read(&path), "a\n");
        sink.off();
        sink.write(&lim, "while off\n");
        sink.rotate(&lim).unwrap();
        sink.write(&lim, "b\n");
        assert_eq!(read(&path), "a\nb\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_log_turned_on_again_rotates_into_the_ring() {
        let dir = std::env::temp_dir().join(format!("sipp-rs-offon-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t_1_messages.log").to_string_lossy().into_owned();
        let mut log = Log { limits: Limits { ring_files: 2, scenario: dir.join("t").to_string_lossy().into_owned(), pid: 1, ..Default::default() }, ..Default::default() };
        log.messages = opened(&path, true, &log.limits);
        log.trace_msg("before\n");
        log.trace("messages", false);
        log.trace("messages", true);
        log.trace_msg("after\n");
        let start = log.messages.rotated.back().expect("rotated").0;
        assert_eq!(read(&log.limits.rotated("messages", start, 0)), "before\n");
        assert_eq!(read(&path), "after\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_log_not_rotated_away_is_added_to() {
        let dir = std::env::temp_dir().join(format!("sipp-rs-kept-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("m.log").to_string_lossy().into_owned();
        // The rotated files' directory is missing: the rename fails.
        let lim = Limits { ring_size: 5, ring_files: 2, scenario: dir.join("missing/t").to_string_lossy().into_owned(), pid: 1, ..Default::default() };
        let mut sink = opened(&path, true, &lim);
        sink.write(&lim, "kept: past the size\n");
        sink.write(&lim, "and more\n");
        assert!(sink.rotated.is_empty());
        assert_eq!(read(&path), "kept: past the size\nand more\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_error_log_turned_on_again_is_added_to() {
        let dir = std::env::temp_dir().join(format!("sipp-rs-errors-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("e.log").to_string_lossy().into_owned();
        let mut log = Log { errors: Sink::new(path.clone(), "errors", true), ..Default::default() };
        log.warning("not traced");
        log.trace("error", true);
        log.warning("one");
        log.trace("error", false);
        log.warning("off");
        log.trace("error", true);
        log.warning("two");
        let text = read(&path);
        let lines: Vec<&str> = text.lines().map(|l| l.rsplit(": ").next().unwrap()).collect();
        assert_eq!(lines, ["The following events occurred:", "one", "The following events occurred:", "two"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_fatal_error_shown_is_not_printed_again() {
        let mut log = Log::default();
        log.error("fatal");
        assert!(log.shown);
        // A later warning is the last error print_errors() shows.
        log.warning("then this");
        assert!(!log.shown);
    }

    #[test]
    fn civil_dates() {
        assert_eq!(super::civil(0), (1970, 1, 1));
        assert_eq!(super::civil(20723), (2026, 9, 27));
        let d = super::http_date();
        assert!(d.ends_with(" GMT") && d.len() == "Sun, 27 Sep 2026 12:34:56 GMT".len(), "{d}");
    }
}

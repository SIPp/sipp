//! -inf injection files: per-call lines of ';'-separated fields.

#[derive(Debug, PartialEq)]
enum Order {
    Sequential,
    Random,
    /// USERS: a -users user's own line, the user's number less one.
    User,
}

#[derive(Debug)]
pub struct InFile {
    /// The file as -inf named it, for FileContents' warnings.
    name: String,
    lines: Vec<String>,
    order: Order,
    /// PRINTF=n: n virtual lines, where %d expands to offset + line * multiple.
    printf: Option<(usize, i64, i64)>,
    counter: usize,
    /// -infindex: the field lines are looked up by, and each key's line.
    index_field: Option<usize>,
    index: std::collections::HashMap<String, usize>,
}

/// A header option, as FileContents reads it: the whole `key` (PRINTF is
/// not the start of PRINTFOFFSET), then '=' and a number ending the
/// header or before a ','.
fn option(name: &str, header: &str, key: &str) -> Result<Option<u64>, String> {
    let mut from = 0;
    let at = loop {
        let Some(at) = header[from..].find(key).map(|at| from + at) else { return Ok(None) };
        if !header.as_bytes().get(at + key.len()).is_some_and(u8::is_ascii_alphanumeric) {
            break at;
        }
        from = at + key.len();
    };
    let Some(value) = header[at + key.len()..].strip_prefix('=') else {
        return Err(format!("Invalid {key} specification (requires =) for {name}:{header}"));
    };
    let (n, rest) = crate::posix::strtoul(value);
    match rest.chars().next() {
        None | Some(',') => Ok(Some(n)),
        Some(c) => Err(format!("Invalid {key} specification (invalid end character '{c}') for {name}:{header}")),
    }
}

impl InFile {
    /// SIPp's FileContents: a header line naming the order, then data lines;
    /// '#' lines are comments and an empty line ends the data.
    pub fn parse(name: &str, text: &str) -> Result<InFile, String> {
        let mut lines = text.lines();
        let header = lines.next().unwrap_or("").trim_end_matches('\r');
        let order = if header.contains("RANDOM") {
            Order::Random
        } else if header.contains("SEQUENTIAL") {
            Order::Sequential
        } else if header.contains("USER") {
            Order::User
        } else {
            return Err(format!("Unknown file type (valid values are RANDOM, SEQUENTIAL, and USER) for {name}:{header}"));
        };
        let lines_n = option(name, header, "PRINTF")?;
        if lines_n == Some(0) {
            return Err(format!("A printf file must have at least one virtual line {name}:{header}"));
        }
        let offset = option(name, header, "PRINTFOFFSET")?.unwrap_or(0) as i64;
        let multiple = option(name, header, "PRINTFMULTIPLE")?.unwrap_or(1) as i64;
        let printf = lines_n.map(|n| (n as usize, offset, multiple));
        let lines: Vec<String> = lines
            .map(|l| l.trim_end_matches('\r'))
            .take_while(|l| !l.is_empty())
            .filter(|l| !l.starts_with('#'))
            .map(str::to_string)
            .collect();
        if lines.is_empty() {
            return Err(format!("Input file has zero lines: {name}"));
        }
        Ok(InFile { name: name.to_string(), lines, order, printf, counter: 0, index_field: None, index: Default::default() })
    }

    /// Lines, the virtual ones of a PRINTF file included.
    pub fn lines(&self) -> usize {
        self.len()
    }

    fn len(&self) -> usize {
        self.printf.map_or(self.lines.len(), |(n, ..)| n)
    }

    /// The line a new call gets; a USERS file has none for a call without
    /// a user (usize::MAX, whose fields are empty). One that does not
    /// `advance` (an <init>) leaves a SEQUENTIAL file's line to the next.
    pub fn next_line(&mut self, name: &str, random: u32, user: u32, advance: bool) -> Result<usize, String> {
        Ok(match self.order {
            Order::Random => random as usize % self.len(),
            Order::Sequential => {
                let line = self.counter;
                if advance {
                    self.counter = (self.counter + 1) % self.len();
                }
                line
            }
            Order::User if user == 0 => usize::MAX,
            Order::User if user as usize > self.len() => {
                return Err(format!("{name} has only {} lines, yet user {user} was requested.", self.len()));
            }
            Order::User => user as usize - 1,
        })
    }

    /// -infindex: look lines up by this field, the last line with a key
    /// winning.
    pub fn build_index(&mut self, field: usize) {
        self.index_field = Some(field);
        self.index.clear();
        for line in 0..self.lines.len() {
            self.reindex(line);
        }
    }

    fn reindex(&mut self, line: usize) {
        if let Some(f) = self.index_field {
            let key = self.field(line, f);
            self.index.insert(key, line);
        }
    }

    fn deindex(&mut self, line: usize) {
        if let Some(f) = self.index_field {
            let key = self.field(line, f);
            if self.index.get(&key) == Some(&line) {
                self.index.remove(&key);
            }
        }
    }

    /// <lookup>: the line whose indexed field is `key`, -1 for none.
    pub fn lookup(&self, name: &str, key: &str) -> Result<f64, String> {
        if self.index_field.is_none() {
            return Err(format!("Invalid Index File: {name}"));
        }
        Ok(self.index.get(key).map_or(-1.0, |&l| l as f64))
    }

    /// <insert>: a new line at the end.
    pub fn insert(&mut self, name: &str, value: &str) -> Result<(), String> {
        if self.printf.is_some() {
            return Err(format!("Can not insert or replace into a printf file: {name}"));
        }
        self.lines.push(value.to_string());
        self.reindex(self.lines.len() - 1);
        Ok(())
    }

    /// <replace>: a line's new text.
    pub fn replace(&mut self, name: &str, line: i64, value: &str) -> Result<(), String> {
        if self.printf.is_some() {
            return Err(format!("Can not insert or replace into a printf file: {name}"));
        }
        if line < 0 || line as usize >= self.lines.len() {
            return Err(format!("Invalid line number ({line}) for file: {name} ({} lines)", self.lines.len()));
        }
        let line = line as usize;
        self.deindex(line);
        self.lines[line] = value.to_string();
        self.reindex(line);
        Ok(())
    }

    /// [fieldN]: the Nth ';'-separated field of a line, "" when it has
    /// none, which FileContents::getField() warns of (not of a line that
    /// isn't there).
    pub fn field(&self, line: usize, n: usize) -> String {
        if line >= self.len() {
            return String::new();
        }
        let text = &self.lines[line % self.lines.len()];
        let Some(value) = text.split(';').nth(n) else {
            crate::log::defer_warning(format!("Field {n} not found in the file {}", self.name));
            return String::new();
        };
        match self.printf {
            Some((_, offset, multiple)) => expand(value, offset + line as i64 * multiple),
            None => value.to_string(),
        }
    }
}

/// All -inf files; [fieldN] without file= reads the first one.
#[derive(Debug, Default)]
pub struct Injection {
    files: Vec<(String, InFile)>,
}

impl Injection {
    pub fn add(&mut self, name: String, file: InFile) {
        self.files.push((name, file));
    }

    pub fn get(&self, name: &str) -> Option<&InFile> {
        self.files.iter().find(|(n, _)| n == name).map(|(_, f)| f)
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut InFile> {
        self.files.iter_mut().find(|(n, _)| n == name).map(|(_, f)| f)
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.files.iter().map(|(n, _)| n.as_str())
    }

    pub fn default_name(&self) -> Option<&str> {
        self.files.first().map(|(n, _)| n.as_str())
    }

    /// Each file's line for a new call of `user` (0 for none), which an
    /// <init> reads without taking it (`advance` false).
    pub fn assign(&mut self, user: u32, mut random: impl FnMut() -> u32, advance: bool) -> Result<std::collections::HashMap<String, usize>, String> {
        self.files.iter_mut().map(|(n, f)| Ok((n.clone(), f.next_line(n, random(), user, advance)?))).collect()
    }
}

/// PRINTF fields: each %[-][0][width][.precision]d becomes the number.
fn expand(field: &str, value: i64) -> String {
    let mut out = String::new();
    let mut rest = field;
    while let Some(pos) = rest.find('%') {
        out += &rest[..pos];
        let spec = &rest[pos + 1..];
        let end = spec.find(|c: char| !(c.is_ascii_digit() || c == '-' || c == '.')).unwrap_or(spec.len());
        if !spec[end..].starts_with('d') {
            out.push('%');
            rest = spec;
            continue;
        }
        let (flags, width_prec) = spec[..end].split_at(spec[..end].find(|c: char| c != '-' && c != '0').unwrap_or(end));
        let (width, precision) = match width_prec.split_once('.') {
            Some((w, p)) => (w.parse().unwrap_or(0), Some(p.parse().unwrap_or(0))),
            None => (width_prec.parse().unwrap_or(0), None),
        };
        let digits = match precision {
            Some(p) => format!("{:0p$}", value.unsigned_abs(), p = p),
            None => value.unsigned_abs().to_string(),
        };
        let num = if value < 0 { format!("-{digits}") } else { digits };
        let padded = if flags.contains('-') {
            format!("{num:<width$}")
        } else if flags.contains('0') && precision.is_none() {
            let sign = if value < 0 { "-" } else { "" };
            format!("{sign}{:0>w$}", num.trim_start_matches('-'), w = width.saturating_sub(sign.len()))
        } else {
            format!("{num:>width$}")
        };
        out += &padded;
        rest = &spec[end + 1..];
    }
    out + rest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_lookup_insert_replace() {
        let mut f = InFile::parse("u.csv", "SEQUENTIAL\nalice;1\nbob;2\nalice;3\n").unwrap();
        assert!(f.lookup("u.csv", "bob").is_err());
        f.build_index(0);
        assert_eq!(f.lookup("u.csv", "alice"), Ok(2.0));
        assert_eq!(f.lookup("u.csv", "bob"), Ok(1.0));
        assert_eq!(f.lookup("u.csv", "carol"), Ok(-1.0));
        f.insert("u.csv", "carol;4").unwrap();
        assert_eq!(f.lookup("u.csv", "carol"), Ok(3.0));
        f.replace("u.csv", 1, "dave;5").unwrap();
        assert_eq!((f.lookup("u.csv", "bob"), f.lookup("u.csv", "dave")), (Ok(-1.0), Ok(1.0)));
        assert_eq!(f.field(1, 1), "5");
        assert!(f.replace("u.csv", 9, "x").is_err());
    }

    #[test]
    fn an_init_reads_the_first_calls_line_without_taking_it() {
        let mut f = InFile::parse("u.csv", "SEQUENTIAL\none;\ntwo;\n").unwrap();
        assert_eq!(f.next_line("u.csv", 0, 0, false), Ok(0));
        assert_eq!((f.next_line("u.csv", 0, 0, true), f.next_line("u.csv", 0, 0, true)), (Ok(0), Ok(1)));
    }

    #[test]
    fn sequential_fields_comments_and_end() {
        let mut f = InFile::parse("u.csv", "SEQUENTIAL\n#comment\nalice;secret;\nbob;pw\n\nignored;x\n").unwrap();
        let mut next = || f.next_line("u.csv", 0, 0, true).unwrap();
        assert_eq!((next(), next(), next()), (0, 1, 0));
        assert_eq!((f.field(0, 0), f.field(0, 1), f.field(0, 2)), ("alice".into(), "secret".into(), "".into()));
        assert_eq!(f.field(1, 1), "pw");
        assert!(InFile::parse("e.csv", "SEQUENTIAL\n").is_err());
        assert_eq!(
            InFile::parse("x.csv", "WHATEVER\na\n").unwrap_err(),
            "Unknown file type (valid values are RANDOM, SEQUENTIAL, and USER) for x.csv:WHATEVER"
        );
        let err = |h: &str| InFile::parse("p.csv", &format!("{h}\na\n")).unwrap_err();
        assert_eq!(err("SEQUENTIAL,PRINTF"), "Invalid PRINTF specification (requires =) for p.csv:SEQUENTIAL,PRINTF");
        assert_eq!(err("SEQUENTIAL,PRINTF=0"), "A printf file must have at least one virtual line p.csv:SEQUENTIAL,PRINTF=0");
        assert_eq!(
            err("SEQUENTIAL,PRINTF=2,PRINTFMULTIPLE=3x"),
            "Invalid PRINTFMULTIPLE specification (invalid end character 'x') for p.csv:SEQUENTIAL,PRINTF=2,PRINTFMULTIPLE=3x"
        );
    }

    #[test]
    fn printf_keys_match_whole() {
        // PRINTF is not the start of PRINTFOFFSET or PRINTFMULTIPLE, in
        // any order.
        let f = InFile::parse("p.csv", "SEQUENTIAL,PRINTFMULTIPLE=2,PRINTFOFFSET=100,PRINTF=10\nuser%d;\n").unwrap();
        assert_eq!((f.lines(), f.field(3, 0)), (10, "user106".to_string()));
        let err = InFile::parse("p.csv", "SEQUENTIAL,PRINTFOFFSET=1x\na\n").unwrap_err();
        assert_eq!(err, "Invalid PRINTFOFFSET specification (invalid end character 'x') for p.csv:SEQUENTIAL,PRINTFOFFSET=1x");
    }

    #[test]
    fn a_missing_field_is_warned_of() {
        // FileContents::getField(): a line without the field, not a line
        // that isn't there, and the file as -inf named it.
        let f = InFile::parse("dir/u.csv", "SEQUENTIAL\na;b\nc;d;\n").unwrap();
        let mut log = crate::log::Log::default();
        assert_eq!((f.field(0, 1), f.field(1, 2), f.field(5, 7)), ("b".into(), "".into(), "".into()));
        log.flush_deferred();
        assert_eq!(log.warnings, 0);
        assert_eq!(f.field(0, 2), "");
        log.flush_deferred();
        assert_eq!(log.warnings, 1);
        assert!(log.last_warning.as_deref().is_some_and(|w| w.ends_with(": Field 2 not found in the file dir/u.csv")));
    }

    #[test]
    fn printf_files_match_printf() {
        let f = InFile::parse("p.csv", "SEQUENTIAL,PRINTF=100,PRINTFOFFSET=1000\n<%d>;<%5d>;<%-5d>;<%05d>;<%.3d>;<%8.3d>;<%-8.3d>;<%-05d>;50%\n").unwrap();
        let fields: Vec<String> = (0..9).map(|n| f.field(42, n)).collect();
        assert_eq!(fields, ["<1042>", "< 1042>", "<1042 >", "<01042>", "<1042>", "<    1042>", "<1042    >", "<1042 >", "50%"]);
        assert_eq!(f.field(100, 0), "");
    }
}

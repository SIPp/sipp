//! -tdmmap {x0-x1}{h}{y0-y1}{z0-z1}: a table of TDM circuits, one for
//! each call while it runs, named by [tdmmap] and shown on screen 5.

pub struct TdmMap {
    a: i64,
    x: i64,
    h: i64,
    b: i64,
    y: i64,
    c: i64,
    z: i64,
    used: Vec<bool>,
}

impl Default for TdmMap {
    /// SIPp's screen without -tdmmap: one circuit, never used.
    fn default() -> TdmMap {
        TdmMap { a: 0, x: 0, h: 0, b: 0, y: 0, c: 0, z: 0, used: vec![false] }
    }
}

/// sscanf()'s %d: an optional sign and digits, after any blanks.
fn int(s: &mut &str) -> Option<i64> {
    let t = s.trim_start();
    let end = t.char_indices().find(|&(i, ch)| !(ch.is_ascii_digit() || (i == 0 && (ch == '-' || ch == '+')))).map_or(t.len(), |(i, _)| i);
    let v = t[..end].parse().ok()?;
    *s = &t[end..];
    Some(v)
}

fn lit(s: &mut &str, c: char) -> Option<()> {
    *s = s.strip_prefix(c)?;
    Some(())
}

impl TdmMap {
    /// "{%d-%d}{%d}{%d-%d}{%d-%d}".
    pub fn parse(arg: &str) -> Result<TdmMap, String> {
        let bad = || "Parameter -tdmmap must be of form {%d-%d}{%d}{%d-%d}{%d-%d}".to_string();
        let mut s = arg;
        let mut n = [0i64; 7];
        let mut read = || -> Option<()> {
            let s = &mut s;
            lit(s, '{')?;
            n[0] = int(s)?;
            lit(s, '-')?;
            n[1] = int(s)?;
            lit(s, '}')?;
            lit(s, '{')?;
            n[2] = int(s)?;
            lit(s, '}')?;
            for k in [3, 5] {
                lit(s, '{')?;
                n[k] = int(s)?;
                lit(s, '-')?;
                n[k + 1] = int(s)?;
                lit(s, '}')?;
            }
            Some(())
        };
        read().ok_or_else(bad)?;
        let (a, b, c) = (n[1] - n[0], n[4] - n[3], n[6] - n[5]);
        let circuits = (a + 1) * (b + 1) * (c + 1);
        if a < 0 || b < 0 || c < 0 || circuits > 1 << 20 {
            return Err(bad());
        }
        Ok(TdmMap { a, x: n[0], h: n[2], b, y: n[3], c, z: n[5], used: vec![false; circuits as usize] })
    }

    /// get_tdm_map_number(): a free circuit from a random one on, numbered
    /// from 1, or None when all are busy.
    pub fn take(&mut self, random: u32) -> Option<usize> {
        let interval = self.used.len() as u32;
        let random = random % interval;
        let at = (0..interval).map(|i| ((random + i) % interval) as usize).find(|&i| !self.used[i])?;
        self.used[at] = true;
        Some(at + 1)
    }

    pub fn give_back(&mut self, number: usize) {
        if let Some(u) = number.checked_sub(1).and_then(|i| self.used.get_mut(i)) {
            *u = false;
        }
    }

    /// [tdmmap] for a call's circuit number.
    pub fn name(&self, n: usize) -> String {
        let n = n as i64;
        format!(
            "{}.{}.{}/{}",
            self.x + (n / ((self.b + 1) * (self.c + 1))) % (self.a + 1),
            self.h,
            self.y + (n / (self.c + 1)) % (self.b + 1),
            self.z + n % (self.c + 1)
        )
    }

    /// draw_tdm_screen(), padded for a scenario of `steps` messages.
    pub fn screen(&self, steps: usize) -> Vec<String> {
        let mut l = vec!["TDM Circuits in use:".to_string()];
        let width = (self.c + 1) as usize;
        let height = ((self.a + 1) * (self.b + 1)) as usize;
        let mut buf = [0u8; 80];
        for (i, &used) in self.used.iter().enumerate() {
            let pos = (i % width).min(79);
            buf[pos] = if used { b'*' } else { b'.' };
            if pos == width - 1 {
                let end = buf.iter().position(|&c| c == 0).unwrap_or(80);
                l.push(String::from_utf8_lossy(&buf[..end]).into_owned());
                buf = [0; 80];
            }
        }
        l.push(String::new());
        let in_use = self.used.iter().filter(|&&u| u).count();
        let total = self.used.len();
        let line = format!("{in_use}/{total} circuits ({}%) in use", 100 * in_use / total);
        l.push(line.chars().take(79).collect());
        for _ in height..steps + 8 {
            l.push(String::new());
        }
        l
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circuits_as_sipp() {
        let mut m = TdmMap::parse("{0-3}{99}{5-8}{1-31}").unwrap();
        assert_eq!(m.used.len(), 4 * 4 * 31);
        assert_eq!(m.name(1), "0.99.5/2");
        assert_eq!(m.name(31), "0.99.6/1");
        assert!(TdmMap::parse("{0-3}{99}{5-8}").is_err());
        let mut two = TdmMap::parse("{0-0}{1}{0-0}{0-1}").unwrap();
        let (p, q) = (two.take(0).unwrap(), two.take(0).unwrap());
        assert_ne!(p, q);
        assert_eq!(two.take(7), None);
        two.give_back(p);
        assert_eq!(two.take(3), Some(p));
        let screen = m.screen(3);
        assert_eq!(screen[1], ".".repeat(31));
        assert_eq!(screen[18], "0/496 circuits (0%) in use");
        m.take(0);
        assert!(m.screen(3)[1..17].iter().any(|l| l.contains('*')));
    }

    #[test]
    fn search_from_zero_tries_the_last_circuit() {
        // Three circuits, the last one free: found from any start.
        let mut three = TdmMap::parse("{0-0}{1}{0-0}{0-2}").unwrap();
        assert_eq!(three.take(0), Some(1));
        assert_eq!(three.take(0), Some(2));
        assert_eq!(three.take(0), Some(3));
        three.give_back(3);
        assert_eq!(three.take(3), Some(3));
    }
}

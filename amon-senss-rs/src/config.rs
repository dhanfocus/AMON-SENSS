//! `amonsenss.config` parsing (`parse_config()` in the original).

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::cnum::strtod;

/// Name/value parameters. Missing names read as `0`, exactly like
/// `std::map::operator[]` did in the original.
///
/// Note: the original code looked up `num_std` while the shipped config file
/// (and `autoconfig`) call the parameter `numstd`, so in practice the value
/// was always 0. This port keeps that lookup so alerts stay identical.
#[derive(Clone, Debug, Default)]
pub struct Params {
    values: BTreeMap<String, f64>,
    pub interval: f64,
    pub file_interval: f64,
    pub attack_low: f64,
    pub attack_high: f64,
    pub min_train: f64,
    pub num_std: f64,
    pub filter_thresh: f64,
    pub min_oci: f64,
}

impl Params {
    pub fn from_pairs<'a>(pairs: impl IntoIterator<Item = (&'a str, f64)>) -> Params {
        let mut p = Params::default();
        for (k, v) in pairs {
            p.values.entry(k.to_string()).or_insert(v);
        }
        p.refresh();
        p
    }

    fn refresh(&mut self) {
        self.interval = self.get("interval");
        self.file_interval = self.get("file_interval");
        self.attack_low = self.get("attack_low");
        self.attack_high = self.get("attack_high");
        self.min_train = self.get("min_train");
        self.num_std = self.get("num_std");
        self.filter_thresh = self.get("filter_thresh");
        self.min_oci = self.get("min_oci");
    }

    pub fn get(&self, name: &str) -> f64 {
        self.values.get(name).copied().unwrap_or(0.0)
    }

    /// Parse a config file. Lines starting with `#` and empty lines are
    /// skipped; the value runs from `=` to the first space or newline. The
    /// first occurrence of a name wins.
    pub fn load(path: &Path) -> std::io::Result<Params> {
        let file = File::open(path)?;
        print!("Reading config file {} ...", path.display());
        let mut pairs: Vec<(String, f64)> = Vec::new();
        for line in BufReader::new(file).split(b'\n') {
            let mut line = line?;
            line.push(b'\n');
            if let Some((name, value)) = parse_line(&line) {
                println!("Parm {name} val {value}");
                pairs.push((name, strtod(&value)));
            }
        }
        Ok(Params::from_pairs(
            pairs.iter().map(|(k, v)| (k.as_str(), *v)),
        ))
    }
}

/// One line of the config file, following the original character loop.
fn parse_line(buf: &[u8]) -> Option<(String, String)> {
    if buf.first() == Some(&b'\n') || buf.first() == Some(&b'#') {
        return None;
    }
    let mut name: &[u8] = b"";
    let mut found: Option<usize> = None;
    let mut end = buf.len();
    for (i, &c) in buf.iter().enumerate() {
        if c == b'=' {
            name = &buf[..i];
            found = Some(i);
        } else if (c == b' ' || c == b'\n') && found.is_some() {
            end = i;
            break;
        }
    }
    let found = found?;
    let value = &buf[found + 1..end.max(found + 1)];
    let trim = |b: &[u8]| String::from_utf8_lossy(b).trim().to_string();
    Some((trim(name), trim(value)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines() {
        assert_eq!(
            parse_line(b"interval=3\n"),
            Some(("interval".into(), "3".into()))
        );
        assert_eq!(
            parse_line(b" min_oci = 1000\n"),
            Some(("min_oci".into(), "".into()))
        );
        assert_eq!(
            parse_line(b"min_oci=1000 # c\n"),
            Some(("min_oci".into(), "1000".into()))
        );
        assert_eq!(parse_line(b"# comment\n"), None);
        assert_eq!(parse_line(b"\n"), None);
        assert_eq!(parse_line(b"novalue\n"), None);
    }

    #[test]
    fn missing_is_zero_and_first_wins() {
        let p = Params::from_pairs([("interval", 3.0), ("interval", 9.0), ("numstd", 5.0)]);
        assert_eq!(p.interval, 3.0);
        assert_eq!(p.num_std, 0.0);
        assert_eq!(p.get("nothing"), 0.0);
    }
}

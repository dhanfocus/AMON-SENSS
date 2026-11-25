//! Saving and loading of trained statistics (`as.dump`), in the same text
//! format as the original so dumps can be exchanged between the two.
//!
//! Format: a header line `numattack BRICK_FINAL`, then one line per
//! (period, layer, bin, dimension): `t index i j n avg ss`, with the numbers
//! written like C++ `ostream << double` (6 significant digits).

use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use crate::cnum::fmt_g;
use crate::consts::NUMB;
use crate::detector::{Detector, AVG, CUR, HIST, N, SS, SYM, VOL};

impl Detector {
    /// `save_history()`. Only writes once training has completed.
    pub fn save_history(&self, path: &Path) -> io::Result<()> {
        if !self.training_done || self.layers.is_empty() {
            return Ok(());
        }
        let mut out = BufWriter::new(File::create(path)?);
        writeln!(out, "{} {}", self.numattack, self.brick_final)?;
        for (index, l) in self.layers.iter().enumerate() {
            for t in [CUR, HIST] {
                for i in 0..l.size {
                    for j in [VOL, SYM] {
                        writeln!(
                            out,
                            "{t} {index} {i} {j} {} {} {}",
                            fmt_g(l.stats[t][N][j][i]),
                            fmt_g(l.stats[t][AVG][j][i]),
                            fmt_g(l.stats[t][SS][j][i])
                        )?;
                    }
                }
            }
        }
        out.flush()
    }

    /// `load_history()`. Returns `Ok(false)` if the file does not exist.
    ///
    /// As in the original, the big-hitter table is not part of the dump, so
    /// the bins are re-allocated (and the loaded statistics dropped) when the
    /// big-hitter phase completes; what survives is the attack counter and
    /// the "training done" state.
    pub fn load_history(&mut self, path: &Path) -> io::Result<bool> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };
        let mut lines = BufReader::new(file).lines();
        let header = lines.next().transpose()?.unwrap_or_default();
        let mut it = header.split_ascii_whitespace();
        let bad =
            |what: &str| io::Error::new(io::ErrorKind::InvalidData, format!("as.dump: bad {what}"));
        self.numattack = it
            .next()
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| bad("header"))?;
        self.brick_final = it
            .next()
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| bad("header"))?;
        self.allocate_layers();
        for line in lines {
            let line = line?;
            let v: Vec<&str> = line.split_ascii_whitespace().collect();
            if v.is_empty() {
                continue;
            }
            if v.len() < 7 {
                return Err(bad("record"));
            }
            let idx = |k: usize| v[k].parse::<usize>().map_err(|_| bad("index"));
            let num = |k: usize| v[k].parse::<f64>().map_err(|_| bad("value"));
            let (t, index, i, j) = (idx(0)?, idx(1)?, idx(2)?, idx(3)?);
            if t > HIST || index >= NUMB || j > SYM || i >= self.layers[index].size {
                return Err(bad("index"));
            }
            let l = &mut self.layers[index];
            l.stats[t][N][j][i] = num(4)?;
            l.stats[t][AVG][j][i] = num(5)?;
            l.stats[t][SS][j][i] = num(6)?;
        }
        self.training_done = true;
        println!("Training data loaded");
        Ok(true)
    }
}

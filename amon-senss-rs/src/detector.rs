//! The AMON-SENSS detection engine: binning of flows into layered "databricks",
//! per-bin running statistics, CUSUM-based anomaly detection, and signature
//! selection for detected attacks.
//!
//! This is a faithful port of `amonsenss.cc`. Function names follow the
//! original (`amonProcessing` -> [`Detector::amon_processing`] and so on) so the
//! two can be read side by side. Integer widths, truncations and loop bounds
//! are kept as they were, because they affect which alerts are produced.
//!
//! Differences from the original are limited to:
//! * processing is single-threaded: the per-interval work that the original
//!   ran on a detached thread now runs synchronously at the interval boundary
//!   (the semantics the original intended, minus its data races);
//! * memory is always zero-initialised (the original relied on `malloc`
//!   returning zeroed pages);
//! * out-of-bounds accesses are clamped instead of reading garbage.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use crate::cnum::{cvt_i32, cvt_i64};
use crate::config::Params;
use crate::consts::*;
use crate::flow::{better_sig, Flow};
use crate::net::{is_special, LocalPrefixes, Services};

// Indices into `Layer::stats`: [period][type][dim].
pub(crate) const CUR: usize = 0;
pub(crate) const HIST: usize = 1;
pub(crate) const N: usize = 0;
pub(crate) const AVG: usize = 1;
pub(crate) const SS: usize = 2;
pub(crate) const VOL: usize = 0;
pub(crate) const SYM: usize = 1;

/// One candidate signature tracked for a bin (Boyer-Moore style majority vote).
#[derive(Clone, Copy, Debug)]
struct Slot {
    flow: Flow,
    len: i32,
    oci: i32,
}

impl Slot {
    const ZERO: Slot = Slot {
        flow: Flow::ZERO,
        len: 0,
        oci: 0,
    };
    const CLEARED: Slot = Slot {
        flow: Flow {
            src: 0,
            sport: -1,
            dst: 0,
            dport: -1,
            proto: 255,
            flags: 0,
            slocal: false,
            dlocal: false,
        },
        len: 0,
        oci: 0,
    };
}

/// Installed signature for a bin and how many flows have matched it.
#[derive(Clone, Copy, Debug)]
struct Signature {
    sig: Flow,
    nm: i32,
}

#[derive(Clone, Copy, Debug, Default)]
struct ShuffleCell {
    index: i32,
    len: u32,
    oci: u32,
}

/// All per-bin state of one layer.
pub(crate) struct Layer {
    pub(crate) size: usize,
    // Current-interval counters (the "cell").
    p: Vec<i64>,
    s: Vec<f64>,
    sent: Vec<i64>,
    rec: Vec<i64>,
    wf_p: Vec<u32>,
    wf_s: Vec<i32>,
    // Long-lived per-bin state.
    sigs: Vec<Signature>,
    samples: Vec<[Slot; NSLOTS]>,
    is_abnormal: Vec<i32>,
    is_attack: Vec<bool>,
    detection_time: Vec<u64>,
    pub(crate) stats: [[[Vec<f64>; 2]; 3]; 2],
    cusum: [Vec<f64>; 2],
    /// Bins that have had `is_attack` set since they were last pruned. Only
    /// used to speed up the cross-layer check in `print_alert`.
    attack_list: Vec<usize>,
    in_attack_list: Vec<bool>,
}

impl Layer {
    pub(crate) fn new(size: usize) -> Layer {
        let zf = || vec![0f64; size];
        Layer {
            size,
            p: vec![0; size],
            s: zf(),
            sent: vec![0; size],
            rec: vec![0; size],
            wf_p: vec![0; size],
            wf_s: vec![0; size],
            sigs: vec![
                Signature {
                    sig: Flow::ZERO,
                    nm: 0
                };
                size
            ],
            samples: vec![[Slot::ZERO; NSLOTS]; size],
            is_abnormal: vec![0; size],
            is_attack: vec![false; size],
            detection_time: vec![0; size],
            stats: std::array::from_fn(|_| std::array::from_fn(|_| [zf(), zf()])),
            cusum: [zf(), zf()],
            attack_list: Vec::new(),
            in_attack_list: vec![false; size],
        }
    }

    fn zero_cell(&mut self) {
        self.p.fill(0);
        self.s.fill(0.0);
        self.sent.fill(0);
        self.rec.fill(0);
        self.wf_p.fill(0);
        self.wf_s.fill(0);
    }

    fn set_attack(&mut self, i: usize) {
        self.is_attack[i] = true;
        if !self.in_attack_list[i] {
            self.in_attack_list[i] = true;
            self.attack_list.push(i);
        }
    }

    fn std(&self, period: usize, dim: usize, i: usize) -> f64 {
        (self.stats[period][SS][dim][i] / (self.stats[period][N][dim][i] - 1.0)).sqrt()
    }

    /// Is there a bin `j < limit` under attack whose signature targets `dst`?
    fn has_attack_on(&mut self, dst: u32, limit: usize) -> bool {
        let mut k = 0;
        let mut found = false;
        while k < self.attack_list.len() {
            let j = self.attack_list[k];
            if !self.is_attack[j] {
                self.in_attack_list[j] = false;
                self.attack_list.swap_remove(k);
                continue;
            }
            if !found && j < limit && !self.sigs[j].sig.is_empty() && self.sigs[j].sig.dst == dst {
                found = true;
            }
            k += 1;
        }
        found
    }
}

/// The detector and all of its global state.
pub struct Detector {
    pub params: Params,
    pub services: Services,
    pub prefixes: LocalPrefixes,
    /// `-f`: install signatures and simulate filtering. Without it no alert is printed.
    pub sim_filter: bool,
    pub verbose: bool,
    /// Where alerts are appended.
    pub alerts_path: PathBuf,
    /// Command run when the alerts file exceeds 10 MB.
    pub rotate_cmd: PathBuf,
    rotate_warned: bool,

    memshuffle: BTreeMap<u32, ShuffleCell>,
    max_shufflelen: u32,
    max_shuffleoci: u32,
    shuffled: i32,
    shuffle_index: i32,
    pub shuffle_done: bool,
    pub brick_final: i32,
    pub(crate) layers: Vec<Layer>,

    pub training_done: bool,
    pub numattack: i32,

    pub curtime: f64,
    pub lasttime: f64,
    pub firsttime: f64,
    pub firsttimeinfile: f64,
    votedtime: i64,
    votes: i32,

    // Counters kept for parity with the original; not used for detection.
    pub malformed_flows: u64,
    pub local_flows: u64,
    pub nonlocal_flows: u64,
    pub processed_bytes: i64,
}

impl Detector {
    pub fn new(params: Params, services: Services, prefixes: LocalPrefixes) -> Detector {
        Detector {
            params,
            services,
            prefixes,
            sim_filter: false,
            verbose: false,
            alerts_path: PathBuf::from("alerts.txt"),
            rotate_cmd: PathBuf::from("./rotate"),
            rotate_warned: false,
            memshuffle: BTreeMap::new(),
            max_shufflelen: 0,
            max_shuffleoci: 0,
            shuffled: 0,
            shuffle_index: 0,
            shuffle_done: false,
            brick_final: 0,
            layers: Vec::new(),
            training_done: false,
            numattack: 0,
            curtime: 0.0,
            lasttime: 0.0,
            firsttime: 0.0,
            firsttimeinfile: 0.0,
            votedtime: 0,
            votes: 0,
            malformed_flows: 0,
            local_flows: 0,
            nonlocal_flows: 0,
            processed_bytes: 0,
        }
    }

    /// Size of layer `index` for a given `BRICK_FINAL`.
    pub(crate) fn layer_size(brick_final: i32, index: usize) -> usize {
        (brick_final.max(0) as usize) + index * LAYER_SKEW * NUMF
    }

    /// `malloc_all()` for every layer.
    pub(crate) fn allocate_layers(&mut self) {
        let bf = self.brick_final;
        self.layers = (0..NUMB)
            .map(|i| Layer::new(Self::layer_size(bf, i)))
            .collect();
    }

    fn svc(&self, port: i16) -> bool {
        self.services.contains(port as i32)
    }

    pub fn is_local(&self, ip: u32) -> bool {
        self.prefixes.contains(ip)
    }

    /// `myhash()`: map an address/port to a bin for the given way.
    fn myhash(&self, ip: u32, port: u16, way: usize, bricku: u32) -> usize {
        if let Some(c) = self.memshuffle.get(&ip) {
            let v = c.index as i64 + way as i64 * (self.shuffle_index as i64 + BRICK_UNIT as i64);
            return v as usize;
        }
        let s = self.shuffle_index as u32;
        let port = port as u32;
        let pref = ip & 0xffff_ff00;
        let w = way as u32;
        let v = match way {
            LHOST => ip % bricku + s,
            LPREF => pref % bricku + bricku + 2 * s,
            FPORT | LPORT => port % bricku + w * bricku + (w + 1) * s,
            LHFPORT | LHLPORT => ip.wrapping_add(port) % bricku + w * bricku + (w + 1) * s,
            LPFPORT | LPLPORT => pref.wrapping_add(port) % bricku + w * bricku + (w + 1) * s,
            LHSYN | LHSYNACK | LHACK | LHRST => ip % bricku + w * bricku + (w + 1) * s,
            LPSYN | LPSYNACK | LPACK | LPRST => pref % bricku + w * bricku + (w + 1) * s,
            _ => 0,
        };
        v as i32 as usize
    }

    /// `compliantsig()`: the signature must include the dimension along which
    /// the anomaly was found.
    fn compliant_sig(&self, i: usize, sig: &Flow) -> bool {
        let loc = if self.brick_final > 0 {
            i as i64 / self.brick_final as i64
        } else {
            -1
        };
        match loc {
            0 | 1 => sig.dst != 0 && (sig.dport != -1 || sig.sport != -1 || sig.proto == ICMP),
            2 | 4 | 5 => sig.dst != 0 && (sig.sport != -1 || sig.proto == ICMP),
            3 | 6 | 7 => sig.dst != 0 && (sig.dport != -1 || sig.proto == ICMP),
            8..=15 => sig.dst != 0 && sig.flags != 0,
            _ => false,
        }
    }

    fn clear_samples(&mut self, index: usize, id: usize) {
        self.layers[id].samples[index] = [Slot::CLEARED; NSLOTS];
    }

    /// `addSample()`: offer partial signatures of this flow to the bin's
    /// candidate slots.
    fn add_sample(&mut self, index: usize, f: &Flow, oci: i32, way: usize, id: usize) {
        let aoci = oci.wrapping_abs();
        for s in 1..(NF - 8) {
            let mut k = Flow {
                proto: f.proto,
                ..Flow::default()
            };
            if s & 8 != 0 {
                k.src = f.src;
            }
            if s & 4 != 0 && self.svc(f.sport) {
                k.sport = f.sport;
            }
            if s & 2 != 0 {
                k.dst = f.dst;
            }
            if s & 1 != 0 && self.svc(f.dport) {
                k.dport = f.dport;
            }
            if matches!(
                way,
                LHOST
                    | LPREF
                    | LHFPORT
                    | LHLPORT
                    | LPFPORT
                    | LPLPORT
                    | LHSYN
                    | LPSYN
                    | LHSYNACK
                    | LPSYNACK
                    | LHRST
                    | LPRST
            ) {
                k.dst = f.dst;
                if matches!(way, LPREF | LPFPORT | LPLPORT | LPSYN | LPSYNACK | LPRST) {
                    k.dst &= 0xffff_ff00;
                }
            }
            if matches!(way, FPORT | LHFPORT | LPFPORT) {
                k.sport = f.sport;
            }
            if matches!(way, LPORT | LHLPORT | LPLPORT) {
                k.dport = f.dport;
            }
            if way >= LHSYN {
                k.flags = f.flags;
            }

            let slot = &mut self.layers[id].samples[index][s - 1];
            if slot.flow.same_tuple(&k) {
                slot.len = slot.len.wrapping_add(aoci);
                slot.oci = slot.oci.wrapping_add(oci);
            } else if slot.flow.is_empty() {
                *slot = Slot {
                    flow: k,
                    len: aoci,
                    oci,
                };
            } else {
                slot.len = slot.len.wrapping_sub(aoci);
                if slot.len < 0 {
                    *slot = Slot {
                        flow: k,
                        len: aoci,
                        oci,
                    };
                }
            }
        }
    }

    /// `malformed()`: is this timestamp outside the range we expect for the
    /// current input file?
    fn malformed(&self, ts: f64) -> bool {
        let fi = self.params.file_interval;
        ts < self.firsttimeinfile - 2.0 * fi || (fi > 0.0 && ts > self.firsttimeinfile + 2.0 * fi)
    }

    /// `abnormal()`: CUSUM score of a bin's volume or symmetry, or 0.
    fn abnormal(&self, dim: usize, index: usize, id: usize) -> f64 {
        let l = &self.layers[id];
        let mean = l.stats[HIST][AVG][dim][index];
        let std = l.std(HIST, dim, index);
        let data = if dim == VOL {
            l.p[index] as f64
        } else {
            l.s[index]
        };
        let cur_avg = l.stats[CUR][AVG][dim][index];
        let data = cur_avg + (data - cur_avg) / (l.stats[CUR][N][dim][index] + 1.0);
        if l.stats[HIST][N][dim][index] < self.params.min_train * MIN_SAMPLES {
            return 0.0;
        }
        let mut tmp = l.cusum[dim][index] + data - mean - 3.0 * std;
        if tmp < 0.0 {
            tmp = 0.0;
        }
        let rto = tmp / (std + 1.0);
        if rto > 0.0 {
            rto
        } else {
            0.0
        }
    }

    /// `print_alert()`: write an alert line if all layers agree on the target.
    fn print_alert(&mut self, i: usize, na: i32, id: usize) {
        let brickf_print = (BRICK_UNIT + id * LAYER_SKEW) as i64;
        let (rate, roci, sig) = {
            let l = &self.layers[id];
            let avgv = l.stats[HIST][AVG][VOL][i];
            let stdv = l.std(HIST, VOL, i);
            let avgs = l.stats[HIST][AVG][SYM][i];
            let stds = l.std(HIST, SYM, i);
            let num_std = self.params.num_std;
            let rate = cvt_i64(l.p[i] as f64 - avgv - num_std * stdv);
            let roci = cvt_i64(l.s[i] - avgs - num_std * stds);
            (rate, roci, l.sigs[i].sig)
        };
        if (roci.wrapping_abs() as f64) < self.params.min_oci {
            return;
        }
        if sig.is_empty() {
            return;
        }

        let mut matched = 1;
        for y in 0..NUMB {
            if y == id {
                continue;
            }
            let limit = NUMF * (BRICK_UNIT + y * LAYER_SKEW);
            if self.layers[y].has_attack_on(sig.dst, limit) {
                matched += 1;
            }
        }

        if matched == NUMB {
            let line = format!(
                "{} {} {} START {} {} {} {}\n",
                na,
                i as i64 / brickf_print,
                cvt_i64(self.curtime),
                i,
                rate.wrapping_abs(),
                roci.wrapping_abs(),
                sig.signature()
            );
            match OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.alerts_path)
            {
                Ok(mut f) => {
                    if let Err(e) = f.write_all(line.as_bytes()) {
                        eprintln!("Could not write {}: {e}", self.alerts_path.display());
                    }
                }
                Err(e) => eprintln!("Could not open {}: {e}", self.alerts_path.display()),
            }
        }

        // Rotate the alerts file once it exceeds 10 MB.
        if fs::metadata(&self.alerts_path)
            .map(|m| m.len() > ROTATE_SIZE)
            .unwrap_or(false)
        {
            match Command::new(&self.rotate_cmd).status() {
                Ok(_) => {}
                Err(e) if !self.rotate_warned => {
                    eprintln!("Could not run {}: {e}", self.rotate_cmd.display());
                    self.rotate_warned = true;
                }
                Err(_) => {}
            }
        }
    }

    /// `alert_ready()`: enough flows matched the signature; decide whether
    /// filtering would have been effective and alert.
    fn alert_ready(&mut self, bucket: usize, id: usize) {
        let ok = {
            let l = &self.layers[id];
            let avgs = l.stats[HIST][AVG][SYM][bucket];
            let stds = l.std(HIST, SYM, bucket);
            let symf = l.wf_s[bucket].wrapping_abs() as f64;
            let mut symb = l.s[bucket].abs() - (avgs.abs() + self.params.num_std * stds.abs());
            if symb < 0.0 {
                symb = symf;
            }
            if symb == 0.0 {
                symb = 1.0;
            }
            symf / symb >= self.params.filter_thresh
        };
        if ok {
            let na = self.numattack;
            self.numattack = self.numattack.wrapping_add(1);
            self.print_alert(bucket, na, id);
        }
        let l = &mut self.layers[id];
        l.is_attack[bucket] = false;
        l.detection_time[bucket] = 0;
        self.clear_samples(bucket, id);
    }

    /// `checkReady()`.
    fn check_ready(&mut self, bucket: usize, id: usize) {
        let nm = self.layers[id].sigs[bucket].nm;
        if nm < MM {
            self.layers[id].sigs[bucket].nm = nm + 1;
            if nm + 1 == MM {
                self.alert_ready(bucket, id);
            }
        }
    }

    /// `shouldFilter()`.
    fn should_filter(&self, bucket: usize, flow: &Flow, id: usize) -> bool {
        let sig = &self.layers[id].sigs[bucket].sig;
        !sig.is_empty() && flow.matches(sig)
    }

    /// `findBestSignature()`.
    fn find_best_signature(&mut self, ltime: f64, i: usize, id: usize) {
        let mut bestsig = Flow::default();
        let mut oci: i32 = 0;
        let totoci = self.layers[id].rec[i] as i32;
        let slots = self.layers[id].samples[i];
        for (k, slot) in slots.iter().enumerate() {
            let s = k + 1;
            if slot.flow.is_empty() {
                continue;
            }
            let candrate = (slot.oci as f64).abs();
            let ratio = candrate / totoci as f64;
            if !self.compliant_sig(i, &slot.flow) {
                if self.verbose {
                    println!(
                        "non compliant SIG: {i} for slot {s} candidate {} v={} o={} toto={totoci} candrate {candrate} divided {ratio}",
                        slot.flow.signature(),
                        slot.len,
                        slot.oci
                    );
                }
                continue;
            }
            if self.verbose {
                println!(
                    "SIG: {i} for slot {s} candidate {} v={} o={} toto={totoci} candrate {candrate} divided {ratio}",
                    slot.flow.signature(),
                    slot.len,
                    slot.oci
                );
            }
            if ratio > self.params.filter_thresh
                && (slot.oci as f64) > self.params.min_oci
                && better_sig(&slot.flow, &bestsig)
            {
                if self.verbose {
                    println!("SIG: changing to {}", slot.flow.signature());
                }
                bestsig = slot.flow;
                oci = cvt_i32(candrate);
            }
        }
        if self.verbose {
            println!(
                "SIG: {i} best sig {} Empty? {} oci 0 out of {totoci}",
                bestsig.signature(),
                bestsig.is_empty() as i32
            );
        }
        if !bestsig.is_empty() {
            if self.verbose {
                let l = &self.layers[id];
                println!(
                    "{ltime} ISIG: {i} volume {} oci {} installed sig {}",
                    l.p[i],
                    l.s[i],
                    bestsig.signature()
                );
            }
            if self.sim_filter {
                self.layers[id].sigs[i] = Signature {
                    sig: bestsig,
                    nm: 0,
                };
            }
            self.clear_samples(i, id);
        } else {
            if self.verbose {
                println!(
                    "AT: Did not find good signature for attack  on bin {i} best sig 1 coverage {} thresh {}",
                    oci as f32 / totoci as f32,
                    self.params.filter_thresh
                );
            }
            self.layers[id].is_attack[i] = false;
        }
    }

    /// `instant_detect()`: re-evaluate one bin right after it was updated.
    fn instant_detect(&mut self, ltime: f64, i: usize, id: usize) {
        {
            let l = &mut self.layers[id];
            l.s[i] = l.rec[i] as f64 / l.sent[i].wrapping_add(1) as f64;
        }
        if self.layers[id].is_attack[i] {
            return;
        }
        let a = self.abnormal(VOL, i, id);
        let b = self.abnormal(SYM, i, id);
        if !(self.training_done && a != 0.0 && b != 0.0) {
            return;
        }
        let attack_high = cvt_i32(self.params.attack_high);
        let attack_low = cvt_i32(self.params.attack_low);
        let score = {
            let l = &mut self.layers[id];
            let mut score = cvt_i32(a + b);
            if score > attack_high {
                score = attack_high;
            }
            l.is_abnormal[i] = score;
            score
        };
        if self.verbose && score != 0 {
            let l = &self.layers[id];
            println!(
                "{ltime:.6} id={id} abnormal for {i} points {score} oci {} ranges {}+-{}, vol {} ranges {}+-{} a {a} b {b} cusum thresh {}",
                l.s[i],
                l.stats[HIST][AVG][SYM][i],
                l.std(HIST, SYM, i),
                l.p[i],
                l.stats[HIST][AVG][VOL][i],
                l.std(HIST, VOL, i),
                self.params.get("cusum_thresh")
            );
        }
        if score >= attack_low && !self.layers[id].is_attack[i] {
            {
                let l = &mut self.layers[id];
                l.set_attack(i);
                l.detection_time[i] = ltime as u64;
            }
            if self.verbose {
                let l = &self.layers[id];
                println!(
                    "id={id} AT: Attack detected on {i} but not reported yet vol {} oci {} min oci {}",
                    l.p[i],
                    l.s[i],
                    cvt_i32(self.params.min_oci)
                );
            }
            self.find_best_signature(ltime, i, id);
        }
    }

    /// `shuffle()`: find big hitters before the bins are allocated.
    fn shuffle(&mut self, addr: u32, len: i32, oci: i32, curtime: u32) {
        let c = self.memshuffle.entry(addr).or_default();
        c.len = c.len.wrapping_add(len as u32);
        c.oci = c.oci.wrapping_add(oci as u32);
        let (clen, coci) = (c.len, c.oci);
        if clen > self.max_shufflelen {
            self.max_shufflelen = clen;
        }
        if coci > self.max_shuffleoci {
            self.max_shuffleoci = coci;
        }

        if self.memshuffle.len() > BRICK_UNIT {
            let lmin = self.max_shufflelen / FRACTION;
            let omin = self.max_shuffleoci / FRACTION;
            self.memshuffle
                .retain(|_, c| !(c.len < lmin && c.oci < omin));
            self.shuffled += 1;
            if self.shuffled > MAX_SHUFFLES && !self.shuffle_done {
                self.finish_shuffle();
            }
        }
        if curtime as f64 - self.firsttime >= self.params.min_train && !self.shuffle_done {
            self.finish_shuffle();
        }
    }

    fn finish_shuffle(&mut self) {
        self.shuffle_index = self.memshuffle.len() as i32;
        for (idx, c) in self.memshuffle.values_mut().enumerate() {
            c.index = idx as i32;
        }
        self.brick_final = self.shuffle_index.wrapping_mul(NUMF as i32) + BRICK_DIMENSION as i32;
        self.allocate_layers();
        self.shuffle_done = true;
        if self.verbose {
            println!(
                "Shuffle done: {} big hitters, {} bins in layer 0",
                self.shuffle_index, self.brick_final
            );
        }
    }

    fn add_in(&mut self, id: usize, b: usize, flow: &Flow, len: i32, oci: i32, way: usize) {
        {
            let l = &mut self.layers[id];
            l.p[b] = l.p[b].wrapping_add(len as i64);
            l.rec[b] = l.rec[b].wrapping_add(oci as i64);
        }
        self.add_sample(b, flow, oci, way, id);
        self.instant_detect(self.curtime, b, id);
    }

    fn add_out(&mut self, id: usize, b: usize, len: i32, oci: i32) {
        {
            let l = &mut self.layers[id];
            l.p[b] = l.p[b].wrapping_sub(len as i64);
            l.sent[b] = l.sent[b].wrapping_add(oci as i64);
        }
        self.instant_detect(self.curtime, b, id);
    }

    fn filter_check(&mut self, id: usize, b: usize, flow: &Flow, len: i32, oci: i32) {
        if self.should_filter(b, flow, id) {
            let l = &mut self.layers[id];
            l.wf_p[b] = l.wf_p[b].wrapping_add(len as u32);
            l.wf_s[b] = l.wf_s[b].wrapping_add(oci);
            self.check_ready(b, id);
        }
    }

    /// `amonProcessing()`: account one flow (or one packet) in every layer.
    pub fn amon_processing(&mut self, mut flow: Flow, len: i32, _start: f64, end: f64, oci: i32) {
        if self.malformed(end) {
            self.malformed_flows += 1;
            return;
        }
        // UDP to/from ports such as 443 that are mostly legitimate one-way traffic.
        if flow.proto == UDP
            && ((is_special(flow.sport as i32) && !self.svc(flow.dport))
                || (is_special(flow.dport as i32) && !self.svc(flow.sport)))
        {
            return;
        }
        if flow.proto == ICMP {
            flow.sport = -2;
            flow.dport = -2;
        }

        if self.curtime == 0.0 {
            self.curtime = end;
        }
        if (end as u64) > (self.curtime as u64) {
            let iend = cvt_i32(end) as i64;
            if self.votes == 0 {
                self.votedtime = iend;
            }
            if iend == self.votedtime {
                self.votes += 1;
            } else {
                self.votes -= 1;
            }
            if self.votes >= MINVOTES {
                self.curtime = end;
                self.votedtime = 0;
                self.votes = 0;
            }
        }
        if self.lasttime == 0.0 {
            self.lasttime = self.curtime;
        }

        if !self.shuffle_done {
            let addr = if flow.dlocal { flow.dst } else { flow.src };
            self.shuffle(addr, len, oci, self.curtime as u32);
            return;
        }

        for index in 0..NUMB {
            let bricku = (BRICK_UNIT + index * LAYER_SKEW) as u32;

            if self.sim_filter {
                for way in LHOST..=LPRST {
                    if way == LHOST || way == LPREF || way >= LHSYN {
                        if flow.dlocal {
                            let b = self.myhash(flow.dst, 0, way, bricku);
                            self.filter_check(index, b, &flow, len, oci);
                        }
                    } else if way == FPORT {
                        if flow.dlocal {
                            let b = self.myhash(0, flow.sport as u16, way, bricku);
                            self.filter_check(index, b, &flow, len, oci);
                        }
                    } else if way == LPORT {
                        if flow.dlocal {
                            let b = self.myhash(0, flow.dport as u16, way, bricku);
                            self.filter_check(index, b, &flow, len, oci);
                        }
                    } else if way == LHFPORT || way == LPFPORT || way == LHLPORT {
                        // The original also omitted LPLPORT here.
                        if flow.dlocal {
                            let port = if way == LHFPORT || way == LPFPORT {
                                flow.sport
                            } else {
                                flow.dport
                            };
                            let b = self.myhash(flow.dst, port as u16, way, bricku);
                            self.filter_check(index, b, &flow, len, oci);
                        }
                    }
                }
            }

            let tcp = flow.proto == TCP;
            let fl = flow.flags;
            for way in LHOST..=LPRST {
                match way {
                    LHOST | LPREF | LHSYN..=LPRST => {
                        if flow.dlocal {
                            let b = self.myhash(flow.dst, 0, way, bricku);
                            let skip = match way {
                                LHSYN | LPSYN => fl != SYN || !tcp,
                                LHSYNACK | LPSYNACK => fl != SYNACK || !tcp,
                                LHACK | LPACK => fl != ACK || !tcp,
                                LHRST | LPRST => fl != RST || !tcp,
                                _ => false,
                            };
                            if skip {
                                continue;
                            }
                            self.add_in(index, b, &flow, len, oci, way);
                        }
                        if flow.slocal {
                            let b = self.myhash(flow.src, 0, way, bricku);
                            let skip = match way {
                                LHSYN | LPSYN => (fl != SYNACK && fl != ACK && fl != RST) || !tcp,
                                LHSYNACK | LPSYNACK => fl != SYN || !tcp,
                                LHACK | LPACK => (fl != PUSH && fl != PUSHACK) || !tcp,
                                LHRST | LPRST => fl != SYN || !tcp,
                                _ => false,
                            };
                            if skip {
                                continue;
                            }
                            self.add_out(index, b, len, oci);
                        }
                    }
                    FPORT => {
                        if flow.dlocal && self.svc(flow.sport) {
                            let b = self.myhash(0, flow.sport as u16, way, bricku);
                            self.add_in(index, b, &flow, len, oci, way);
                        }
                        if flow.slocal && self.svc(flow.dport) {
                            let b = self.myhash(0, flow.dport as u16, way, bricku);
                            self.add_out(index, b, len, oci);
                        }
                    }
                    LPORT => {
                        if flow.dlocal && self.svc(flow.dport) {
                            let b = self.myhash(0, flow.dport as u16, way, bricku);
                            self.add_in(index, b, &flow, len, oci, way);
                        }
                        if flow.slocal && self.svc(flow.sport) {
                            let b = self.myhash(0, flow.sport as u16, way, bricku);
                            self.add_out(index, b, len, oci);
                        }
                    }
                    LHFPORT | LPFPORT => {
                        if flow.dlocal && self.svc(flow.sport) {
                            let b = self.myhash(flow.dst, flow.sport as u16, way, bricku);
                            self.add_in(index, b, &flow, len, oci, way);
                        }
                        if flow.slocal && self.svc(flow.dport) {
                            let b = self.myhash(flow.src, flow.dport as u16, way, bricku);
                            self.add_out(index, b, len, oci);
                        }
                    }
                    LHLPORT | LPLPORT => {
                        if flow.dlocal && self.svc(flow.dport) {
                            let b = self.myhash(flow.dst, flow.dport as u16, way, bricku);
                            self.add_in(index, b, &flow, len, oci, way);
                        }
                        if flow.slocal && self.svc(flow.sport) {
                            let b = self.myhash(flow.src, flow.sport as u16, way, bricku);
                            self.add_out(index, b, len, oci);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// `update_stats()`: fold the finished interval into the running
    /// statistics and roll them into history once per training period.
    fn update_stats(&mut self, index: usize) {
        if !self.shuffle_done || self.layers.is_empty() {
            return;
        }
        let brickf = Self::layer_size(self.brick_final, index).min(self.layers[index].size);
        {
            let l = &mut self.layers[index];
            for i in 0..brickf {
                for j in [VOL, SYM] {
                    let data = if j == VOL {
                        l.p[i] as f64
                    } else {
                        l.s[i] = l.rec[i] as f64 / l.sent[i].wrapping_add(1) as f64;
                        l.s[i]
                    };
                    if l.is_abnormal[i] == 0 {
                        l.stats[CUR][N][j][i] += 1.0;
                        let n = l.stats[CUR][N][j][i];
                        if n == 1.0 {
                            l.stats[CUR][AVG][j][i] = data;
                            l.stats[CUR][SS][j][i] = 0.0;
                        } else {
                            let ao = l.stats[CUR][AVG][j][i];
                            let an = ao + (data - ao) / n;
                            l.stats[CUR][AVG][j][i] = an;
                            l.stats[CUR][SS][j][i] += (data - ao) * (data - an);
                        }
                    }
                }
            }
        }

        let trained = cvt_i32(self.lasttime - self.firsttime);
        if trained as f64 >= self.params.min_train {
            if !self.training_done {
                println!("Training has completed");
                self.training_done = true;
            }
            self.firsttime = self.curtime;
            let threshold = self.params.min_train * MIN_SAMPLES;
            // As in the original, every layer is rolled over using the bin
            // count of the layer that triggered the rollover.
            for l in self.layers.iter_mut() {
                let upto = brickf.min(l.size);
                for x in [SS, AVG, N] {
                    for j in [VOL, SYM] {
                        for i in 0..upto {
                            if l.stats[CUR][N][j][i] < threshold {
                                continue;
                            }
                            let cur = l.stats[CUR][x][j][i];
                            l.stats[HIST][x][j][i] = if cur == 0.0 {
                                0.5 * l.stats[HIST][x][j][i] + 0.5 * cur
                            } else {
                                cur
                            };
                            l.stats[CUR][x][j][i] = 0.0;
                        }
                    }
                }
            }
        }
    }

    /// `detect_attack()`: per-interval CUSUM update and attack bookkeeping.
    fn detect_attack(&mut self, ltime: f64, id: usize) {
        if self.layers.is_empty() {
            return;
        }
        let brickf = Self::layer_size(self.brick_final, id).min(self.layers[id].size);
        for i in 0..brickf {
            {
                let l = &mut self.layers[id];
                let avgv = l.stats[HIST][AVG][VOL][i];
                let stdv = l.std(HIST, VOL, i);
                let avgs = l.stats[HIST][AVG][SYM][i];
                let stds = l.std(HIST, SYM, i);
                let volume = l.p[i] as i32;
                let asym = cvt_i32(l.s[i]);
                for (dim, data, mean, std) in [(VOL, volume, avgv, stdv), (SYM, asym, avgs, stds)] {
                    let tmp = l.cusum[dim][i] + data as f64 - mean - 3.0 * std;
                    l.cusum[dim][i] = if tmp > 0.0 { tmp } else { 0.0 };
                }
            }

            if self.layers[id].is_attack[i] {
                if self.layers[id].sigs[i].nm == MM {
                    self.alert_ready(i, id);
                } else {
                    let diff = ltime - self.layers[id].detection_time[i] as f64;
                    if diff >= ADELAY {
                        let l = &mut self.layers[id];
                        l.is_attack[i] = false;
                        l.detection_time[i] = 0;
                        self.clear_samples(i, id);
                    }
                }
            } else if self.training_done
                && self.abnormal(VOL, i, id) == 0.0
                && self.abnormal(SYM, i, id) == 0.0
            {
                let l = &mut self.layers[id];
                if l.is_abnormal[i] > 0 {
                    l.is_abnormal[i] -= 1;
                }
                if l.is_abnormal[i] == 0 {
                    self.clear_samples(i, id);
                }
            }
        }
    }

    /// `reset_transmit()`: the per-interval work.
    fn reset_transmit(&mut self, ltime: f64) {
        self.lasttime = self.curtime;
        for index in 0..NUMB {
            if self.training_done {
                self.detect_attack(ltime, index);
            }
            self.update_stats(index);
        }
    }

    /// Called when `curtime` has advanced by at least one interval: process the
    /// finished interval and start a fresh one.
    pub fn end_interval(&mut self) {
        let lastbintime = self.curtime;
        let zero = self.shuffle_done;
        self.reset_transmit(lastbintime);
        if zero {
            for l in self.layers.iter_mut() {
                l.zero_cell();
            }
        }
        self.lasttime = self.curtime;
    }

    /// Has `curtime` moved at least one interval past the last boundary?
    pub fn interval_elapsed(&self) -> bool {
        self.curtime - self.lasttime >= self.params.interval
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det() -> Detector {
        let params = Params::from_pairs([
            ("interval", 1.0),
            ("min_train", 10.0),
            ("file_interval", 1e9),
        ]);
        let mut lp = LocalPrefixes::default();
        lp.add("10.0.0.0/24");
        Detector::new(params, Services::from_ports([0, 53, 80]), lp)
    }

    #[test]
    fn hash_bins_stay_in_range() {
        let mut d = det();
        d.finish_shuffle();
        for id in 0..NUMB {
            let bricku = (BRICK_UNIT + id * LAYER_SKEW) as u32;
            for way in LHOST..=LPRST {
                for (ip, port) in [
                    (0u32, 0u16),
                    (u32::MAX, u16::MAX),
                    (0x0a00_0001, 53),
                    (12345678, 40000),
                ] {
                    let b = d.myhash(ip, port, way, bricku);
                    assert!(b < d.layers[id].size, "way {way} layer {id} bin {b}");
                }
            }
        }
    }

    #[test]
    fn shuffle_completes_after_min_train() {
        let mut d = det();
        let mut f = Flow {
            src: 0x0b00_0001,
            sport: 53,
            dst: 0x0a00_0005,
            dport: 999,
            proto: UDP,
            ..Flow::default()
        };
        f.dlocal = true;
        d.firsttimeinfile = 1000.0;
        d.firsttime = 1000.0;
        d.amon_processing(f, 100, 1000.0, 1000.0, 1);
        assert!(!d.shuffle_done);
        d.amon_processing(f, 100, 1010.0, 1010.0, 1);
        assert!(d.shuffle_done);
        assert_eq!(d.brick_final, (NUMF + BRICK_DIMENSION) as i32);
    }
}

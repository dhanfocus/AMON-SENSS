//! Deterministic synthetic traffic for the golden tests.
//!
//! The same generator feeds both this crate and the original C++ binary (via
//! `cargo run --example synth`), so expected outputs in `tests/golden/` can be
//! regenerated from the reference implementation. Keep it deterministic: any
//! change to the generated traffic requires regenerating the golden files.

#![allow(dead_code)]

pub const T0: u64 = 1_600_000_000;

/// splitmix64.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: &str) -> Rng {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in seed.bytes() {
            h = (h ^ b as u64).wrapping_mul(0x100_0000_01b3);
        }
        Rng(h)
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    /// Uniform integer in `lo..=hi`.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next_u64() % (hi - lo + 1)
    }
    /// Uniform float in `[0, 1)`.
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
    pub fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.range(0, items.len() as u64 - 1) as usize]
    }
}

pub fn ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
    u32::from_be_bytes([a, b, c, d])
}

fn dotted(x: u32) -> String {
    let [a, b, c, d] = x.to_be_bytes();
    format!("{a}.{b}.{c}.{d}")
}

#[derive(Clone, Debug)]
pub struct SynFlow {
    pub t0: u64,
    pub ms0: u64,
    pub t1: u64,
    pub ms1: u64,
    pub proto: u8,
    pub src: u32,
    pub sport: u32,
    pub dst: u32,
    pub dport: u32,
    pub flags: u32,
    pub pkts: u64,
    pub bytes: u64,
    /// Reverse direction, used by the Flowride writer only.
    pub rpkts: u64,
    pub rbytes: u64,
}

/// Records that only exist in a given output format.
#[derive(Clone, Debug)]
pub enum Rec {
    Flow(SynFlow),
    /// A line that is not a flow record (nfdump format only).
    Junk(&'static str),
    /// A non-IPv4 Ethernet frame (pcap format only), at the given time.
    Arp(u64, u64),
}

#[derive(Clone, Copy, Debug)]
pub enum Attack {
    DnsReflection { victim: u32, rate: u64 },
    SynFlood { victim: u32, port: u32, rate: u64 },
    IcmpFlood { victim: u32, rate: u64 },
}

pub struct Scenario {
    pub name: &'static str,
    pub seconds: u64,
    pub bg: (u64, u64),
    /// (from, to, attack): active for seconds `from..to`.
    pub attacks: Vec<(u64, u64, Attack)>,
    /// Number of distinct local hosts in 10.1.0.0/16 touched during the
    /// first seconds (exercises the big-hitter table overflow path).
    pub spread_hosts: u32,
    pub edge_cases: bool,
}

pub fn scenario(name: &str) -> Scenario {
    let v1 = ip(10, 0, 0, 5);
    let v2 = ip(10, 1, 2, 3);
    let v3 = ip(10, 0, 0, 9);
    match name {
        "basic" => Scenario {
            name: "basic",
            seconds: 600,
            bg: (20, 35),
            attacks: vec![
                (
                    200,
                    280,
                    Attack::DnsReflection {
                        victim: v1,
                        rate: 25,
                    },
                ),
                (
                    320,
                    400,
                    Attack::SynFlood {
                        victim: v2,
                        port: 80,
                        rate: 25,
                    },
                ),
                (
                    440,
                    500,
                    Attack::IcmpFlood {
                        victim: v3,
                        rate: 20,
                    },
                ),
            ],
            spread_hosts: 0,
            edge_cases: true,
        },
        "bighitters" => Scenario {
            name: "bighitters",
            seconds: 450,
            bg: (20, 30),
            attacks: vec![
                (
                    200,
                    280,
                    Attack::DnsReflection {
                        victim: v2,
                        rate: 25,
                    },
                ),
                (
                    320,
                    400,
                    Attack::SynFlood {
                        victim: v1,
                        port: 25,
                        rate: 25,
                    },
                ),
            ],
            spread_hosts: 4000,
            edge_cases: false,
        },
        "packets" => Scenario {
            name: "packets",
            seconds: 400,
            bg: (15, 25),
            attacks: vec![
                (
                    200,
                    260,
                    Attack::DnsReflection {
                        victim: v1,
                        rate: 150,
                    },
                ),
                (
                    300,
                    360,
                    Attack::IcmpFlood {
                        victim: v3,
                        rate: 150,
                    },
                ),
            ],
            spread_hosts: 0,
            edge_cases: true,
        },
        other => panic!("unknown scenario {other}"),
    }
}

fn remote(rng: &mut Rng) -> u32 {
    ip(
        rng.range(11, 200) as u8,
        rng.range(0, 255) as u8,
        rng.range(0, 255) as u8,
        rng.range(1, 254) as u8,
    )
}

fn local(rng: &mut Rng) -> u32 {
    if rng.unit() < 0.5 {
        ip(10, 0, 0, rng.range(1, 40) as u8)
    } else {
        ip(10, 1, rng.range(0, 20) as u8, rng.range(1, 30) as u8)
    }
}

#[allow(clippy::too_many_arguments)]
fn flow(
    t0: u64,
    ms0: u64,
    t1: u64,
    ms1: u64,
    proto: u8,
    src: u32,
    sport: u32,
    dst: u32,
    dport: u32,
    flags: u32,
    pkts: u64,
    bytes: u64,
) -> Rec {
    Rec::Flow(SynFlow {
        t0,
        ms0,
        t1,
        ms1,
        proto,
        src,
        sport,
        dst,
        dport,
        flags,
        pkts,
        bytes,
        rpkts: 0,
        rbytes: 0,
    })
}

fn background(rng: &mut Rng, t: u64, sc: &Scenario, out: &mut Vec<Rec>) {
    let n = rng.range(sc.bg.0, sc.bg.1);
    for _ in 0..n {
        let dur = rng.pick(&[0, 0, 0, 1, 2]);
        let t0 = t - dur;
        let (ms0, ms1) = (rng.range(0, 999), rng.range(0, 999));
        let (lh, rh) = (local(rng), remote(rng));
        let k = rng.unit();
        let eph = rng.range(1024, 65535) as u32;
        let p = rng.range(1, 6);
        if k < 0.20 {
            let svc = rng.pick(&[80, 22, 25]);
            out.push(flow(t0, ms0, t, ms1, 6, rh, eph, lh, svc, 2, p, p * 60));
            out.push(flow(t0, ms0, t, ms1, 6, lh, svc, rh, eph, 18, p, p * 60));
        } else if k < 0.30 {
            out.push(flow(
                t0,
                ms0,
                t,
                ms1,
                6,
                rh,
                eph,
                lh,
                80,
                27,
                p * 5,
                p * 5000,
            ));
        } else if k < 0.50 {
            let mut q = flow(t0, ms0, t, ms1, 17, lh, eph, rh, 53, 0, p, p * 70);
            if let Rec::Flow(f) = &mut q {
                f.rpkts = p;
                f.rbytes = p * 200;
            }
            out.push(q);
            out.push(flow(t0, ms0, t, ms1, 17, rh, 53, lh, eph, 0, p, p * 200));
        } else if k < 0.60 {
            out.push(flow(t0, ms0, t, ms1, 17, lh, 123, rh, 123, 0, 1, 76));
            out.push(flow(t0, ms0, t, ms1, 17, rh, 123, lh, 123, 0, 1, 76));
        } else if k < 0.70 {
            out.push(flow(t0, ms0, t, ms1, 1, rh, 0, lh, 2048, 0, p, p * 84));
            out.push(flow(t0, ms0, t, ms1, 1, lh, 0, rh, 0, 0, p, p * 84));
        } else if k < 0.78 {
            out.push(flow(
                t0,
                ms0,
                t,
                ms1,
                17,
                rh,
                443,
                lh,
                eph,
                0,
                p * 10,
                p * 12000,
            ));
        } else if k < 0.85 {
            out.push(flow(t0, ms0, t, ms1, 6, lh, eph, rh, 443, 2, 1, 60));
            let fl = rng.pick(&[18, 18, 4]);
            out.push(flow(t0, ms0, t, ms1, 6, rh, 443, lh, eph, fl, 1, 60));
        } else if k < 0.90 {
            // Service ports above 32767 (stored as negative shorts by the original).
            out.push(flow(
                t0,
                ms0,
                t,
                ms1,
                17,
                rh,
                40000,
                lh,
                40001,
                0,
                p,
                p * 100,
            ));
        } else if k < 0.95 {
            let other = remote(rng);
            out.push(flow(t0, ms0, t, ms1, 17, rh, eph, other, 53, 0, p, p * 70));
        } else {
            let fl = rng.pick(&[16, 4, 8]);
            out.push(flow(t0, ms0, t, ms1, 6, lh, eph, rh, 80, fl, p, p * 60));
        }
    }
    if sc.edge_cases && rng.unit() < 0.05 {
        match rng.range(0, 3) {
            0 => out.push(Rec::Junk("Date first seen          Duration Proto")),
            1 => out.push(flow(
                t,
                0,
                t,
                0,
                17,
                remote(rng),
                65535,
                local(rng),
                53,
                0,
                3,
                300,
            )),
            2 => out.push(flow(
                t - 3000,
                0,
                t,
                0,
                17,
                remote(rng),
                53,
                local(rng),
                65535,
                0,
                9000,
                900000,
            )),
            _ => out.push(Rec::Arp(t, rng.range(0, 999))),
        }
    }
}

fn attack(rng: &mut Rng, t: u64, a: Attack, out: &mut Vec<Rec>) {
    match a {
        Attack::DnsReflection { victim, rate } => {
            for _ in 0..rate {
                let p = rng.range(200, 400);
                let (ms0, ms1) = (rng.range(0, 999), rng.range(0, 999));
                let dport = rng.range(1024, 65535) as u32;
                out.push(flow(
                    t,
                    ms0,
                    t,
                    ms1,
                    17,
                    remote(rng),
                    53,
                    victim,
                    dport,
                    0,
                    p,
                    p * 1400,
                ));
            }
        }
        Attack::SynFlood { victim, port, rate } => {
            for _ in 0..rate {
                let p = rng.range(100, 300);
                let (ms0, ms1) = (rng.range(0, 999), rng.range(0, 999));
                let sport = rng.range(1024, 65535) as u32;
                out.push(flow(
                    t,
                    ms0,
                    t,
                    ms1,
                    6,
                    remote(rng),
                    sport,
                    victim,
                    port,
                    2,
                    p,
                    p * 60,
                ));
            }
        }
        Attack::IcmpFlood { victim, rate } => {
            for _ in 0..rate {
                let p = rng.range(100, 300);
                out.push(flow(
                    t,
                    0,
                    t,
                    0,
                    1,
                    remote(rng),
                    0,
                    victim,
                    2048,
                    0,
                    p,
                    p * 1000,
                ));
            }
        }
    }
}

pub fn generate(sc: &Scenario) -> Vec<Rec> {
    let mut rng = Rng::new(sc.name);
    let mut out = Vec::new();
    for s in 0..sc.seconds {
        let t = T0 + s;
        if s < 10 && sc.spread_hosts > 0 {
            let per = sc.spread_hosts / 10;
            for h in 0..per {
                let n = s as u32 * per + h;
                let dst = ip(10, 1, (n / 250) as u8, (n % 250 + 1) as u8);
                out.push(flow(
                    t,
                    0,
                    t,
                    500,
                    17,
                    remote(&mut rng),
                    53,
                    dst,
                    3333,
                    0,
                    2,
                    200,
                ));
            }
        }
        background(&mut rng, t, sc, &mut out);
        for &(from, to, a) in &sc.attacks {
            if (from..to).contains(&s) {
                attack(&mut rng, t, a, &mut out);
            }
        }
    }
    out
}

pub fn to_nfdump(recs: &[Rec]) -> String {
    let mut s = String::new();
    let mut n = 0;
    for r in recs {
        match r {
            Rec::Flow(f) => {
                n += 1;
                s.push_str(&format!(
                    "2|{}|{}|{}|{}|{}|0|0|0|{}|{}|0|0|0|{}|{}|0|0|0|0|{}|0|{}|{}\n",
                    f.t0,
                    f.ms0,
                    f.t1,
                    f.ms1,
                    f.proto,
                    f.src,
                    f.sport,
                    f.dst,
                    f.dport,
                    f.flags,
                    f.pkts,
                    f.bytes
                ));
            }
            Rec::Junk(j) => {
                s.push_str(j);
                s.push('\n');
            }
            Rec::Arp(..) => {}
        }
    }
    s.push_str(&format!("Summary: total flows: {n}\n"));
    s.push_str("Sys: 0.0000s flows/second: 0.0 Wall: 0.0000s flows/second: 0.0\n");
    s.push_str("2|1600009999|0|1600009999|0|17|0|0|0|1|53|0|0|0|167772165|999|0|0|0|0|0|0|1|100\n");
    s
}

pub fn to_flowride(recs: &[Rec]) -> String {
    let mut s = String::new();
    for r in recs {
        if let Rec::Flow(f) = r {
            let proto = match f.proto {
                6 => "TCP",
                17 => "UDP",
                _ => "ICMP",
            };
            s.push_str(&format!(
                // Fields as read by the original: 12 flags, 15/16 packets,
                // 17/18 bytes (forward/reverse), 19 end time.
                "{}{:09}\t{proto}\tACTIVE\tx\t{}\t{}\t{}\t{}\t1\t0\t60\t0\t{}\t8\t0\t{}\t{}\t{}\t{}\t{}{:09}\n",
                f.t0,
                f.ms0 * 1_000_000,
                dotted(f.src),
                dotted(f.dst),
                f.sport,
                f.dport,
                f.flags,
                f.pkts,
                f.rpkts,
                f.bytes,
                f.rbytes,
                f.t1,
                f.ms1 * 1_000_000 + 123
            ));
        }
    }
    s
}

pub fn to_pcap(recs: &[Rec]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    let record = |out: &mut Vec<u8>, sec: u64, usec: u64, data: &[u8], orig: usize| {
        out.extend_from_slice(&(sec as u32).to_le_bytes());
        out.extend_from_slice(&(usec as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(orig as u32).to_le_bytes());
        out.extend_from_slice(data);
    };
    let mut k = 0u64;
    for r in recs {
        match r {
            Rec::Flow(f) => {
                k += 1;
                let mut pkt = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x08, 0x00];
                // Every 97th packet carries IP options (IHL 6).
                let ihl: usize = if k % 97 == 0 { 6 } else { 5 };
                let l4len = match f.proto {
                    6 => 20,
                    _ => 8,
                };
                let ip_len =
                    (f.bytes / f.pkts.max(1)).clamp((ihl * 4 + l4len) as u64, 1500) as usize;
                let mut iph = vec![0u8; ihl * 4];
                iph[0] = 0x40 | ihl as u8;
                iph[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
                iph[8] = 64;
                iph[9] = f.proto;
                iph[12..16].copy_from_slice(&f.src.to_be_bytes());
                iph[16..20].copy_from_slice(&f.dst.to_be_bytes());
                pkt.extend_from_slice(&iph);
                let mut l4 = vec![0u8; l4len];
                if f.proto == 6 || f.proto == 17 {
                    l4[0..2].copy_from_slice(&(f.sport as u16).to_be_bytes());
                    l4[2..4].copy_from_slice(&(f.dport as u16).to_be_bytes());
                }
                if f.proto == 6 {
                    l4[12] = 0x50;
                    l4[13] = f.flags as u8;
                }
                pkt.extend_from_slice(&l4);
                record(&mut out, f.t1, f.ms1 * 1000 + k % 1000, &pkt, 14 + ip_len);
            }
            Rec::Arp(sec, ms) => {
                let mut pkt = vec![
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, 3, 0x08, 0x06,
                ];
                pkt.extend_from_slice(&[0u8; 28]);
                record(&mut out, *sec, ms * 1000, &pkt, pkt.len());
            }
            Rec::Junk(_) => {}
        }
    }
    out
}

/// Test configuration used for all golden runs: short training so attacks
/// are detected within a few minutes of synthetic traffic.
pub const CONFIG: &str = "# Test configuration\n\
interval=1\n\
file_interval=100000000\n\
attack_low=30\n\
attack_high=60\n\
min_train=60\n\
numstd=5\n\
filter_thresh=0.25\n\
min_oci=10\n\
cusum_thresh=30\n";

pub const PREFIXES: &str = "10.0.0.0/24\n10.1.0.0/16\n";

/// Part `part` (0-based) of `parts` equal time slices of a scenario, for
/// multi-file inputs.
pub fn time_slice(sc: &Scenario, recs: &[Rec], part: u64, parts: u64) -> Vec<Rec> {
    let len = sc.seconds.div_ceil(parts);
    let (from, to) = (T0 + part * len, T0 + (part + 1) * len);
    recs.iter()
        .filter(|r| {
            let t = match r {
                Rec::Flow(f) => f.t1,
                Rec::Arp(t, _) => *t,
                Rec::Junk(_) => from,
            };
            (from..to).contains(&t)
        })
        .cloned()
        .collect()
}

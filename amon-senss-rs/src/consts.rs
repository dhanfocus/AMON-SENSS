//! Compile-time constants, mirroring `utils.h` / `amonsenss.cc` of the C++ original.

/// How many independent "brick" layers are kept. Each layer uses a slightly
/// different number of bins, which reduces false positives from collisions.
pub const NUMB: usize = 5;
/// Seconds an attack may wait for enough signature matches before it is dropped.
pub const ADELAY: f64 = 35.0;
/// How many ways the traffic is binned (see the `LHOST`..`LPRST` constants).
pub const NUMF: usize = 16;
/// Bins per way. Deliberately not a power of two.
pub const BRICK_UNIT: usize = 3337;
/// Bins in layer 0 before big hitters are added.
pub const BRICK_DIMENSION: usize = NUMF * BRICK_UNIT;
/// Each layer `i` gets `i * LAYER_SKEW` extra bins per way.
pub const LAYER_SKEW: usize = 13;
/// Matching flows required before an alert is emitted.
pub const MM: i32 = 10;
/// Number of candidate-signature slots per bin in the original (`NF`).
pub const NF: usize = 20;
/// Slots actually filled by `addSample` (indices `1..NF-8`).
pub const NSLOTS: usize = NF - 8 - 1;
/// Fraction of the training period that must have samples before stats are rolled over.
pub const MIN_SAMPLES: f64 = 0.1;
/// Big-hitter detection: rounds of pruning before the shuffle table is frozen.
pub const MAX_SHUFFLES: i32 = 100;
/// Big-hitter detection: entries below `max / FRACTION` are pruned.
pub const FRACTION: u32 = 10000;
/// Votes needed to advance the current time (see `amon_processing`).
pub const MINVOTES: i32 = 1;
/// `alerts.txt` is rotated with `./rotate` once it grows past this many bytes.
pub const ROTATE_SIZE: u64 = 10_000_000;
/// Maximum line length read by `fgets` in the original; also the live snaplen.
pub const MAXLINE: usize = 1024;

// Transport protocols.
pub const TCP: u8 = 6;
pub const UDP: u8 = 17;
pub const ICMP: u8 = 1;

// TCP flag combinations used for flag-specific bins.
pub const SYN: i32 = 2;
pub const SYNACK: i32 = 18;
pub const PUSH: i32 = 8;
pub const PUSHACK: i32 = 24;
pub const RST: i32 = 4;
pub const ACK: i32 = 16;

// Ways of binning traffic (`enum ways` in the original).
pub const LHOST: usize = 0;
pub const LPREF: usize = 1;
pub const FPORT: usize = 2;
pub const LPORT: usize = 3;
pub const LHFPORT: usize = 4;
pub const LHLPORT: usize = 5;
pub const LPFPORT: usize = 6;
pub const LPLPORT: usize = 7;
pub const LHSYN: usize = 8;
pub const LPSYN: usize = 9;
pub const LHSYNACK: usize = 10;
pub const LPSYNACK: usize = 11;
pub const LHACK: usize = 12;
pub const LPACK: usize = 13;
pub const LHRST: usize = 14;
pub const LPRST: usize = 15;

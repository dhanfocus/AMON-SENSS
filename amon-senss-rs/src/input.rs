//! Input formats and the record-reading loop (`read_one_line`,
//! `process_one_line`, `read_from_file`, and the per-format
//! `amonProcessing*` parsers of the original).

use std::io::{self, BufRead, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionOption;
use pcap_file::pcapng::{Block, PcapNgReader};

use crate::cnum::{atoi, cvt_i32, strtol};
use crate::consts::{ICMP, TCP, UDP};
use crate::detector::Detector;
use crate::flow::Flow;
use crate::net::todec;

/// Input record formats (`-F`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    /// libpcap file (pcap or pcapng)
    Pcap,
    /// live capture from an interface (needs the `live` build feature)
    Plive,
    /// flow-tools files, converted with `ft2nfdump | nfdump -o pipe`
    Ft,
    /// nfdump files, read with `nfdump -o pipe`
    Nf,
    /// Flowride records (gzip-compressed, tab separated)
    Fr,
}

/// Field accessor for a delimiter-separated line. `d(k)` is the text after the
/// `k`-th delimiter, matching the `delimiters[k]` indexing of the original.
pub struct Fields<'a> {
    line: &'a [u8],
    starts: Vec<usize>,
    delim: u8,
}

impl<'a> Fields<'a> {
    pub fn split(line: &'a [u8], delim: u8) -> Fields<'a> {
        let mut starts = vec![0];
        starts.extend(
            line.iter()
                .enumerate()
                .filter(|(_, &c)| c == delim)
                .map(|(i, _)| i + 1),
        );
        Fields {
            line,
            starts,
            delim,
        }
    }

    /// Number of delimiters on the line.
    pub fn delimiters(&self) -> usize {
        self.starts.len() - 1
    }

    /// Field `k` (0 = before the first delimiter). Missing fields are empty.
    pub fn field(&self, k: usize) -> &'a [u8] {
        let Some(&start) = self.starts.get(k) else {
            return b"";
        };
        let rest = &self.line[start..];
        match rest.iter().position(|&c| c == self.delim) {
            Some(end) => &rest[..end],
            None => rest,
        }
    }

    /// Text after delimiter `k` (`line + delimiters[k]` in the original).
    pub fn d(&self, k: usize) -> &'a [u8] {
        self.field(k + 1)
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Layout of an `nfdump -o pipe` line.
///
/// nfdump up to 1.6 writes start and end time as `sec|msec|sec|msec`
/// (23 separators for IPv4 and IPv6 alike); this is the layout the original
/// parsed. nfdump 1.7 writes each time as a single millisecond field, so the
/// line has 21 separators and every later field moves down by two.
struct NfLayout {
    v17: bool,
}

impl NfLayout {
    fn of(f: &Fields) -> NfLayout {
        NfLayout {
            v17: f.delimiters() == 21,
        }
    }

    /// Index of a field given its nfdump 1.6 `delimiters[]` index (>= 4).
    fn idx(&self, old: usize) -> usize {
        if self.v17 {
            old - 2
        } else {
            old
        }
    }

    /// Flow start time.
    fn start(&self, f: &Fields) -> f64 {
        if self.v17 {
            strtol(f.d(0)) as f64 / 1000.0
        } else {
            strtol(f.d(0)) as f64 + strtol(f.d(1)) as f64 / 1000.0
        }
    }

    /// Flow end time (also the record's timestamp).
    fn end(&self, f: &Fields) -> f64 {
        if self.v17 {
            strtol(f.d(1)) as f64 / 1000.0
        } else {
            strtol(f.d(2)) as f64 + atoi(f.d(3)) as f64 / 1000.0
        }
    }
}

impl Detector {
    /// `amonProcessingNfdump()`: one `nfdump -o pipe` line, e.g.
    /// `2|1453485557|768|1453485557|768|6|0|0|0|2379511808|44694|0|0|0|2792759296|995|0|0|0|0|2|0|1|40`
    /// (nfdump 1.6) or
    /// `2|1453485557768|1453485557768|6|0|0|0|2379511808|44694|0|0|0|2792759296|995|0|0|0|0|2|0|1|40`
    /// (nfdump 1.7).
    pub fn process_nfdump(&mut self, f: &Fields) {
        let lay = NfLayout::of(f);
        let start = lay.start(f);
        let end = if lay.v17 {
            lay.end(f)
        } else {
            strtol(f.d(2)) as f64 + strtol(f.d(3)) as f64 / 1000.0
        };
        let dur = (end - start).clamp(0.0, 3600.0);
        let proto = atoi(f.d(lay.idx(4)));
        let flags = atoi(f.d(lay.idx(19)));
        let mut flow = Flow {
            src: strtol(f.d(lay.idx(8))) as u32,
            sport: atoi(f.d(lay.idx(9))) as i16,
            dst: strtol(f.d(lay.idx(13))) as u32,
            dport: atoi(f.d(lay.idx(14))) as i16,
            proto: proto as u8,
            flags,
            ..Flow::default()
        };
        flow.slocal = self.is_local(flow.src);
        flow.dlocal = self.is_local(flow.dst);
        let bytes = atoi(f.d(lay.idx(22)));
        self.processed_bytes = self.processed_bytes.wrapping_add(bytes as i64);
        if !flow.slocal && !flow.dlocal {
            self.nonlocal_flows += 1;
            return;
        }
        self.local_flows += 1;
        let pkts = atoi(f.d(lay.idx(21)));
        let pkts = cvt_i32(pkts as f64 / (dur + 1.0)).wrapping_add(1);
        let bytes = cvt_i32(bytes as f64 / (dur + 1.0)).wrapping_add(1);

        // Outstanding-connection indicator: TCP flows with PUSH (or pure ACK)
        // are considered completed and ignored; UDP/ICMP always count.
        let oci = if proto == TCP as i32 {
            if (flags & 8) > 0 || flags == 16 {
                0
            } else {
                pkts
            }
        } else if proto == UDP as i32 || proto == ICMP as i32 {
            pkts
        } else {
            return;
        };
        if oci == 0 {
            return;
        }
        self.amon_processing(flow, bytes, start, end, oci);
    }

    /// `amonProcessingFlowride()`: one tab-separated Flowride record (already
    /// known to have 19 delimiters).
    pub fn process_flowride(&mut self, f: &Fields, start: f64) {
        let end = flowride_time(f.d(18));
        if end > self.curtime {
            self.curtime = end;
        }
        // Normalise the duration; Flowride reports every 5 seconds.
        let dur = (end - start).clamp(1.0, 5.0);

        let proto: u8 = match f.d(0) {
            b"UDP" => UDP,
            b"TCP" => TCP,
            _ => 0,
        };
        let mut flow = Flow {
            src: todec(f.d(3)),
            sport: atoi(f.d(5)) as i16,
            dst: todec(f.d(4)),
            dport: atoi(f.d(6)) as i16,
            proto,
            ..Flow::default()
        };
        flow.slocal = self.is_local(flow.src);
        flow.dlocal = self.is_local(flow.dst);
        let pbytes = atoi(f.d(16));
        let rbytes = atoi(f.d(17));
        let pktsdir = atoi(f.d(14));
        let pktsrev = atoi(f.d(15));
        if pktsdir == 0 && pktsrev == 0 {
            return;
        }
        self.processed_bytes = self.processed_bytes.wrapping_add(pbytes as i64);
        if !flow.slocal && !flow.dlocal {
            self.nonlocal_flows += 1;
            return;
        }
        self.local_flows += 1;
        let mut flags = atoi(f.d(11));
        let ppkts = atoi(f.d(14));
        let rpkts = atoi(f.d(15));
        let pkts = cvt_i32((ppkts as f64 / dur).ceil());
        let bytes = cvt_i32((pbytes as f64 / dur).ceil());
        let rpkts = cvt_i32((rpkts as f64 / dur).ceil());
        let rbytes = cvt_i32((rbytes as f64 / dur).ceil());

        let (oci, roci) = if proto == TCP {
            // Ad-hoc fix for Flowride from the original: fake a PUSH flag
            // for flows that look like they carry data.
            if pkts > 0 && bytes / pkts > 100 {
                flags |= 8;
            }
            if rpkts > 0 && rbytes / rpkts > 100 {
                flags |= 8;
            }
            if flags == 16 {
                flags |= 8;
            }
            if (flags & 1) > 0 {
                flags |= 8;
            }
            if (flags & 8) > 0 {
                (0, 0)
            } else {
                (pkts, rpkts)
            }
        } else {
            (pkts, rpkts)
        };
        if oci == 0 {
            return;
        }
        self.amon_processing(flow, bytes, start, end, oci);
        if rbytes > 0 {
            let rflow = Flow {
                src: flow.dst,
                sport: flow.dport,
                dst: flow.src,
                dport: flow.sport,
                proto: flow.proto,
                slocal: flow.dlocal,
                dlocal: flow.slocal,
                ..Flow::default()
            };
            self.amon_processing(rflow, rbytes, start, end, roci);
        }
    }

    /// `amonProcessingPcap()`: one Ethernet/IPv4 packet. Each packet is
    /// treated as a one-packet flow. Packets too short to hold the headers
    /// that are read are skipped.
    pub fn process_packet(&mut self, p: &[u8], time: f64) {
        if p.len() < 14 + 20 || u16::from_be_bytes([p[12], p[13]]) != 0x0800 {
            return;
        }
        let ip = &p[14..];
        let ihl = (ip[0] & 0x0f) as usize * 4;
        let proto = ip[9];
        let (sport, dport) = if proto == TCP || proto == UDP {
            let l4 = 14 + ihl;
            if p.len() < l4 + 4 {
                return;
            }
            (
                u16::from_be_bytes([p[l4], p[l4 + 1]]) as i16,
                u16::from_be_bytes([p[l4 + 2], p[l4 + 3]]) as i16,
            )
        } else {
            (0, 0)
        };
        let mut flow = Flow {
            src: u32::from_be_bytes([ip[12], ip[13], ip[14], ip[15]]),
            sport,
            dst: u32::from_be_bytes([ip[16], ip[17], ip[18], ip[19]]),
            dport,
            proto,
            ..Flow::default()
        };
        flow.slocal = self.is_local(flow.src);
        flow.dlocal = self.is_local(flow.dst);
        let bytes = u16::from_be_bytes([ip[2], ip[3]]) as i32;
        self.amon_processing(flow, bytes, time, time, 1);
    }
}

/// Flowride timestamps are nanoseconds since the epoch: 10 digits of seconds
/// followed by 9 digits of fraction.
fn flowride_time(field: &[u8]) -> f64 {
    let secs = &field[..field.len().min(10)];
    let frac = if field.len() > 10 {
        &field[10..field.len().min(19)]
    } else {
        b""
    };
    atoi(secs) as f64 + atoi(frac) as f64 / 1_000_000_000.0
}

/// Why reading stopped.
#[derive(Debug, PartialEq, Eq)]
pub enum ReadEnd {
    /// End of input (or the nfdump summary line).
    Eof,
    /// SIGINT was received.
    Interrupted,
}

/// A source of packets.
pub trait PacketSource {
    /// Next packet as (seconds, microseconds, data); `None` at end of input.
    fn next_packet(&mut self, stop: &AtomicBool) -> Option<(i64, i64, Vec<u8>)>;
}

/// pcap or pcapng file/stream.
pub enum PcapFile<R: Read> {
    Pcap(PcapReader<R>),
    PcapNg {
        reader: PcapNgReader<R>,
        /// Timestamp units per second, per interface.
        resolutions: Vec<u64>,
    },
}

impl<R: Read> PcapFile<R> {
    /// Open a pcap or pcapng stream, detecting the format from its magic number.
    pub fn open(mut r: R) -> io::Result<PcapFile<io::Chain<io::Cursor<Vec<u8>>, R>>> {
        let mut magic = vec![0u8; 4];
        r.read_exact(&mut magic)?;
        let is_ng = magic == [0x0a, 0x0d, 0x0d, 0x0a];
        let chained = io::Cursor::new(magic).chain(r);
        let err =
            |e: pcap_file::PcapError| io::Error::new(io::ErrorKind::InvalidData, e.to_string());
        Ok(if is_ng {
            PcapFile::PcapNg {
                reader: PcapNgReader::new(chained).map_err(err)?,
                resolutions: Vec::new(),
            }
        } else {
            PcapFile::Pcap(PcapReader::new(chained).map_err(err)?)
        })
    }
}

fn tsresol_units(v: u8) -> u64 {
    let exp = (v & 0x7f) as u32;
    let base: u64 = if v & 0x80 != 0 { 2 } else { 10 };
    base.checked_pow(exp).unwrap_or(1_000_000)
}

impl<R: Read> PacketSource for PcapFile<R> {
    fn next_packet(&mut self, _stop: &AtomicBool) -> Option<(i64, i64, Vec<u8>)> {
        match self {
            PcapFile::Pcap(r) => match r.next_packet()? {
                Ok(pkt) => {
                    let ts = pkt.timestamp;
                    Some((
                        ts.as_secs() as i64,
                        ts.subsec_micros() as i64,
                        pkt.data.into_owned(),
                    ))
                }
                Err(e) => {
                    eprintln!("pcap read error: {e}");
                    None
                }
            },
            PcapFile::PcapNg {
                reader,
                resolutions,
            } => loop {
                match reader.next_block()? {
                    Ok(Block::InterfaceDescription(idb)) => {
                        let mut units = 1_000_000;
                        for opt in &idb.options {
                            if let InterfaceDescriptionOption::IfTsResol(v) = opt {
                                units = tsresol_units(*v);
                            }
                        }
                        resolutions.push(units);
                    }
                    Ok(Block::EnhancedPacket(epb)) => {
                        // pcap-file reports the raw timestamp as nanoseconds;
                        // reinterpret it with the interface's resolution.
                        let raw = epb.timestamp.as_nanos() as u64;
                        let units = resolutions
                            .get(epb.interface_id as usize)
                            .copied()
                            .unwrap_or(1_000_000);
                        let secs = raw / units;
                        let frac = raw % units;
                        let usec = (frac as u128 * 1_000_000 / units as u128) as i64;
                        return Some((secs as i64, usec, epb.data.into_owned()));
                    }
                    Ok(Block::SimplePacket(spb)) => return Some((0, 0, spb.data.into_owned())),
                    Ok(_) => continue,
                    Err(e) => {
                        eprintln!("pcapng read error: {e}");
                        return None;
                    }
                }
            },
        }
    }
}

/// Drives the detector from an input stream, handling the per-interval tick
/// and progress reporting (`read_from_file()` of the original).
pub struct Reader<'a> {
    pub det: &'a mut Detector,
    pub stop: &'a AtomicBool,
    /// Records processed in total, across all inputs (`allflows`).
    pub allflows: &'a mut u64,
}

impl Reader<'_> {
    /// Common per-record bookkeeping. Returns false if the record has no time.
    fn admit(&mut self, epoch: f64, progress_start: &mut i64) -> bool {
        if epoch == 0.0 {
            return false;
        }
        let det = &mut *self.det;
        if det.firsttime == 0.0 {
            det.firsttime = epoch;
        }
        if det.firsttimeinfile == 0.0 {
            det.firsttimeinfile = epoch;
        }
        *self.allflows += 1;
        if *self.allflows % 1_000_000 == 0 {
            let t = now();
            println!("Processed {}, 1M in {}", self.allflows, t - *progress_start);
            *progress_start = t;
        }
        if det.interval_elapsed() {
            det.end_interval();
        }
        true
    }

    /// Read text records (`nf`, `ft` or `fr`).
    pub fn read_text(&mut self, input: &mut dyn BufRead, format: Format) -> io::Result<ReadEnd> {
        println!("Reading from file");
        let mut progress_start = now();
        let mut nlines: u64 = 0;
        let mut buf = Vec::with_capacity(256);
        let end = loop {
            buf.clear();
            if input.read_until(b'\n', &mut buf)? == 0 {
                break ReadEnd::Eof;
            }
            if self.stop.load(Ordering::Relaxed) {
                break ReadEnd::Interrupted;
            }
            let is_nf = matches!(format, Format::Nf | Format::Ft);
            // nfdump ends its output with a summary; stop there (not counted).
            if is_nf && buf.windows(3).any(|w| w == b"Sys") {
                break ReadEnd::Eof;
            }
            nlines += 1;
            match format {
                Format::Nf | Format::Ft => {
                    if !buf.contains(&b'|') {
                        continue;
                    }
                    let f = Fields::split(&buf, b'|');
                    let epoch = NfLayout::of(&f).end(&f);
                    if self.admit(epoch, &mut progress_start) {
                        self.det.process_nfdump(&f);
                    }
                }
                Format::Fr => {
                    let f = Fields::split(&buf, b'\t');
                    if f.delimiters() != 19 {
                        continue;
                    }
                    let epoch = flowride_time(f.d(18));
                    if self.admit(epoch, &mut progress_start) {
                        self.det.process_flowride(&f, epoch);
                    }
                }
                Format::Pcap | Format::Plive => unreachable!("packet formats use read_packets"),
            }
        };
        println!("Read {nlines} lines");
        Ok(end)
    }

    /// Read packets (`pcap` or `plive`).
    pub fn read_packets(&mut self, src: &mut dyn PacketSource) -> ReadEnd {
        println!("Reading from file");
        let mut progress_start = now();
        let mut nlines: u64 = 0;
        let end = loop {
            let Some((sec, usec, data)) = src.next_packet(self.stop) else {
                break ReadEnd::Eof;
            };
            if self.stop.load(Ordering::Relaxed) {
                break ReadEnd::Interrupted;
            }
            nlines += 1;
            if data.len() < 14 || u16::from_be_bytes([data[12], data[13]]) != 0x0800 {
                continue;
            }
            let epoch = sec as f64 + usec as f64 / 1_000_000.0;
            if self.admit(epoch, &mut progress_start) {
                self.det.process_packet(&data, epoch);
            }
        };
        if self.stop.load(Ordering::Relaxed) {
            return ReadEnd::Interrupted;
        }
        println!("Read {nlines} lines");
        end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_follow_delimiter_indexing() {
        let line = b"2|1453485557|768|1453485557|768|6|0|0|0|2379511808|44694|0|0|0|2792759296|995|0|0|0|0|2|0|1|40\n";
        let f = Fields::split(line, b'|');
        assert_eq!(f.delimiters(), 23);
        assert_eq!(f.d(0), b"1453485557");
        assert_eq!(f.d(4), b"6");
        assert_eq!(f.d(8), b"2379511808");
        assert_eq!(f.d(9), b"44694");
        assert_eq!(f.d(13), b"2792759296");
        assert_eq!(f.d(14), b"995");
        assert_eq!(f.d(19), b"2");
        assert_eq!(f.d(21), b"1");
        assert_eq!(f.d(22), b"40\n");
        assert_eq!(f.d(40), b"");
    }

    #[test]
    fn nfdump_layouts_agree() {
        let v16 = b"2|1453485557|768|1453485558|5|6|0|0|0|2379511808|44694|0|0|0|2792759296|995|0|0|0|0|2|0|7|40\n";
        let v17 = b"2|1453485557768|1453485558005|6|0|0|0|2379511808|44694|0|0|0|2792759296|995|0|0|0|0|2|0|7|40\n";
        let (a, b) = (Fields::split(v16, b'|'), Fields::split(v17, b'|'));
        let (la, lb) = (NfLayout::of(&a), NfLayout::of(&b));
        assert!(!la.v17 && lb.v17);
        assert_eq!(la.start(&a), lb.start(&b));
        assert_eq!(la.end(&a), lb.end(&b));
        for old in [4, 8, 9, 13, 14, 19, 21, 22] {
            assert_eq!(a.d(la.idx(old)), b.d(lb.idx(old)), "field {old}");
        }
    }

    #[test]
    fn flowride_timestamps() {
        assert_eq!(
            flowride_time(b"1576613073700960814\n"),
            1576613073.0 + 700960814.0 / 1e9
        );
        assert_eq!(flowride_time(b"15"), 15.0);
    }

    #[test]
    fn tsresol() {
        assert_eq!(tsresol_units(6), 1_000_000);
        assert_eq!(tsresol_units(9), 1_000_000_000);
        assert_eq!(tsresol_units(0x80 | 10), 1024);
    }
}

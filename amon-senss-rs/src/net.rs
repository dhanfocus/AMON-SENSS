//! Address helpers and the two lookup tables loaded at start-up: service
//! ports (`services.txt`) and protected local prefixes (`localprefs.txt`).

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::cnum::atoi;

/// `todec()`: dotted quad to integer. Like the original it simply treats any
/// non-digit as a separator and wraps on overflow.
pub fn todec(ip: &[u8]) -> u32 {
    let mut res: u32 = 0;
    let mut dec: u32 = 0;
    for &c in ip {
        if c.is_ascii_digit() {
            dec = dec.wrapping_mul(10).wrapping_add((c - b'0') as u32);
        } else {
            res = res.wrapping_mul(256).wrapping_add(dec);
            dec = 0;
        }
    }
    res.wrapping_mul(256).wrapping_add(dec)
}

/// `toip()`: integer to dotted quad.
pub fn toip(addr: u32) -> String {
    let [a, b, c, d] = addr.to_be_bytes();
    format!("{a}.{b}.{c}.{d}")
}

/// `isspecial()`: ports that carry a lot of one-way UDP (QUIC, IPsec NAT-T, ...).
pub fn is_special(port: i32) -> bool {
    matches!(port, 443 | 80 | 4500 | 4501 | 8080)
}

/// Service ports of interest.
#[derive(Default, Debug)]
pub struct Services {
    ports: HashSet<i32>,
}

impl Services {
    /// `loadservices()`: whitespace-separated integers, read until the first
    /// token that is not an integer. A missing file yields an empty table.
    pub fn load(path: &Path) -> Services {
        let mut ports = HashSet::new();
        if let Ok(text) = fs::read_to_string(path) {
            for tok in text.split_ascii_whitespace() {
                match tok.parse::<i64>() {
                    Ok(p) => {
                        ports.insert(p as i32);
                    }
                    Err(_) => break,
                }
            }
        } else {
            eprintln!("Warning: could not read {}", path.display());
        }
        Services { ports }
    }

    pub fn from_ports(ports: impl IntoIterator<Item = i32>) -> Services {
        Services {
            ports: ports.into_iter().collect(),
        }
    }

    /// `isservice()`. Takes the port as the original did, i.e. after it had
    /// been stored in a `short`, so ports above 32767 arrive negative and
    /// never match.
    pub fn contains(&self, port: i32) -> bool {
        self.ports.contains(&port)
    }

    pub fn len(&self) -> usize {
        self.ports.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ports.is_empty()
    }
}

/// Local (protected) address space, stored as sets of /24 and /30 blocks.
#[derive(Default, Debug)]
pub struct LocalPrefixes {
    pref24: HashSet<u32>,
    pref30: HashSet<u32>,
}

impl LocalPrefixes {
    /// `loadprefixes()`: one `a.b.c.d/len` per whitespace-separated token.
    /// IPv6 prefixes are skipped. As in the original the address is *not*
    /// masked before it is inserted, so `10.0.0.5/24` does not cover
    /// `10.0.0.0/24`; write prefixes with their network address.
    pub fn load(path: &Path) -> LocalPrefixes {
        let mut lp = LocalPrefixes::default();
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(_) => {
                eprintln!("Warning: could not read {}", path.display());
                return lp;
            }
        };
        for pref in text.split_ascii_whitespace() {
            println!("Prefix {pref}");
            lp.add(pref);
        }
        lp
    }

    /// Add one prefix token; returns false if it was skipped.
    pub fn add(&mut self, pref: &str) -> bool {
        if pref.contains(':') {
            println!("IPv6");
            return false;
        }
        let Some((addr, mask)) = pref.split_once('/') else {
            return false;
        };
        let mask = atoi(mask.as_bytes()).max(0);
        let mut dpref = todec(addr.as_bytes());
        if mask <= 24 {
            for _ in 0..(1u64 << (24 - mask)) {
                self.pref24.insert(dpref);
                dpref = dpref.wrapping_add(256);
            }
        } else {
            // The original computed `1 << (30 - mask)`, which is undefined for
            // /31 and /32; here those simply cover their enclosing /30.
            let count = if mask <= 30 {
                1u64 << (30 - mask)
            } else {
                dpref &= 0xffff_fffc;
                1
            };
            for _ in 0..count {
                self.pref30.insert(dpref);
                dpref = dpref.wrapping_add(4);
            }
        }
        true
    }

    /// `islocal()`.
    pub fn contains(&self, ip: u32) -> bool {
        self.pref24.contains(&(ip & 0xffff_ff00)) || self.pref30.contains(&(ip & 0xffff_fffc))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotted_quads() {
        assert_eq!(todec(b"10.0.0.5"), 0x0a00_0005);
        assert_eq!(toip(0x0a00_0005), "10.0.0.5");
        assert_eq!(toip(todec(b"255.255.255.255")), "255.255.255.255");
        assert_eq!(todec(b"129.82.138.44"), 2169670188);
    }

    #[test]
    fn prefixes() {
        let mut lp = LocalPrefixes::default();
        assert!(lp.add("10.1.0.0/16"));
        assert!(lp.add("192.168.1.8/29"));
        assert!(lp.add("172.16.0.1/32"));
        assert!(!lp.add("2001:db8::/32"));
        assert!(!lp.add("garbage"));
        assert!(lp.contains(todec(b"10.1.200.7")));
        assert!(!lp.contains(todec(b"10.2.0.1")));
        assert!(lp.contains(todec(b"192.168.1.15")));
        assert!(!lp.contains(todec(b"192.168.1.16")));
        assert!(lp.contains(todec(b"172.16.0.3")));
    }

    #[test]
    fn unmasked_prefix_quirk() {
        let mut lp = LocalPrefixes::default();
        lp.add("10.0.0.5/24");
        assert!(!lp.contains(todec(b"10.0.0.5")));
    }
}

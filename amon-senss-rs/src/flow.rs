//! Flow keys / attack signatures (`flow_t` in the original) and the helper
//! predicates that operate on them.

use crate::consts::{ICMP, TCP, UDP};
use crate::net::toip;

/// A flow 5-tuple plus TCP flags. Also used as an attack signature, in which
/// case "unset" fields are `0` for addresses and `-1` for ports.
///
/// Field widths deliberately match the C++ original (`short` ports,
/// `unsigned char` protocol): ports above 32767 are stored as negative
/// numbers, exactly as they were there, which affects service-port lookups.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flow {
    pub src: u32,
    pub sport: i16,
    pub dst: u32,
    pub dport: i16,
    pub proto: u8,
    pub flags: i32,
    pub slocal: bool,
    pub dlocal: bool,
}

impl Default for Flow {
    /// The constructor defaults of `flow_t` (`proto = -1` wraps to 255).
    fn default() -> Self {
        Flow {
            src: 0,
            sport: -1,
            dst: 0,
            dport: -1,
            proto: 255,
            flags: 0,
            slocal: false,
            dlocal: false,
        }
    }
}

impl Flow {
    /// All-zero flow, which is what freshly `calloc`ed memory held in the original.
    pub const ZERO: Flow = Flow {
        src: 0,
        sport: 0,
        dst: 0,
        dport: 0,
        proto: 0,
        flags: 0,
        slocal: false,
        dlocal: false,
    };

    /// `flow_t::operator==`: compares the 5-tuple but not the flags.
    pub fn same_tuple(&self, rhs: &Flow) -> bool {
        self.src == rhs.src
            && self.dst == rhs.dst
            && self.sport == rhs.sport
            && self.dport == rhs.dport
            && self.proto == rhs.proto
    }

    /// `empty()`: the signature has no address, port or flag set (protocol
    /// does not count).
    pub fn is_empty(&self) -> bool {
        self.src == 0
            && (self.sport == -1 || self.sport == 0)
            && self.dst == 0
            && (self.dport == -1 || self.dport == 0)
            && self.flags == 0
    }

    /// `zeros()`: number of unset fields. In the original the protocol test
    /// compared an `unsigned char` with `-1` and was therefore always false,
    /// so the protocol never counts.
    pub fn zeros(&self) -> i32 {
        (self.src == 0) as i32
            + (self.sport == -1) as i32
            + (self.dst == 0) as i32
            + (self.dport == -1) as i32
            + (self.flags == 0) as i32
    }

    /// `match()`: does this flow match the given signature?
    pub fn matches(&self, sig: &Flow) -> bool {
        if self.proto != sig.proto && sig.proto != 0 {
            return false;
        }
        if sig.is_empty() {
            return false;
        }
        (self.src == sig.src || sig.src == 0)
            && (self.sport == sig.sport || sig.sport == -1)
            && (self.dst == sig.dst || sig.dst == 0)
            && (self.dport == sig.dport || sig.dport == -1)
            && ((self.flags & sig.flags) > 0 || sig.flags == 0)
    }

    /// `printsignature()`: human-readable form used in `alerts.txt`.
    pub fn signature(&self) -> String {
        let mut out = String::new();
        if self.src != 0 {
            out.push_str("src ip ");
            out.push_str(&toip(self.src));
        }
        if self.sport != -1 && (self.sport != -2 || self.proto != ICMP) {
            if !out.is_empty() {
                out.push_str(" and ");
            }
            out.push_str(&format!("src port {}", self.sport as u16));
        }
        if !out.is_empty() {
            out.push_str(" and ");
        }
        out.push_str("dst ip ");
        out.push_str(&toip(self.dst));
        if self.dport != -1 && (self.dport != -2 || self.proto != ICMP) {
            out.push_str(&format!(" and dst port {}", self.dport as u16));
        }
        match self.proto {
            TCP => out.push_str(" and proto tcp"),
            UDP => out.push_str(" and proto udp"),
            ICMP => out.push_str(" and proto icmp"),
            _ => {}
        }
        if self.proto == TCP {
            out.push_str(&format!(" and flags {}", self.flags));
        }
        out
    }
}

/// `bettersig(a, b)`: is `a` a better (more specific, but not too specific)
/// signature than `b`?
pub fn better_sig(a: &Flow, b: &Flow) -> bool {
    if b.is_empty() {
        return true;
    }
    a.zeros() <= b.zeros()
        && a.src == 0
        && ((a.sport != -1 && a.dport == -1) || (a.dport != -1 && a.sport == -1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::todec;

    #[test]
    fn signature_text() {
        let mut f = Flow {
            sport: 53,
            dst: todec(b"10.0.0.5"),
            proto: UDP,
            ..Flow::default()
        };
        assert_eq!(
            f.signature(),
            "src port 53 and dst ip 10.0.0.5 and proto udp"
        );
        f.proto = TCP;
        f.sport = -1;
        f.dport = 80;
        f.flags = 2;
        assert_eq!(
            f.signature(),
            "dst ip 10.0.0.5 and dst port 80 and proto tcp and flags 2"
        );
        let icmp = Flow {
            sport: -2,
            dport: -2,
            dst: todec(b"10.0.0.9"),
            proto: ICMP,
            ..Flow::default()
        };
        assert_eq!(icmp.signature(), "dst ip 10.0.0.9 and proto icmp");
        let high = Flow {
            src: todec(b"1.2.3.4"),
            sport: 40000u16 as i16,
            dst: 1,
            proto: 0,
            ..Flow::default()
        };
        assert_eq!(
            high.signature(),
            "src ip 1.2.3.4 and src port 40000 and dst ip 0.0.0.1"
        );
    }

    #[test]
    fn emptiness_and_matching() {
        assert!(Flow::default().is_empty());
        assert!(Flow::ZERO.is_empty());
        let sig = Flow {
            dst: 7,
            dport: 80,
            proto: TCP,
            ..Flow::default()
        };
        let flow = Flow {
            src: 1,
            sport: 1234,
            dst: 7,
            dport: 80,
            proto: TCP,
            flags: 2,
            ..Flow::default()
        };
        assert!(flow.matches(&sig));
        assert!(!Flow { dport: 81, ..flow }.matches(&sig));
        assert!(!Flow { proto: UDP, ..flow }.matches(&sig));
        let any_proto = Flow { proto: 0, ..sig };
        assert!(Flow { proto: UDP, ..flow }.matches(&any_proto));
    }

    #[test]
    fn better_signature() {
        let empty = Flow::default();
        let a = Flow {
            dst: 5,
            sport: 53,
            proto: UDP,
            ..Flow::default()
        };
        assert!(better_sig(&a, &empty));
        let both_ports = Flow { dport: 99, ..a };
        assert!(!better_sig(&both_ports, &a));
        let with_src = Flow { src: 9, ..a };
        assert!(!better_sig(&with_src, &a));
    }
}

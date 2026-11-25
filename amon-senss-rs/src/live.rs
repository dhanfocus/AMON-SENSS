//! Live capture from a network interface (`-F plive`), behind the `live`
//! cargo feature because it links against libpcap.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::consts::MAXLINE;
use crate::input::PacketSource;

pub struct LiveCapture {
    cap: pcap::Capture<pcap::Active>,
}

impl LiveCapture {
    /// Open `iface` in promiscuous mode with the original's snaplen and a
    /// one-second read timeout.
    pub fn open(iface: &str) -> Result<LiveCapture, pcap::Error> {
        let cap = pcap::Capture::from_device(iface)?
            .snaplen(MAXLINE as i32)
            .promisc(true)
            .timeout(1000)
            .open()?;
        Ok(LiveCapture { cap })
    }
}

impl PacketSource for LiveCapture {
    fn next_packet(&mut self, stop: &AtomicBool) -> Option<(i64, i64, Vec<u8>)> {
        loop {
            if stop.load(Ordering::Relaxed) {
                return None;
            }
            match self.cap.next_packet() {
                Ok(p) => {
                    let ts = p.header.ts;
                    // time_t / suseconds_t widths differ between platforms.
                    #[allow(clippy::unnecessary_cast)]
                    return Some((ts.tv_sec as i64, ts.tv_usec as i64, p.data.to_vec()));
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => {
                    eprintln!("live capture error: {e}");
                    return None;
                }
            }
        }
    }
}

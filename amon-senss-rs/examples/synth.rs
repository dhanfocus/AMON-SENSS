//! Write deterministic synthetic traffic to stdout.
//!
//! Usage: `cargo run --example synth -- <nf|fr|pcap|config|prefixes> [scenario]`
//!
//! Used to regenerate the golden files in `tests/golden/` with the original
//! C++ implementation; see `tests/golden/README.md`.

#[path = "../tests/common/synth.rs"]
mod synth;

use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let what = args.get(1).map(String::as_str).unwrap_or("nf");
    let name = args.get(2).map(String::as_str).unwrap_or("basic");
    let mut out = std::io::stdout().lock();
    let bytes: Vec<u8> = match what {
        "config" => synth::CONFIG.as_bytes().to_vec(),
        "prefixes" => synth::PREFIXES.as_bytes().to_vec(),
        "nf" => synth::to_nfdump(&synth::generate(&synth::scenario(name))).into_bytes(),
        "fr" => synth::to_flowride(&synth::generate(&synth::scenario(name))).into_bytes(),
        "pcap" => synth::to_pcap(&synth::generate(&synth::scenario(name))),
        other => {
            eprintln!("unknown output {other}; expected nf, fr, pcap, config or prefixes");
            std::process::exit(2);
        }
    };
    out.write_all(&bytes).expect("write");
}

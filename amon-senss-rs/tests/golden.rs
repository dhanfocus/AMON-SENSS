//! Golden tests: run the `amonsenss` binary on deterministic synthetic
//! traffic and compare `alerts.txt` and `as.dump` with the output of the
//! original C++ implementation on the same input (see `tests/golden/`).

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

use common::synth;

fn fnv(bytes: &[u8]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h = (h ^ b as u64).wrapping_mul(0x100_0000_01b3);
    }
    format!("{h:016x}")
}

/// A fresh working directory with config, services and prefixes.
fn workdir(case: &str, keep: bool) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("golden")
        .join(case);
    if !keep {
        let _ = fs::remove_dir_all(&dir);
    }
    fs::create_dir_all(&dir).unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::copy(root.join("services.txt"), dir.join("services.txt")).unwrap();
    fs::write(dir.join("amonsenss.config"), synth::CONFIG).unwrap();
    fs::write(dir.join("localprefs.txt"), synth::PREFIXES).unwrap();
    dir
}

fn run(dir: &Path, args: &[&str], stdin: Option<&[u8]>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_amonsenss"))
        .args(args)
        .current_dir(dir)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start amonsenss");
    if let Some(data) = stdin {
        let mut s = child.stdin.take().unwrap();
        s.write_all(data).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "amonsenss {args:?} failed: {}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

struct Golden {
    lines: usize,
    alerts_fnv: String,
    dump_fnv: String,
    sigs: BTreeMap<String, usize>,
}

fn parse_golden(text: &str) -> Golden {
    let mut g = Golden {
        lines: 0,
        alerts_fnv: String::new(),
        dump_fnv: String::new(),
        sigs: BTreeMap::new(),
    };
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let (key, rest) = line.split_once(' ').unwrap_or((line, ""));
        match key {
            "alerts_lines" => g.lines = rest.parse().unwrap(),
            "alerts_fnv" => g.alerts_fnv = rest.to_string(),
            "dump_fnv" => g.dump_fnv = rest.to_string(),
            "sig" => {
                let (n, sig) = rest.split_once(' ').unwrap_or((rest, ""));
                g.sigs.insert(sig.to_string(), n.parse().unwrap());
            }
            _ => panic!("bad golden line {line:?}"),
        }
    }
    g
}

fn histogram(alerts: &str) -> BTreeMap<String, usize> {
    let mut h = BTreeMap::new();
    for line in alerts.lines().skip(1) {
        let sig = line.splitn(8, ' ').nth(7).unwrap_or("").to_string();
        *h.entry(sig).or_insert(0) += 1;
    }
    h
}

fn check(case: &str, dir: &Path) {
    let golden_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(format!("{case}.txt"));
    let g = parse_golden(&fs::read_to_string(&golden_path).unwrap());
    let alerts = fs::read(dir.join("alerts.txt")).unwrap();
    let text = String::from_utf8_lossy(&alerts);
    let dump_fnv = fs::read(dir.join("as.dump"))
        .map(|d| fnv(&d))
        .unwrap_or_else(|_| "none".into());

    let hist = histogram(&text);
    if hist != g.sigs {
        let mut msg = String::new();
        for k in hist
            .keys()
            .chain(g.sigs.keys())
            .collect::<std::collections::BTreeSet<_>>()
        {
            let (a, b) = (
                hist.get(k).copied().unwrap_or(0),
                g.sigs.get(k).copied().unwrap_or(0),
            );
            if a != b {
                msg.push_str(&format!("  {k:?}: got {a}, expected {b}\n"));
            }
        }
        panic!(
            "{case}: alert signatures differ from the reference:\n{msg}(output kept in {})",
            dir.display()
        );
    }
    assert_eq!(
        text.lines().count(),
        g.lines,
        "{case}: number of alert lines"
    );
    assert_eq!(
        fnv(&alerts),
        g.alerts_fnv,
        "{case}: alerts.txt differs (kept in {})",
        dir.display()
    );
    assert_eq!(
        dump_fnv,
        g.dump_fnv,
        "{case}: as.dump differs (kept in {})",
        dir.display()
    );
}

fn nfdump(scenario: &str) -> Vec<u8> {
    synth::to_nfdump(&synth::generate(&synth::scenario(scenario))).into_bytes()
}

#[test]
fn nf_basic() {
    let dir = workdir("nf-basic", false);
    run(&dir, &["-S", "-F", "nf", "-f"], Some(&nfdump("basic")));
    check("nf-basic", &dir);
}

#[test]
fn nf_basic_without_filtering_prints_no_alerts() {
    let dir = workdir("nf-nofilter", false);
    run(&dir, &["-S", "-F", "nf"], Some(&nfdump("basic")));
    check("nf-nofilter", &dir);
}

#[test]
fn nf_reload_history() {
    // First run trains and writes as.dump; the second loads it with -l.
    let dir = workdir("nf-reload", false);
    let input = nfdump("basic");
    run(&dir, &["-S", "-F", "nf", "-f"], Some(&input));
    check("nf-basic", &dir);
    let dir = workdir("nf-reload", true);
    run(&dir, &["-l", "-S", "-F", "nf", "-f"], Some(&input));
    check("nf-reload", &dir);
}

#[test]
fn nf_big_hitters() {
    let dir = workdir("nf-bighitters", false);
    run(&dir, &["-S", "-F", "nf", "-f"], Some(&nfdump("bighitters")));
    check("nf-bighitters", &dir);
}

#[test]
fn flowride_basic() {
    let dir = workdir("fr-basic", false);
    let input = synth::to_flowride(&synth::generate(&synth::scenario("basic")));
    run(&dir, &["-S", "-F", "fr", "-f"], Some(input.as_bytes()));
    check("fr-basic", &dir);
}

#[test]
fn pcap_from_folder() {
    let dir = workdir("pcap-packets", false);
    let input_dir = dir.join("input");
    fs::create_dir_all(&input_dir).unwrap();
    let file = input_dir.join("packets.pcap");
    fs::write(
        &file,
        synth::to_pcap(&synth::generate(&synth::scenario("packets"))),
    )
    .unwrap();
    // Files are only read once they are older than a minute.
    let old = SystemTime::now() - Duration::from_secs(3600);
    fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(old)
        .unwrap();
    run(&dir, &["-r", "input", "-F", "pcap", "-f", "--once"], None);
    check("pcap-packets", &dir);
}

#[test]
fn missing_input_is_an_error() {
    let dir = workdir("no-input", false);
    let out = Command::new(env!("CARGO_BIN_EXE_amonsenss"))
        .args(["-F", "nf"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(!out.status.success());
}

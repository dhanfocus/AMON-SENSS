//! `amonsenss` command-line program.
//!
//! Copyright (C) 2018 University of Southern California.
//! This program is free software; you can redistribute it and/or modify it
//! under the terms of the GNU General Public License, version 2, as published
//! by the Free Software Foundation. See `COPYING`.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;

use amon_senss::input::{PcapFile, ReadEnd, Reader};
use amon_senss::{Detector, Format, LocalPrefixes, Params, Services};

const CONFIG_FILE: &str = "amonsenss.config";
const SERVICES_FILE: &str = "services.txt";
const PREFIXES_FILE: &str = "localprefs.txt";
const ALERTS_FILE: &str = "alerts.txt";
const DUMP_FILE: &str = "as.dump";
/// Files are only picked up once they have not been modified for this long.
const MIN_FILE_AGE_SECS: i64 = 60;

/// AMON-SENSS: scalable detection of DDoS attacks and creation of signatures
/// for attack filtering. (C) 2018 University of Southern California.
///
/// Reads amonsenss.config, services.txt and localprefs.txt from the current
/// directory and appends alerts to alerts.txt.
#[derive(Parser, Debug)]
#[command(name = "amonsenss", version)]
struct Cli {
    /// Streaming input from stdin
    #[arg(short = 'S')]
    stream: bool,

    /// Input is in given file or folder (read recursively), or live on the
    /// specified iface. May be repeated.
    #[arg(short = 'r', value_name = "FILE|FOLDER|IFACE")]
    inputs: Vec<String>,

    /// Load historical data from as.dump
    #[arg(short = 'l')]
    load: bool,

    /// Input is in this format
    #[arg(short = 'F', value_enum, value_name = "FORMAT")]
    format: Option<Format>,

    /// Start from this given file in the input folder
    #[arg(short = 's', value_name = "FILE")]
    start_file: Option<String>,

    /// End with this given file in the input folder
    #[arg(short = 'e', value_name = "FILE")]
    end_file: Option<String>,

    /// Simulate filtering; without this no alerts are printed
    #[arg(short = 'f')]
    sim_filter: bool,

    /// Verbose (very chatty debugging output)
    #[arg(short = 'v')]
    verbose: bool,

    /// Process the files present now and exit, instead of watching the
    /// input folders for new files forever
    #[arg(long)]
    once: bool,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn age_secs(meta: &fs::Metadata) -> i64 {
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    now() - mtime
}

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

fn save_and_exit(det: &Detector, code: i32) -> ! {
    println!("Caught signal {code}");
    if let Err(e) = det.save_history(Path::new(DUMP_FILE)) {
        eprintln!("Could not save {DUMP_FILE}: {e}");
    }
    let _ = io::stdout().flush();
    std::process::exit(code);
}

/// Start the external decoder for a flow file.
fn spawn_decoder(format: Format, file: &str) -> io::Result<Child> {
    match format {
        Format::Nf => Command::new("nfdump")
            .args(["-r", file, "-o", "pipe"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn(),
        Format::Ft => {
            let mut ft = Command::new("ft2nfdump")
                .args(["-r", file])
                .stdout(Stdio::piped())
                .spawn()?;
            let ft_out = ft.stdout.take().expect("piped stdout");
            let nf = Command::new("nfdump")
                .args(["-r", "-", "-o", "pipe"])
                .stdin(ft_out)
                .stdout(Stdio::piped())
                .spawn();
            // ft2nfdump is reaped by the OS when we exit; detach it.
            std::thread::spawn(move || {
                let _ = ft.wait();
            });
            nf
        }
        Format::Fr => Command::new("gunzip")
            .args(["-c", file])
            .stdout(Stdio::piped())
            .spawn(),
        Format::Pcap | Format::Plive => unreachable!(),
    }
}

/// Read one input file of the given format.
fn read_file(reader: &mut Reader, format: Format, file: &str) -> ReadEnd {
    match format {
        Format::Pcap | Format::Plive => {
            let f = match File::open(file) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Could not open {file}: {e}");
                    return ReadEnd::Eof;
                }
            };
            match PcapFile::open(BufReader::new(f)) {
                Ok(mut src) => reader.read_packets(&mut src),
                Err(e) => {
                    eprintln!("Could not read {file} as pcap: {e}");
                    ReadEnd::Eof
                }
            }
        }
        _ => {
            let mut child = match spawn_decoder(format, file) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Could not start decoder for {file}: {e}");
                    return ReadEnd::Eof;
                }
            };
            let stdout = child.stdout.take().expect("piped stdout");
            let mut input = BufReader::new(stdout);
            let end = reader.read_text(&mut input, format).unwrap_or_else(|e| {
                eprintln!("Error reading {file}: {e}");
                ReadEnd::Eof
            });
            drop(input);
            let _ = child.wait();
            end
        }
    }
}

#[cfg(feature = "live")]
fn run_live(reader: &mut Reader, ifaces: &[String]) -> ReadEnd {
    let iface = &ifaces[0];
    if ifaces.len() > 1 {
        eprintln!("Live capture reads a single interface; using {iface}");
    }
    match amon_senss::live::LiveCapture::open(iface) {
        Ok(mut cap) => reader.read_packets(&mut cap),
        Err(e) => {
            eprintln!("Could not open interface {iface}: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(feature = "live"))]
fn run_live(_reader: &mut Reader, _ifaces: &[String]) -> ReadEnd {
    eprintln!("This build has no live capture support; rebuild with `cargo build --release --features live`");
    std::process::exit(1);
}

fn main() {
    let cli = Cli::parse();

    // Touch the alerts file.
    if let Err(e) = fs::write(
        ALERTS_FILE,
        "#attackID intID start-time bin bytes packets signature\n",
    ) {
        eprintln!("Could not create {ALERTS_FILE}: {e}");
        std::process::exit(1);
    }
    // Like the original, -l is acted on while the options are parsed, before
    // the configuration is read.
    let mut det = Detector::new(
        Params::default(),
        Services::default(),
        LocalPrefixes::default(),
    );
    if cli.load {
        if let Err(e) = det.load_history(Path::new(DUMP_FILE)) {
            eprintln!("Could not load {DUMP_FILE}: {e}");
            std::process::exit(1);
        }
    }
    if let Some(s) = &cli.start_file {
        println!("Start file {s}");
    }
    if let Some(e) = &cli.end_file {
        println!("End file {e}");
    }
    if cli.inputs.is_empty() && !cli.stream {
        eprintln!("You must specify an input folder, which holds Netflow records");
        std::process::exit(255);
    }
    let Some(format) = cli.format else {
        eprintln!("You must specify the input format with -F <pcap|plive|ft|nf|fr>");
        std::process::exit(1);
    };
    println!("Verbose {}", cli.verbose as i32);
    let services = Services::load(Path::new(SERVICES_FILE));
    let prefixes = LocalPrefixes::load(Path::new(PREFIXES_FILE));
    let params = match Params::load(Path::new(CONFIG_FILE)) {
        Ok(p) => p,
        Err(_) => {
            println!("Config file {CONFIG_FILE} does not exist. Please include it and re-run.. ");
            std::process::exit(0);
        }
    };

    det.params = params;
    det.services = services;
    det.prefixes = prefixes;
    det.sim_filter = cli.sim_filter;
    det.verbose = cli.verbose;

    // First SIGINT: finish the current record, save as.dump and exit.
    // A second SIGINT exits immediately.
    let stop = Arc::new(AtomicBool::new(false));
    let sigint = signal_hook::consts::SIGINT;
    signal_hook::flag::register_conditional_shutdown(sigint, 130, Arc::clone(&stop))
        .expect("signal handler");
    signal_hook::flag::register(sigint, Arc::clone(&stop)).expect("signal handler");

    let mut allflows: u64 = 0;
    let mut reader = Reader {
        det: &mut det,
        stop: &stop,
        allflows: &mut allflows,
    };

    if cli.stream {
        let end = if format == Format::Pcap || format == Format::Plive {
            match PcapFile::open(io::stdin().lock()) {
                Ok(mut src) => reader.read_packets(&mut src),
                Err(e) => {
                    eprintln!("Could not read stdin as pcap: {e}");
                    std::process::exit(1);
                }
            }
        } else {
            let stdin = io::stdin();
            let mut lock = stdin.lock();
            reader.read_text(&mut lock, format).unwrap_or_else(|e| {
                eprintln!("Error reading stdin: {e}");
                ReadEnd::Eof
            })
        };
        if end == ReadEnd::Interrupted {
            save_and_exit(reader.det, 2);
        }
    } else if format == Format::Plive {
        if run_live(&mut reader, &cli.inputs) == ReadEnd::Interrupted {
            save_and_exit(reader.det, 2);
        }
    } else {
        let mut startfile = cli.start_file.clone();
        let mut tracefiles: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut first = true;
        loop {
            if !first {
                // Poll for new files once per second.
                sleep(Duration::from_secs(1));
            }
            if stop.load(Ordering::Relaxed) {
                save_and_exit(reader.det, 2);
            }
            let mut newfiles: Vec<String> = Vec::new();
            let mut inputs: Vec<String> = cli.inputs.clone();
            let mut i = 0;
            while i < inputs.len() {
                if let Ok(meta) = fs::metadata(&inputs[i]) {
                    if meta.is_dir() {
                        match fs::read_dir(&inputs[i]) {
                            Ok(rd) => {
                                let mut names: Vec<String> = rd
                                    .filter_map(|e| e.ok())
                                    .map(|e| e.file_name().to_string_lossy().into_owned())
                                    .collect();
                                names.sort();
                                for name in names {
                                    inputs.push(format!("{}/{}", inputs[i], name));
                                }
                            }
                            Err(e) => {
                                eprintln!("Could not read directory {}: {e}", inputs[i]);
                                std::process::exit(1);
                            }
                        }
                    } else if meta.is_file()
                        && !seen.contains(&inputs[i])
                        && age_secs(&meta) > MIN_FILE_AGE_SECS
                    {
                        seen.insert(inputs[i].clone());
                        tracefiles.push(inputs[i].clone());
                        if !first {
                            newfiles.push(inputs[i].clone());
                        }
                    }
                }
                i += 1;
            }
            let processfiles = if first {
                &mut tracefiles
            } else {
                &mut newfiles
            };
            processfiles.sort_by(|a, b| basename(a).cmp(basename(b)));
            for f in processfiles.iter() {
                println!("Files to read {f}");
            }
            let processfiles = processfiles.clone();
            let mut started = startfile.is_none();
            for file in &processfiles {
                if !started {
                    if let Some(s) = &startfile {
                        if !file.contains(s.as_str()) {
                            continue;
                        }
                    }
                }
                started = true;
                startfile = None;
                println!("Reading from {file}");
                reader.det.firsttimeinfile = 0.0;
                if read_file(&mut reader, format, file) == ReadEnd::Interrupted {
                    save_and_exit(reader.det, 2);
                }
                println!(
                    "Done with the file {file} time {} flows {} training {} shuffle {}",
                    now(),
                    reader.allflows,
                    reader.det.training_done as i32,
                    reader.det.shuffle_done as i32
                );
                if let Some(e) = &cli.end_file {
                    if file.contains(e.as_str()) {
                        break;
                    }
                }
            }
            first = false;
            if cli.once {
                break;
            }
        }
    }

    if let Err(e) = reader.det.save_history(Path::new(DUMP_FILE)) {
        eprintln!("Could not save {DUMP_FILE}: {e}");
    }
}

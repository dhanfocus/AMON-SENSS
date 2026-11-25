# AMON-SENSS (Rust)

A Rust port of [AMON-SENSS](https://steel.isi.edu/projects/SENSS/), software
for scalable detection of DDoS attacks and creation of signatures for attack
filtering. Signatures and alerts are written in real time to `alerts.txt`.

You will discover when you run this tool that many attacks get detected.
Today's traffic is often one-way and has many anomalies that AMON-SENSS picks
up. Use the `read_alerts` script to narrow the output down to attacks with high
confidence.

The port is behaviour-compatible with the C++ original (version 1.1). Given the
same input and configuration, it writes a byte-identical `alerts.txt` and
`as.dump`. The test suite checks this against output recorded from the
original (see [Testing](#testing)). It is also about three times faster and
needs far less memory, because it keeps one interval of counters per layer
instead of a queue of 100.

## Building

Requires Rust 1.75 or newer.

```bash
cargo build --release
```

The binary is `target/release/amonsenss`. Live capture from an interface
(`-F plive`) is optional because it links against libpcap:

```bash
cargo build --release --features live
```

Reading pcap/pcapng files does not need libpcap.

## Configuration

`amonsenss` reads these files from the **current directory**:

| File | Purpose |
|------|---------|
| `amonsenss.config` | Parameters (`name=value`). A sample is provided. |
| `localprefs.txt` | Prefixes you want to protect, one `a.b.c.d/len` per line. Replace the sample with your own. Write each prefix with its network address (`10.0.0.0/24`, not `10.0.0.5/24`). |
| `services.txt` | Service ports of interest. You don't need to change it. |

Parameters in `amonsenss.config`:

| Name | Meaning |
|------|---------|
| `interval` | Seconds between detection runs |
| `file_interval` | Seconds of traffic covered by each input file. Flows more than 2× this outside the first timestamp of a file are dropped. 0 disables the upper bound. |
| `attack_low` | Abnormality score at which an attack is signalled |
| `attack_high` | Cap on the abnormality score |
| `min_train` | Seconds of training before detection starts |
| `filter_thresh` | Fraction of the attack a signature must cover |
| `min_oci` | Minimum estimated attack packet rate to print an alert. If you see too many alerts, increase it. |
| `numstd`, `cusum_thresh` | Present for compatibility; not used by the detector (see below) |

`scripts/autoconfig` asks for these values interactively. Note that it writes
`as.config`; rename the file to `amonsenss.config`.

## Running

Typical usage:

```bash
./amonsenss -r /folder-w-nfdump -F nf -f > /dev/null
```

AMON-SENSS expects one or more files with NetFlow records (nfdump or
flow-tools format), pcap, or Flowride records. If you give a folder, it reads
every file in it and its subfolders, sorted by file name. It then keeps
watching the folders and processes new files as they appear. A file is picked
up once it hasn't been modified for 60 seconds.

```
-h                       Print help
-S                       Streaming input from stdin
-r <file|folder|iface>   Input file or folder (repeatable), or interface for plive
-l                       Load historical data from as.dump
-F <pcap|plive|ft|nf|fr> Input format:
                           pcap  - libpcap file (pcap or pcapng)
                           plive - live capture from an interface (needs --features live)
                           ft    - flow-tools files (needs ft2nfdump and nfdump)
                           nf    - nfdump files (needs nfdump)
                           fr    - gzipped Flowride files (needs gunzip)
-s <file>                Start from this file in the input folder
-e <file>                End with this file in the input folder
-f                       Simulate filtering; without this no alerts are printed
-v                       Verbose (very large debugging output)
--once                   Process the files present now and exit instead of
                         watching the folders (new in the Rust port)
```

Streaming example:

```bash
nfdump -R /data/flows -o pipe | ./amonsenss -S -F nf -f
```

Ongoing attacks produce a steady stream of alerts. Each line of `alerts.txt`
has the form:

```
attackID layer time START bin rate packets signature
```

When `alerts.txt` exceeds 10 MB, AMON-SENSS runs `./rotate` (see `scripts/`)
to rotate it.

Press Ctrl-C to stop: the current record is finished, the trained statistics
are saved to `as.dump`, and the program exits. A second Ctrl-C exits right
away.

To get condensed START/END messages for attacks:

```bash
perl scripts/read_alerts alerts.txt
```

This tool follows `alerts.txt` as it grows and prints a small number of
human-readable, actionable alerts. If you rotate `alerts.txt`, restart it.

To understand how AMON-SENSS works, see
<http://steel.isi.edu/projects/SENSS/amon-senss.pdf>.

## Differences from the C++ original

These don't change `alerts.txt` or `as.dump` for well-formed input:

* **Single-threaded.** The per-interval detection work ran on a detached
  thread that raced with flow processing. It now runs synchronously at each
  interval boundary, which makes results deterministic.
* **Memory safety.** Arrays are zero-initialised (the original relied on
  `malloc` returning zeroed memory). Over-long or truncated records and
  packets are bounds-checked: missing fields read as 0, and packets too short
  for their headers are skipped. Before, these read garbage.
* **`/31` and `/32` prefixes** in `localprefs.txt` cover their enclosing /30.
  In the original they were undefined behaviour: a /32 made it insert about
  a billion entries.
* **Directory scanning** checks the age of each file by its full path. The
  original called `stat()` on the bare entry name, relative to the current
  directory. Files and folders are discovered in sorted order.
* **External decoders** (`nfdump`, `ft2nfdump`, `gunzip`) get the file name
  as an argument instead of through a shell command string.
* **`-F plive`** captures live from an interface (with `--features live`). In
  the original this mode never processed any packets.
* **pcap on stdin** (`-S -F pcap`) works; it crashed the original.
* `-F` is required (it was an uninitialised pointer when omitted). `-h` no
  longer truncates `alerts.txt`. `--once` is new.
* If `./rotate` is missing, a warning is printed once.

These quirks of the original are kept on purpose, because they decide which
alerts are produced:

* Ports are stored as 16-bit signed values, so service ports above 32767
  never match `services.txt`, and port 65535 reads as "no port".
* The detector reads a parameter called `num_std`, but the config file
  defines `numstd`, so the effective value is 0. `cusum_thresh` is unused.
* `localprefs.txt` entries are not masked to their network address.
* When statistics roll over into history, every layer is rolled over using
  the bin count of layer 0.
* The `-l` option restores the attack counter and "training done" state, but
  the big-hitter table is not saved. The per-bin statistics are therefore
  re-initialised once the big-hitter phase finishes.
* The input-stream checks (the nfdump `Sys` summary line, the 19 tab
  separators of Flowride records, the Flowride TCP-flag heuristics) are
  unchanged.
* Double-to-integer conversions follow x86-64 semantics: NaN or
  out-of-range values become `INT_MIN`.

## Not ported

The research and evaluation tooling of the original repository is not part
of this crate: `ground-truth/`, the RabbitMQ/AMQP helpers, `control.cc`,
`size.cc`, the SQL schemas, and the Perl scripts `sum_alerts`, `match.pl`
and `merge.pl`. The operational companion scripts `read_alerts`, `rotate`
and `autoconfig` are included unchanged in `scripts/`.

## Testing

```bash
cargo test
```

The golden tests in `tests/golden.rs` generate deterministic synthetic
traffic: background traffic plus DNS-reflection, SYN-flood and ICMP-flood
attacks, in nfdump, Flowride and pcap formats. They run `amonsenss` on it and
compare `alerts.txt` and `as.dump` with output recorded from the C++
original. `tests/golden/README.md` explains how to regenerate the expected
files.

## License

Copyright (C) 2018 University of Southern California.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License, version 2, as published by the
Free Software Foundation. It is distributed in the hope that it will be
useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See `COPYING` for
details.

Original authors: Jelena Mirkovic (AMON-SENSS); Michalis Kallitsis, Stilian
Stoev and George Michailidis (AMON, which inspired AMON-SENSS). For questions
about the method, contact Jelena Mirkovic <sunshine@isi.edu>.

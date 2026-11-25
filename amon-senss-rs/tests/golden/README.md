# Golden files

Each `<case>.txt` records what the **original C++ AMON-SENSS** produced for one
test case: the number of lines and an FNV-1a hash of `alerts.txt`, an FNV-1a
hash of `as.dump`, and a per-signature histogram of the alerts. When a test
fails, the histogram is used to report which signatures differ.

The inputs come from `tests/common/synth.rs`. They are deterministic and are
not stored. Any change to the generator or to `synth::CONFIG` means these
files must be regenerated.

## Regenerating

1. Build a deterministic copy of the original. In a scratch copy of
   `amonsenss.cc`, `utils.cc` and `utils.h` from the C++ repository:
   * replace `pthread_detach(thread_id);` with `pthread_join(thread_id, NULL);`
     so the per-interval work finishes before the next record, as in the port;
   * replace every `malloc(n)` in `malloc_all()` with `calloc(1, n)`;
   * after `first = false;` in `main()`, add
     `if (getenv("AMON_ONCE")) break;` (one pass over the input folder);
   * change the two `strstr(...) > 0` comparisons to `!= NULL` so it compiles
     with a current compiler.

   ```bash
   g++ -std=gnu++11 -O2 -w -o amonsenss-ref amonsenss.cc utils.cc -lpcap -lpthread
   ```

2. For each case, run the reference in an empty directory that contains
   `services.txt` from this crate, plus the output of
   `cargo run --example synth -- config > amonsenss.config` and
   `cargo run --example synth -- prefixes > localprefs.txt`:

   | Case | Input | Command |
   |------|-------|---------|
   | `nf-basic` | `synth -- nf basic` | `amonsenss-ref -S -F nf -f < input` |
   | `nf-nofilter` | `synth -- nf basic` | `amonsenss-ref -S -F nf < input` |
   | `nf-reload` | `synth -- nf basic` | in the `nf-basic` directory afterwards: `amonsenss-ref -l -S -F nf -f < input` |
   | `nf-bighitters` | `synth -- nf bighitters` | `amonsenss-ref -S -F nf -f < input` |
   | `fr-basic` | `synth -- fr basic` | `amonsenss-ref -S -F fr -f < input` |
   | `fr-folder` | `synth -- fr-part basic K 3` for K = 0, 1, 2, gzipped (`gzip -n`) as `in/b/fr-01.gz`, `in/a/fr-02.gz`, `in/fr-03.gz`; files **and folders** with mtime at least a minute old (the original checks the parent folder's mtime) | `AMON_ONCE=1 amonsenss-ref -r in -F fr -f` |
   | `fr-startend` | as `fr-folder` | `AMON_ONCE=1 amonsenss-ref -r in -F fr -f -s fr-01 -e fr-02` |
   | `pcap-packets` | `synth -- pcap packets` saved as `packets.pcap`, mtime at least a minute old | `AMON_ONCE=1 amonsenss-ref -r packets.pcap -F pcap -f` |

3. Write each `<case>.txt` from the resulting `alerts.txt` and `as.dump` in
   the format of the existing files. Hashes are 64-bit FNV-1a over the whole
   file, in lowercase hex. Histogram keys are the text after the seventh
   space of each alert line.

# ELFMint

**ELFMint** is a fail-soft validator for the metadata of ELF binaries. It reads the ELF
header, the program header table and, when present, the section header table of a file,
evaluates a catalogue of 30 checks, and reports every finding as machine-readable JSON with
the field and file offset involved, the *basis* of the rule that was violated (ELF
specification, loader behaviour, toolchain convention or heuristic) and the *threat class*
the finding belongs to (accidental corruption, anti-analysis, tampering, hygiene).

ELFMint was built as the measurement instrument of a study of the *loader–analyser gap*:
the set of ELF files that the Linux kernel and the dynamic linkers accept while analysis
tools reject, crash on or silently misread. Its design goals follow from that use:

* **It never aborts on a malformed file.** A first-level parser with bounds-checked accessors
  records every inconsistent field and continues; a malformed section header table does not
  prevent the program-header checks from running, and vice versa. The validator is fuzzed with
  a built-in harness (`--fuzz`) and is built with arithmetic-overflow checks enabled.
* **Every check says what kind of rule it applies.** A violation of the ELF specification that
  the kernel ignores, a property the kernel rejects, a convention of mainstream toolchains and
  a missing hardening feature are different things, and ELFMint keeps them apart instead of
  emitting an undifferentiated "warning".
* **Checks are context-aware.** Linkage, section-table status, UPX packing and the C-library
  family (glibc, musl, uClibc-ng, bionic) are determined first and decide which checks apply
  and which interpreter paths are conventional. Section-to-segment and hardening checks are
  not applied to relocatable objects such as kernel modules, where they would produce spurious
  findings.
* **Not a malware detector.** ELFMint reports structural facts. In vendor firmware and IoT
  malware alike, most anomalies are produced by toolchains, stripping tools and extraction
  damage; the study that motivated the tool found no single metadata anomaly that is a
  reliable indicator of compromise once the benign reference is chosen correctly.

ELFMint descends from the `checker` crate of
[manifest-producer](https://github.com/SoftengPoliTo/manifest-producer) (commit `ba357cf`),
which verified a handful of preconditions (debug symbols, static linking, hardening) before
the extraction of a certification manifest. ELFMint replaces that crate's goblin-only parsing
with the two-level fail-soft parser, adds the structural catalogue (H1–H10, P1–P7, S1–S4,
X1–X3, D1) and the context layer, and fixes two hardening defects of the original checker
(RELRO recorded as bind-now in `DT_FLAGS`/`DT_FLAGS_1`, and static-PIE executables).
See [docs/design.md](docs/design.md).

## Build

```
cargo build --release            # binary in target/release/elfmint
cargo test --release             # integration tests on synthetic fixtures (tests/fixtures)
```

A recent stable Rust toolchain (tested with 1.99); the only non-trivial dependency is
[goblin](https://github.com/m4b/goblin), pinned to 0.10.7 because its strict/permissive
behaviour is part of what the tool reports. ELFMint runs on any host (Linux, macOS, Windows):
it only reads files and never executes them.

## Usage

```
elfmint FILE [FILE ...]                  # pretty-printed JSON, one document per file
elfmint --jsonl OUT.jsonl --list FILES   # one JSON object per line, paths read from FILES
elfmint --fuzz SEED ITERATIONS RNG_SEED  # robustness self-test on in-memory mutations of SEED
```

Example on a 129-byte synthetic executable whose section header table is declared beyond the
end of the file (fixture `tests/fixtures/sht_beyond_eof.elf`):

```json
{
  "path": "tests/fixtures/sht_beyond_eof.elf",
  "size": 129,
  "sha256": "…",
  "goblin_strict": "error: bad offset 65536",
  "goblin_permissive": "ok",
  "raw_issues": [ { "field": "e_shoff", "offset": 40, "msg": "section header table beyond end of file" } ],
  "context": { "class": "ELF64", "endian": "LE", "machine": 62, "e_type": 2,
               "linkage": "static", "sht": "Unreadable", "packed": false,
               "libc": "none-or-static", "interp": null, "needed": [] },
  "model":   { "entry": 4194424, "loads": [[4194304, 129, 0, 129, 5]], "interp": null, "needed": [] },
  "checks": [
    { "id": "H1", "basis": "S", "class": "T0",    "outcome": "Pass", "detail": "ELF magic present", "field": "e_ident[EI_MAG]", "offset": 0 },
    { "id": "H8", "basis": "S", "class": "T0/T1", "outcome": "Fail", "detail": "section header table (n=0) extends beyond end of file", "field": "e_shoff", "offset": 40 },
    { "id": "S1", "basis": "C", "class": "T1",    "outcome": "NotApplicable", "detail": "section header table absent or unreadable", "field": null, "offset": null },
    { "id": "P1", "basis": "S,L", "class": "T0/T1", "outcome": "Pass", "detail": "PT_LOAD with p_filesz > p_memsz: []", "field": null, "offset": null }
  ]
}
```

(abridged: the real output lists all 30 checks). Every check has one of four outcomes:
`Pass`, `Fail` (with `field` and `offset` where the rule is located), `NotApplicable` (the
predicate is undefined for this file, e.g. section checks without a section table) and
`Unparsable` (the field needed to evaluate the check could not be read). The full schema is
in [docs/output-format.md](docs/output-format.md); the catalogue with the rule, basis, threat
class and corresponding Linux kernel behaviour of every check is in
[docs/checks.md](docs/checks.md).

`examples/summarise_jsonl.py` aggregates a JSONL run into per-check activation rates with
the correct denominators (files to which each check applies), which is how the base rates in
the paper were computed.

## Threat classes and how to read the output

| Class | Meaning | Checks |
|---|---|---|
| T0 | accidental corruption: truncation, extraction damage | X3; H1, H7, H8, P1 also carry T0 |
| T1 | anti-analysis: the kernel still runs the file, analysis tools may not | H2–H10, P1–P5a, S1, S3, S4 |
| T2 | tampering that leaves structural traces | P6, P7, S2 |
| T3 | hygiene: hardening and build conventions, never a sign of compromise | P5b, D1, R1–R4 |
| context | properties that select other checks and define comparison strata | X1 (section table absent), X2 (UPX) |

A `Fail` on a T3 check describes how a binary was built. A `Fail` on a T1 check is a
structural anomaly whose interpretation depends on the corpus: a non-standard `EI_OSABI` (H4),
for example, is written by pre-EABI ARM toolchains in vendor firmware and malware alike. The
paper reports the activation rate of every check on 61,499 ELF files from 1,124 vendor
firmware images and on 1,241 IoT malware samples; those base rates are the false-positive cost
to expect from each check.

## Performance and robustness

On an Ubuntu 22.04 host (2 vCPU) ELFMint processed 3,171 real binaries at a median of 0.76 ms
per file (mean 4.2 ms), including the goblin pass. It completed on all 70,641 ELF files
extracted from the FirmAE firmware dataset, all 1,241 malware samples and 100 random
multi-field mutants produced by the Melkor ELF fuzzer; the built-in harness ran 150,000
iterations on a seed binary without a panic.

## Repository layout

```
src/raw.rs      level-1 bounds-checked parser (ELF header, PHT, SHT, dynamic section, PT_INTERP)
src/checks.rs   check catalogue, context attributes, static model
src/main.rs     CLI, JSON/JSONL output, fuzzing harness
tests/          integration tests; tests/gen_fixtures.py regenerates tests/fixtures/*.elf
docs/           checks.md (catalogue), output-format.md (schema), design.md (architecture)
examples/       scan_tree.sh (run on a directory), summarise_jsonl.py (activation rates)
```

## Citing

If you use ELFMint, please cite the paper that introduces and evaluates it (see
[CITATION.cff](CITATION.cff)).

## Licence

MIT, as the manifest-producer project it originates from. See [LICENSE](LICENSE).

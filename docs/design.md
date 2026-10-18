# Design

## Origin

ELFMint originates as the `checker` crate (`manifest-producer-checker` 0.1.0) of
[manifest-producer](https://github.com/SoftengPoliTo/manifest-producer), a tool and library that
recovers the behaviour (system calls, APIs) of a firmware binary for certification manifests.
That crate inspected a binary with goblin and verified preconditions for the manifest
extraction: presence of debug symbols, static linking and the hardening properties reported by
checksec-like tools. ELFMint asks a different question, namely whether the binary's structure
is internally consistent, with what rule it disagrees, and whether the loader would care.

Differences from the original checker:

* **Two-level fail-soft parsing.** `src/raw.rs` reads the ELF header, the program header table
  and the section header table with bounds-checked, field-by-field accessors, honours extended
  section numbering, and records every out-of-bounds or inconsistent field in `raw_issues`
  without stopping. goblin (permissive mode) is used only at level 2, for symbols, dynamic
  entries and notes, and only for files whose program header table level 1 accepted. The
  original checker stopped at the first field goblin rejected.
* **A structural catalogue** (H1–H10, P1–P7, S1–S4, X1–X3, D1) in addition to the hardening
  checks (R1–R4), each with a declared basis and threat class (see `checks.md`).
* **Context before checks.** Linkage, section-table status, packing and C-library family are
  determined first; they decide applicability and the per-libc interpreter whitelist.
* **Applicability rules.** Checks whose predicate is undefined for a file return
  `NotApplicable` instead of a spurious failure (section checks without a section table,
  hardening and section-to-segment checks on relocatable objects).
* **Two corrected hardening defects.** RELRO now recognises bind-now recorded in
  `DT_FLAGS` (`DF_BIND_NOW`) and `DT_FLAGS_1` (`DF_1_NOW`), not only a literal `DT_BIND_NOW`
  tag; PIE recognises static-PIE executables (`ET_DYN` with `DF_1_PIE`) that have no
  `PT_INTERP`. The original checker reported RELRO absent on every rustc target and PIE absent
  on static-PIE builds; ELFMint agrees with pwntools and checksec 2.7.1 on all of them.
* **A static model** (`model`) exposing entry point, loadable ranges with permissions,
  interpreter and needed libraries, so that the parser's view can be compared with the
  runtime memory map of the executed process.
* **A fuzzing harness** (`--fuzz`) that mutates the header and table regions of a seed file in
  memory with a seeded xorshift generator and counts panics; the release profile enables
  arithmetic-overflow checks so that silent wrap-around is caught as a panic.

## Principles

1. *Fail soft.* A malformed field must never prevent the evaluation of unrelated checks,
   because the files of greatest interest are the ones that break conventional parsers.
2. *Typed checks.* Each check declares whether it enforces a normative constraint of the
   specification (S), a property a loader enforces (L), a toolchain convention (C) or a
   heuristic (H), and which threat class it serves. "Violates the standard", "is unusual" and
   "lacks a mitigation" are kept apart.
3. *Context awareness.* The meaning of a check depends on linkage, section-table status,
   packing and C library; the same finding is a T0, T1 or T3 fact depending on that context.

## What ELFMint is not

It is not a loader: it does not execute files and does not predict runtime permissions on
targets where the kernel widens a declared read–write segment to read–write–execute (older
ARMv5 and MIPS kernels do). It is not a malware classifier: base rates in vendor firmware show
that section-table absence, missing hardening and a non-standard `EI_OSABI` are produced by
mainstream toolchains. It is not a disassembler or a symbol-level analyser: level 2 reads
symbol names only to decide R4.

## Known limitations of version 0.2.0

* The page size assumed by P2 is 4096 bytes.
* H2's machine table covers the architectures common in IoT firmware (x86, x86-64, ARM,
  AArch64, MIPS, PowerPC, SPARC, SuperH, M68k, RISC-V, LoongArch, ARC, ...); other machines are
  `NotApplicable`.
* The `n=` figure in the H8 detail string reports the number of section headers actually read,
  not the declared `e_shnum`, when the table is unreadable (cosmetic).
* Two catalogue gaps observed in the evaluation: a bogus `e_machine` that is not in the
  consistency table and an `ET_CORE` file pass all checks.

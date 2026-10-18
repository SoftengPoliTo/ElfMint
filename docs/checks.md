# Check catalogue

Basis: **S** normative constraint of the ELF specification (TIS ELF 1.2 / gABI), **L** property
checked by a loader, **C** convention of mainstream toolchains, **H** heuristic.
Class: threat class (T0 accidental corruption, T1 anti-analysis, T2 tampering, T3 hygiene,
*context* = stratification variable). Kernel: behaviour of the Linux ELF handler
(`fs/binfmt_elf.c`, v7.2.10) for a file that violates the rule; "fatal" means the process is
killed after the point of no return, "rejects" means `execve` fails.

| ID | Rule (a violation is reported) | Basis | Class | Kernel | Notes |
|---|---|---|---|---|---|
| H1 | ELF magic present | S | T0 | rejects | |
| H2 | `EI_CLASS`/`EI_DATA` consistent with `e_machine` and header layout | S | T1 | mostly ignores | `EI_CLASS` checked only on some architectures (MIPS, RISC-V); a machine value that decodes only with the opposite byte order is reported as a likely altered `EI_DATA` |
| H3 | `EI_VERSION` = `e_version` = 1 | S | T1 | ignores | |
| H4 | `EI_OSABI` is `NONE` or `LINUX` | C | T1 | ignores | `ELFOSABI_ARM` (97) is written by pre-EABI ARM toolchains; the FreeBSD tag still runs |
| H5 | `e_ehsize` equals the structure size | S | T1 | ignores | |
| H6 | `e_phentsize` equals the structure size | S | T1 | rejects | goblin ignores the field |
| H7 | Program header table inside the file; `e_phnum` within the kernel bound (64 KiB) | S, L | T0/T1 | rejects | |
| H8 | Section header table inside the file when `e_shoff` ≠ 0; extended numbering (`e_shnum` = 0, count in section 0) honoured | S | T0/T1 | ignores | an unreadable table is reported here only, never as truncation (X3) |
| H9 | `e_shstrndx` valid (a `SHT_STRTAB` inside the file) or `SHN_UNDEF`/`SHN_XINDEX` | S | T1 | ignores | |
| H10 | `e_type` consistent with structure (`PT_LOAD` present for `ET_EXEC`/`ET_DYN`; `e_entry` = 0 and no program headers for `ET_REL`) | S | T1 | partly | |
| P1 | `p_filesz` ≤ `p_memsz` for every `PT_LOAD` | S, L | T0/T1 | fatal | equality is normal |
| P2 | `p_offset` ≡ `p_vaddr` modulo the page size | S, L | T1 | fatal | 4096-byte page assumed |
| P3 | `p_align` is 0, 1 or a power of two; `p_offset` ≡ `p_vaddr` modulo `p_align` | S | T1 | ignores | |
| P4 | `PT_LOAD` entries ascending and non-overlapping | S | T1 | ignores | not reported by readelf |
| P5a | One `PT_INTERP`, inside the file, NUL-terminated, 2–4096 bytes, absolute path, consistent with the C library indicated by `DT_NEEDED` | L, C | T1 | partly | qemu-user rejects several of these |
| P5b | Interpreter path in the per-libc whitelist (glibc, musl, uClibc-ng, bionic; `/lib`, `/lib32`, `/lib64`, `/libx32`, `/usr/lib`, `/usr/lib64`, `/system/bin`) | C | T3 | n/a | |
| P6 | No writable-and-executable `PT_LOAD` | C | T2 | ignores | |
| P7 | Entry point inside an executable `PT_LOAD` | H | T2 | partly | static executables: address bound only; not applicable to `ET_REL`, `ET_CORE` and shared objects with `e_entry` = 0 |
| S1 | Allocated sections contained in a `PT_LOAD` with compatible permissions | C | T1 | ignores | loadable images only |
| S2 | No executable section outside every loadable segment | H | T2 | ignores | loadable images only |
| S3 | Section names present, printable ASCII and unique | H | T1 | ignores | |
| S4 | Sections do not overlap (`SHT_NOBITS` excepted); `sh_addralign` is 0 or a power of two | S | T1 | ignores | |
| X1 | Section header table absent (`e_shoff` = 0) | C | context | n/a | expected after sstrip and UPX; OpenWrt's default musl builds |
| X2 | Packing indicator present (`UPX!` marker anywhere in the file) | C | context | n/a | |
| X3 | File shorter than its own program header table or the end of its last `PT_LOAD` | C | T0 | rejects/fatal | pure truncation signal; see H8 |
| D1 | Debugging sections present (`.debug*`, `.zdebug*`) | C | T3 | n/a | not applicable without a section table |
| R1 | Non-executable stack (`PT_GNU_STACK` without `PF_X`) | C | T3 | honours | a missing `PT_GNU_STACK` is reported as a failure (default is architecture-dependent) |
| R2 | Full RELRO (`PT_GNU_RELRO` and bind-now via `DT_BIND_NOW`, `DT_FLAGS`/`DF_BIND_NOW` or `DT_FLAGS_1`/`DF_1_NOW`) | C | T3 | n/a | checksec 3.2.0 semantics |
| R3 | PIE (`ET_DYN` with `PT_INTERP`, or static-PIE with `DF_1_PIE`) | C | T3 | n/a | shared objects: not applicable |
| R4 | Stack protector (`__stack_chk_fail`/`__stack_chk_guard`/`__intel_security_cookie` symbols) | C | T3 | n/a | undecidable on stripped static binaries; `Unparsable` when the level-2 parse fails |

## Applicability

A check's denominator contains only the files for which its predicate is defined. Section
checks (S1–S4, D1, H9) are `NotApplicable` without a readable section table; S1, S2 and the
hardening checks R1–R4 are `NotApplicable` for relocatable objects and core files; P5a/P5b
are `NotApplicable` without `PT_INTERP`; H2 is `NotApplicable` when `e_machine` is not in the
consistency table (for example the damaged sample with `e_machine` = 0x4141). Reporting
activation rates as *failures over applicable files* is what makes rates comparable across
corpora with different toolchain mixes.

## Context attributes

Before the checks run, ELFMint determines: ELF class and byte order; `e_machine` and `e_type`;
**linkage** (`dynamic` if `PT_INTERP` is present, `static-pie-or-dso` if only `PT_DYNAMIC`,
`static` otherwise); **section-table status** (`Present`, `Absent`, `Unreadable`); **packing**
(UPX marker); **C-library family** from the interpreter name, falling back to `DT_NEEDED`
(`libc.so.6` → glibc, `libc.so.0`/`libuClibc*` → uClibc, `libc.so`/`libc.musl*` → musl).
These attributes select the applicable checks and the interpreter whitelist, and they are the
stratification variables used when comparing corpora.

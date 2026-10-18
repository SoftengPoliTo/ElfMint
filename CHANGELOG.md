# Changelog

## 0.2.0 — 2026-10-18

Version evaluated in the paper "When the Loader Says Yes" (development builds were labelled
`elfguard`, `elfguard2`, `elfguard3`; the binary evaluated in the paper is `elfguard3`, SHA-256
`d36e1d9af8d8c207d95067fbe691826c6545db5825a1c87ca305c32c9b7a57be`, built from this source).

* Two-level fail-soft parser (`raw.rs` + goblin 0.10.7 permissive) replacing goblin-only parsing.
* Catalogue of 30 checks (H1–H10, P1–P7 with P5 split into P5a/P5b, S1–S4, X1–X3, D1, R1–R4),
  each with basis, threat class, field and offset.
* Context attributes (linkage, section-table status, packing, C-library family) and
  applicability rules (section-to-segment and hardening checks on loadable images only).
* X3 truncation check as a pure T0 signal; unreadable section header table reported by H8.
* RELRO recognises bind-now in `DT_FLAGS`/`DT_FLAGS_1`; PIE recognises static-PIE (`DF_1_PIE`).
* JSON/JSONL output with SHA-256 and timing; `--list` input; `--fuzz` robustness harness;
  release profile with `overflow-checks = true`.
* Integration tests on synthetic fixtures (`tests/`).

## 0.1.0 — manifest-producer checker (commit ba357cf)

Original `checker` crate of manifest-producer: goblin-based inspection of debug symbols,
static linking and hardening properties.

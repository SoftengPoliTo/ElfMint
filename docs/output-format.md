# Output format

One JSON object per analysed file (pretty-printed on stdout, or one object per line with
`--jsonl OUT`).

| Field | Type | Meaning |
|---|---|---|
| `path` | string | path as given on the command line or in the `--list` file |
| `sha256` | string | SHA-256 of the file content |
| `size` | integer | file size in bytes |
| `elapsed_us` | integer | wall-clock time spent on the file, microseconds |
| `io_error` | string | present (and the only other field) when the file could not be read |
| `panic` | true | present only if the analysis panicked; the fuzzing harness exists to keep this from happening |
| `goblin_strict` | string | `"ok"` or `"error: …"` from goblin's strict parser (reported, not used by the checks) |
| `goblin_permissive` | string | `"ok"` or `"error: …"` from goblin's permissive parser (level 2: symbols, dynamic section, notes) |
| `raw_issues` | array of `{field, offset, msg}` | every out-of-bounds or inconsistent field found by the level-1 parser |
| `context` | object | see below |
| `model` | object | the *static model* used to compare the file with the runtime view of the loader |
| `checks` | array of 30 check objects | the catalogue, always in the same order |

## `context`

`class` (`ELF32`/`ELF64`/`invalid(n)`), `endian` (`LE`/`BE`/`invalid(n)`), `machine` (`e_machine`),
`e_type`, `linkage` (`dynamic`/`static-pie-or-dso`/`static`), `sht` (`Present`/`Absent`/`Unreadable`),
`packed` (bool), `libc` (`glibc`/`musl`/`uclibc`/`bionic`/`unknown`/`none-or-static`),
`interp` (string or null), `needed` (array of `DT_NEEDED` names).

## `model`

`entry` (`e_entry`), `loads` (array of `[p_vaddr, p_memsz, p_offset, p_filesz, p_flags]`, one per
`PT_LOAD` in file order), `interp`, `needed`. This is the subset of a parser's view that can be
compared with the auxiliary vector and `/proc/<pid>/maps` of the executed process.

## Check object

```
{ "id": "H8", "basis": "S", "class": "T0/T1", "outcome": "Fail",
  "detail": "section header table (n=0) extends beyond end of file",
  "field": "e_shoff", "offset": 40 }
```

`outcome` ∈ {`Pass`, `Fail`, `NotApplicable`, `Unparsable`}. `field` and `offset` locate the rule
in the file when the check is positional; they are `null` for relational checks (for example P4,
S1) whose detail names the offending table entries by index. `basis` is one of `S`, `L`, `C`, `H`
or a comma-separated combination; `class` is `T0`, `T1`, `T2`, `T3`, `context`, a combination such
as `T0/T1`, or `-` for checks that could not be evaluated at all (identification bytes unreadable).

## Exit status

The process exits 0 after analysing every file, whatever the findings; unreadable files produce an
object with `io_error`. Fatal conditions are limited to a missing `--jsonl` output path.

//! Integration tests: run the built binary on the synthetic fixtures of tests/fixtures/
//! (regenerate them with tests/gen_fixtures.py) and check the reported outcomes.
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

fn run(name: &str) -> serde_json::Value {
    let out = Command::new(env!("CARGO_BIN_EXE_elfmint")).arg(fixture(name)).output().expect("run elfmint");
    assert!(out.status.success(), "elfmint exited with {:?}", out.status);
    serde_json::from_slice(&out.stdout).expect("valid JSON on stdout")
}

fn outcomes(v: &serde_json::Value) -> HashMap<String, String> {
    v["checks"].as_array().expect("checks array").iter()
        .map(|c| (c["id"].as_str().unwrap().to_string(), c["outcome"].as_str().unwrap().to_string()))
        .collect()
}

#[test]
fn minimal_executable_passes_structural_checks() {
    let v = run("minimal.elf");
    let o = outcomes(&v);
    for id in ["H1", "H2", "H3", "H4", "H5", "H6", "H7", "H10", "P1", "P2", "P3", "P4", "P6", "P7", "X3"] {
        assert_eq!(o[id], "Pass", "check {id}");
    }
    assert_eq!(o["H8"], "NotApplicable"); // no section header table
    assert_eq!(o["X1"], "Fail");          // context: section header table absent
    assert_eq!(v["context"]["linkage"], "static");
    assert_eq!(v["context"]["machine"], 62);
    assert_eq!(v["checks"].as_array().unwrap().len(), 30);
}

#[test]
fn section_table_beyond_eof_is_h8_not_x3() {
    let o = outcomes(&run("sht_beyond_eof.elf"));
    assert_eq!(o["H8"], "Fail");
    assert_eq!(o["X3"], "Pass");
    assert_eq!(o["S1"], "NotApplicable"); // table unreadable: section checks do not apply
    assert_eq!(o["P1"], "Pass");           // program-header checks still evaluated (fail-soft)
}

#[test]
fn truncated_file_is_x3() {
    let o = outcomes(&run("truncated.elf"));
    assert_eq!(o["X3"], "Fail");
    assert_eq!(o["H8"], "NotApplicable");
}

#[test]
fn flipped_ei_data_is_h2() {
    let v = run("ei_data_flipped.elf");
    let o = outcomes(&v);
    assert_eq!(o["H2"], "Fail");
    assert!(v["checks"][1]["detail"].as_str().unwrap().contains("opposite byte order"));
}

#[test]
fn loader_relevant_single_field_mutations() {
    assert_eq!(outcomes(&run("filesz_gt_memsz.elf"))["P1"], "Fail");
    assert_eq!(outcomes(&run("phentsize_plus8.elf"))["H6"], "Fail");
    assert_eq!(outcomes(&run("rwx_segment.elf"))["P6"], "Fail");
}

#[test]
fn damaged_prefix_never_panics_and_reports_unparsable() {
    let v = run("damaged_prefix.elf");
    assert!(v.get("panic").is_none());
    let o = outcomes(&v);
    assert_eq!(o["H1"], "Pass");
    assert_eq!(o["H2"], "NotApplicable"); // e_machine 0x4141 is not in the consistency table
    assert!(o.values().any(|s| s == "Unparsable" || s == "Fail"));
}

#[test]
fn jsonl_output_and_file_list() {
    let dir = std::env::temp_dir().join(format!("elfmint-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let list = dir.join("list.txt");
    std::fs::write(&list, format!("{}\n{}\n", fixture("minimal.elf").display(), fixture("truncated.elf").display())).unwrap();
    let out = dir.join("out.jsonl");
    let st = Command::new(env!("CARGO_BIN_EXE_elfmint")).args(["--jsonl", out.to_str().unwrap(), "--list", list.to_str().unwrap()]).status().unwrap();
    assert!(st.success());
    let text = std::fs::read_to_string(&out).unwrap();
    assert_eq!(text.lines().count(), 2);
    for line in text.lines() { let v: serde_json::Value = serde_json::from_str(line).unwrap(); assert!(v["sha256"].is_string()); }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn fuzz_mode_reports_zero_panics() {
    let out = Command::new(env!("CARGO_BIN_EXE_elfmint")).args(["--fuzz", fixture("minimal.elf").to_str().unwrap(), "2000", "7"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["panics"], 0);
    assert_eq!(v["iterations"], 2000);
}

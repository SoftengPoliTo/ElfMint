//! ELFMint 0.2: fail-soft ELF metadata validator.
//! Usage: elfmint [--jsonl OUT] [--list FILELIST] [FILE ...]
mod checks;
mod raw;
use goblin::elf::Elf;
use goblin::options::ParseOptions;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::{BufRead, Write};

fn level2(data: &[u8]) -> (String, String, Option<Vec<String>>) {
    let strict = match Elf::parse(data) { Ok(_) => "ok".to_string(), Err(e) => format!("error: {e}") };
    match Elf::parse_with_opts(data, &ParseOptions::permissive()) {
        Ok(elf) => {
            let mut names: Vec<String> = elf.syms.iter().filter_map(|s| elf.strtab.get_at(s.st_name).map(str::to_string)).collect();
            names.extend(elf.dynsyms.iter().filter_map(|s| elf.dynstrtab.get_at(s.st_name).map(str::to_string)));
            (strict, "ok".into(), Some(names))
        }
        Err(e) => (strict, format!("error: {e}"), None),
    }
}

fn analyse_file(path: &str) -> serde_json::Value {
    let t0 = std::time::Instant::now();
    let data = match std::fs::read(path) { Ok(d) => d, Err(e) => return json!({"path": path, "io_error": e.to_string()}) };
    let sha = format!("{:x}", Sha256::digest(&data));
    let res = std::panic::catch_unwind(|| {
        let (g_strict, g_perm, syms) = level2(&data);
        let r = raw::Raw::parse(&data);
        let (ctx, model, checks) = checks::analyse(&r, syms.as_deref());
        json!({"goblin_strict": g_strict, "goblin_permissive": g_perm, "raw_issues": r.issues, "context": ctx, "model": model, "checks": checks})
    });
    let mut out = match res { Ok(v) => v, Err(_) => json!({"panic": true}) };
    out["path"] = json!(path); out["sha256"] = json!(sha); out["size"] = json!(data.len());
    out["elapsed_us"] = json!(t0.elapsed().as_micros() as u64);
    out
}

/// Robustness self-test: mutate header and table bytes in memory with a seeded xorshift RNG.
fn fuzz(path: &str, iters: u64, seed: u64) {
    let base = std::fs::read(path).expect("read");
    let (mut panics, mut x) = (0u64, seed | 1);
    let mut rnd = move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    let hot: Vec<(u64, u64)> = {
        let r = raw::Raw::parse(&base);
        let mut v = vec![(0u64, r.ehsz())];
        if let Some(h) = r.h { v.push((h.e_phoff, h.e_phnum as u64 * r.phsz())); if h.e_shoff != 0 { v.push((h.e_shoff, r.shnum.min(4096) * r.shsz())); } }
        v.into_iter().filter(|(o, l)| *l > 0 && o + l <= base.len() as u64).collect()
    };
    for it in 0..iters {
        let mut d = base.clone();
        let n = 1 + rnd() % 8;
        let mut log = vec![];
        for _ in 0..n {
            let (o, l) = hot[(rnd() % hot.len() as u64) as usize];
            let pos = (o + rnd() % l) as usize;
            let val = match rnd() % 4 { 0 => 0u8, 1 => 0xff, 2 => d[pos] ^ (1 << (rnd() % 8)), _ => rnd() as u8 };
            log.push((pos, val)); d[pos] = val;
        }
        if d.len() > 64 && rnd() % 16 == 0 { let cut = 16 + (rnd() as usize % (d.len() - 16)); d.truncate(cut); }
        let ok = std::panic::catch_unwind(|| { let (_g1, _g2, syms) = level2(&d); let r = raw::Raw::parse(&d); let _ = checks::analyse(&r, syms.as_deref()); }).is_ok();
        if !ok { panics += 1; if panics <= 5 { eprintln!("PANIC iter={it} seed={seed} mutations={log:?} len={}", d.len()); } }
    }
    println!("{{\"file\": \"{path}\", \"iterations\": {iters}, \"seed\": {seed}, \"panics\": {panics}}}");
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--fuzz") {
        std::panic::set_hook(Box::new(|_| {}));
        let iters = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1000);
        let seed = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1);
        fuzz(&args[1], iters, seed); return;
    }
    let mut files = vec![]; let mut out: Option<String> = None; let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--jsonl" => { out = args.get(i + 1).cloned(); i += 2; }
            "--list" => { if let Some(l) = args.get(i + 1) { if let Ok(f) = std::fs::File::open(l) { files.extend(std::io::BufReader::new(f).lines().map_while(Result::ok).filter(|s| !s.is_empty())); } } i += 2; }
            _ => { files.push(args[i].clone()); i += 1; }
        }
    }
    std::panic::set_hook(Box::new(|_| {}));
    match out {
        Some(o) => {
            let mut w = std::io::BufWriter::new(std::fs::File::create(o).expect("cannot create output"));
            for f in &files { writeln!(w, "{}", analyse_file(f)).ok(); }
        }
        None => { for f in &files { println!("{}", serde_json::to_string_pretty(&analyse_file(f)).unwrap()); } }
    }
}

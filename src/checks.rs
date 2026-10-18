//! Check catalogue (see docs/checks.md). Basis: S specification, L loader, C toolchain convention,
//! H heuristic. Class: T0 accidental corruption, T1 anti-analysis, T2 tampering, T3 hygiene, context.
use crate::raw::*;
use serde::Serialize;

#[derive(Serialize, Clone, Copy, Debug, PartialEq)]
pub enum Outcome { Pass, Fail, NotApplicable, Unparsable }
#[derive(Serialize, Clone, Debug)]
pub struct Check { pub id: &'static str, pub basis: &'static str, pub class: &'static str, pub outcome: Outcome, pub detail: String, pub field: Option<String>, pub offset: Option<u64> }
#[derive(Serialize, Clone, Debug, Default)]
pub struct Context { pub class: String, pub endian: String, pub machine: u16, pub e_type: u16, pub linkage: String, pub sht: String, pub packed: bool, pub libc: String, pub interp: Option<String>, pub needed: Vec<String> }
#[derive(Serialize, Clone, Debug, Default)]
pub struct Model { pub entry: Option<u64>, pub loads: Vec<(u64, u64, u64, u64, u32)>, pub interp: Option<String>, pub needed: Vec<String> }

fn c(id: &'static str, basis: &'static str, class: &'static str, outcome: Outcome, detail: impl Into<String>) -> Check {
    Check { id, basis, class, outcome, detail: detail.into(), field: None, offset: None }
}
fn cf(id: &'static str, basis: &'static str, class: &'static str, outcome: Outcome, detail: impl Into<String>, field: &str, offset: u64) -> Check {
    Check { id, basis, class, outcome, detail: detail.into(), field: Some(field.into()), offset: Some(offset) }
}
fn pass_fail(b: bool) -> Outcome { if b { Outcome::Pass } else { Outcome::Fail } }

// e_machine -> (allowed classes: 1=32,2=64,3=both, little-endian required)
fn machine_info(m: u16) -> Option<(u8, bool)> {
    match m {
        3 => Some((1, true)), 62 => Some((2, true)), 40 => Some((1, false)), 183 => Some((2, false)), 8 => Some((3, false)),
        10 => Some((3, false)), 243 => Some((3, true)), 20 => Some((1, false)), 21 => Some((2, false)), 2 | 18 | 43 => Some((3, false)),
        42 => Some((1, false)), 4 => Some((1, false)), 22 => Some((3, false)), 258 => Some((2, true)), 164 => Some((1, false)), 94 => Some((1, true)),
        _ => None,
    }
}

pub fn conventional_interp(p: &str) -> Option<&'static str> {
    let (dir, base) = p.rsplit_once('/')?;
    if !matches!(dir, "/lib" | "/lib32" | "/lib64" | "/libx32" | "/usr/lib" | "/usr/lib64" | "/system/bin") { return None; }
    if base.starts_with("ld-musl-") && base.ends_with(".so.1") { return Some("musl"); }
    if (base.starts_with("ld-uClibc") || base.starts_with("ld64-uClibc")) && base.contains(".so.") { return Some("uclibc"); }
    if (base.starts_with("ld-linux") && base.contains(".so.")) || base == "ld.so.1" || (base.starts_with("ld64.so.") && base.len() > 8) { return Some("glibc"); }
    if dir == "/system/bin" && (base == "linker" || base == "linker64") { return Some("bionic"); }
    None
}
fn libc_from_needed(needed: &[String]) -> Option<&'static str> {
    for n in needed {
        if n == "libc.so.6" { return Some("glibc"); }
        if n == "libc.so.0" || n.starts_with("libuClibc") { return Some("uclibc"); }
        if n == "libc.so" || n.starts_with("libc.musl") { return Some("musl"); }
    }
    None
}

pub fn analyse(r: &Raw, symbols: Option<&[String]>) -> (Context, Model, Vec<Check>) {
    let mut v: Vec<Check> = vec![];
    let mut ctx = Context::default();
    let mut model = Model::default();
    use Outcome::*;
    v.push(cf("H1", "S", "T0", pass_fail(r.magic_ok), if r.magic_ok { "ELF magic present" } else { "ELF magic missing" }, "e_ident[EI_MAG]", 0));
    let Some(id) = r.ident else {
        for idc in ["H2","H3","H4","H5","H6","H7","H8","H9","H10","P1","P2","P3","P4","P5a","P5b","P6","P7","S1","S2","S3","S4","X1","X2","X3","D1","R1","R2","R3","R4"] {
            v.push(cf(idc, "-", "-", Unparsable, "identification bytes unavailable", "e_ident", 0));
        }
        return (ctx, model, v);
    };
    ctx.class = match id[4] { 1 => "ELF32".into(), 2 => "ELF64".into(), x => format!("invalid({x})") };
    ctx.endian = match id[5] { 1 => "LE".into(), 2 => "BE".into(), x => format!("invalid({x})") };
    let Some(h) = r.h else {
        let id_ok = r.is64.is_some() && r.le.is_some();
        if id_ok {
            v.push(c("H2", "S", "T1", NotApplicable, "EI_CLASS/EI_DATA valid; e_machine unavailable"));
            v.push(cf("X3", "C", "T0", Fail, format!("file ({} bytes) shorter than the ELF header ({} bytes)", r.size(), r.ehsz()), "ELF header", 0));
        } else {
            v.push(cf("H2", "S", "T1", Fail, "EI_CLASS or EI_DATA invalid: header not decodable", "e_ident[EI_CLASS/EI_DATA]", 4));
            v.push(c("X3", "C", "T0", Unparsable, "header not decodable"));
        }
        for idc in ["H3","H4","H5","H6","H7","H8","H9","H10","P1","P2","P3","P4","P5a","P5b","P6","P7","S1","S2","S3","S4","X1","X2","D1","R1","R2","R3","R4"] {
            v.push(cf(idc, "-", "-", Unparsable, "ELF header not decodable", "ELF header", 0));
        }
        return (ctx, model, v);
    };
    ctx.machine = h.e_machine; ctx.e_type = h.e_type;
    // H2: class and byte order consistent with e_machine (and with the swapped interpretation)
    let swapped = h.e_machine.swap_bytes();
    let h2 = match machine_info(h.e_machine) {
        Some((cls, le_req)) => {
            let cls_ok = cls == 3 || (cls == 2) == (r.is64 == Some(true));
            let le_ok = !le_req || r.le == Some(true);
            if cls_ok && le_ok { c("H2", "S", "T1", Pass, format!("e_machine {} consistent with {} {}", h.e_machine, ctx.class, ctx.endian)) }
            else { cf("H2", "S", "T1", Fail, format!("e_machine {} inconsistent with {} {}", h.e_machine, ctx.class, ctx.endian), "e_ident[EI_CLASS/EI_DATA]", 4) }
        }
        None if machine_info(swapped).is_some() => cf("H2", "S", "T1", Fail, format!("e_machine decodes as known ({swapped}) only with the opposite byte order: EI_DATA likely altered"), "e_ident[EI_DATA]", 5),
        None => c("H2", "S", "T1", NotApplicable, format!("e_machine {} not in the consistency table", h.e_machine)),
    };
    v.push(h2);
    v.push(cf("H3", "S", "T1", pass_fail(id[6] == 1 && h.e_version == 1), format!("EI_VERSION={} e_version={}", id[6], h.e_version), "e_ident[EI_VERSION]/e_version", 6));
    v.push(cf("H4", "C", "T1", pass_fail(id[7] == 0 || id[7] == 3), format!("EI_OSABI={}", id[7]), "e_ident[EI_OSABI]", 7));
    v.push(cf("H5", "S", "T1", pass_fail(h.e_ehsize as u64 == r.ehsz()), format!("e_ehsize={} expected {}", h.e_ehsize, r.ehsz()), "e_ehsize", if r.is64 == Some(true) { 52 } else { 40 }));
    let h6 = if h.e_phnum == 0 { c("H6", "S", "T1", NotApplicable, "no program headers") }
        else { cf("H6", "S", "T1", pass_fail(h.e_phentsize as u64 == r.phsz()), format!("e_phentsize={} expected {}", h.e_phentsize, r.phsz()), "e_phentsize", if r.is64 == Some(true) { 54 } else { 42 }) };
    v.push(h6);
    let exec_like = h.e_type == 2 || h.e_type == 3;
    let pht_bytes = (h.e_phnum as u64) * r.phsz();
    let h7_ok = r.pht_complete && pht_bytes <= 65536 && !(exec_like && h.e_phnum == 0);
    v.push(cf("H7", "S,L", "T0/T1", pass_fail(h7_ok), format!("e_phnum={} complete={} bytes={}", h.e_phnum, r.pht_complete, pht_bytes), "e_phoff", if r.is64 == Some(true) { 32 } else { 28 }));
    // H8: section header table inside the file (extended numbering honoured)
    let h8 = match r.sht {
        Sht::Absent => c("H8", "S", "T0/T1", NotApplicable, "no section header table (e_shoff = 0)"),
        Sht::Unreadable => cf("H8", "S", "T0/T1", Fail, format!("section header table (n={}) extends beyond end of file", r.shnum), "e_shoff", if r.is64 == Some(true) { 40 } else { 32 }),
        Sht::Present => {
            let end = h.e_shoff.checked_add(r.shnum.saturating_mul(r.shsz()));
            cf("H8", "S", "T0/T1", pass_fail(end.is_some_and(|e| e <= r.size()) && (h.e_shentsize as u64 == r.shsz())), format!("shnum={} e_shentsize={}", r.shnum, h.e_shentsize), "e_shoff", if r.is64 == Some(true) { 40 } else { 32 })
        }
    };
    v.push(h8);
    let h9 = match r.sht {
        Sht::Absent => c("H9", "S", "T1", NotApplicable, "no section header table"),
        _ if r.shstrndx == 0 => c("H9", "S", "T1", Pass, "SHN_UNDEF: no section name table"),
        _ => {
            let ok = r.shdrs.get(r.shstrndx as usize).is_some_and(|s| s.sh_type == SHT_STRTAB && r.bytes(s.sh_offset, s.sh_size).is_some());
            cf("H9", "S", "T1", pass_fail(ok), format!("shstrndx={}", r.shstrndx), "e_shstrndx", if r.is64 == Some(true) { 62 } else { 50 })
        }
    };
    v.push(h9);
    let loads: Vec<&Phdr> = r.phdrs.iter().filter(|p| p.p_type == PT_LOAD).collect();
    let h10_ok = match h.e_type { 1 => h.e_entry == 0 && h.e_phnum == 0, 2 | 3 => !loads.is_empty(), 4 => true, t => t >= 0xfe00 };
    v.push(cf("H10", "S", "T1", pass_fail(h10_ok), format!("e_type={} PT_LOAD={} e_entry={:#x}", h.e_type, loads.len(), h.e_entry), "e_type", 16));
    // Program-header checks
    if loads.is_empty() { for idc in ["P1","P2","P3","P4"] { v.push(c(idc, "S", "T1", NotApplicable, "no PT_LOAD")); } } else {
        let bad1: Vec<usize> = loads.iter().enumerate().filter(|(_, p)| p.p_filesz > p.p_memsz).map(|(i, _)| i).collect();
        v.push(c("P1", "S,L", "T0/T1", pass_fail(bad1.is_empty()), format!("PT_LOAD with p_filesz > p_memsz: {bad1:?}")));
        let bad2: Vec<usize> = loads.iter().enumerate().filter(|(_, p)| p.p_filesz > 0 && (p.p_offset.wrapping_sub(p.p_vaddr)) % 4096 != 0).map(|(i, _)| i).collect();
        v.push(c("P2", "S,L", "T1", pass_fail(bad2.is_empty()), format!("PT_LOAD with p_offset != p_vaddr mod 4096: {bad2:?}")));
        let bad3: Vec<usize> = loads.iter().enumerate().filter(|(_, p)| { let a = p.p_align; !(a <= 1 || (a.is_power_of_two() && (p.p_offset.wrapping_sub(p.p_vaddr)) % a == 0)) }).map(|(i, _)| i).collect();
        v.push(c("P3", "S", "T1", pass_fail(bad3.is_empty()), format!("PT_LOAD with invalid p_align or incongruent offset: {bad3:?}")));
        let mut ok4 = true; for w in loads.windows(2) { let end = w[0].p_vaddr.saturating_add(w[0].p_memsz); if w[1].p_vaddr < end { ok4 = false; } }
        v.push(c("P4", "S", "T1", pass_fail(ok4), "PT_LOAD ascending and non-overlapping"));
    }
    // Interpreter
    let interps = r.interps();
    let interp_s: Option<String> = interps.first().and_then(|(_, b)| b.as_ref().map(|b| String::from_utf8_lossy(b.split(|&x| x == 0).next().unwrap_or(&[])).into_owned()));
    let needed = r.needed();
    ctx.interp = interp_s.clone(); ctx.needed = needed.clone();
    if interps.is_empty() { v.push(c("P5a", "L,C", "T1", NotApplicable, "no PT_INTERP")); v.push(c("P5b", "C", "T3", NotApplicable, "no PT_INTERP")); } else {
        let (p0, b0) = &interps[0];
        let terminated = b0.as_ref().is_some_and(|b| b.last() == Some(&0));
        let s = interp_s.clone().unwrap_or_default();
        let fam_i = conventional_interp(&s);
        let fam_n = libc_from_needed(&needed);
        let mut probs = vec![];
        if interps.len() > 1 { probs.push(format!("{} PT_INTERP entries", interps.len())); }
        if b0.is_none() { probs.push("PT_INTERP beyond end of file".into()); }
        if !terminated { probs.push("PT_INTERP not NUL-terminated at p_filesz".into()); }
        if p0.p_filesz < 2 || p0.p_filesz > 4096 { probs.push(format!("PT_INTERP length {}", p0.p_filesz)); }
        if !s.starts_with('/') { probs.push("relative interpreter path".into()); }
        if let (Some(a), Some(b)) = (fam_i, fam_n) { if a != b { probs.push(format!("interpreter is {a} but DT_NEEDED indicates {b}")); } }
        v.push(cf("P5a", "L,C", "T1", pass_fail(probs.is_empty()), if probs.is_empty() { format!("interpreter {s}") } else { probs.join("; ") }, "PT_INTERP", p0.p_offset));
        v.push(c("P5b", "C", "T3", pass_fail(fam_i.is_some()), format!("interpreter {s} family {:?}", fam_i)));
    }
    v.push(c("P6", "C", "T2", pass_fail(!loads.iter().any(|p| p.p_flags & PF_W != 0 && p.p_flags & PF_X != 0)), "no writable-and-executable PT_LOAD"));
    let p7 = if h.e_type == 1 || h.e_type == 4 || (h.e_type == 3 && h.e_entry == 0) { c("P7", "H", "T2", NotApplicable, "no program entry expected") }
        else { let inx = loads.iter().any(|p| p.p_flags & PF_X != 0 && h.e_entry >= p.p_vaddr && h.e_entry < p.p_vaddr.saturating_add(p.p_memsz));
            cf("P7", "H", "T2", pass_fail(inx), format!("e_entry={:#x}", h.e_entry), "e_entry", 24) };
    v.push(p7);
    // Loadable image = ET_EXEC or ET_DYN. Section-to-segment and hardening checks describe a loaded image.
    let image = h.e_type == 2 || h.e_type == 3;
    // Section checks
    let names: Vec<Option<String>> = r.shdrs.iter().map(|s| r.section_name(s)).collect();
    if r.sht != Sht::Present { for idc in ["S1","S2","S3","S4"] { v.push(c(idc, "C", "T1", NotApplicable, "section header table absent or unreadable")); } } else {
        let mut bad1 = vec![]; let mut bad2 = vec![];
        for (i, s) in r.shdrs.iter().enumerate().skip(1) {
            let alloc = s.sh_flags & SHF_ALLOC != 0; let exec = s.sh_flags & SHF_EXECINSTR != 0;
            if exec && !alloc { bad2.push(i); }
            if !alloc || s.sh_addr == 0 || s.sh_flags & SHF_TLS != 0 || s.sh_size == 0 { continue; }
            let end = s.sh_addr.saturating_add(s.sh_size);
            match loads.iter().find(|p| s.sh_addr >= p.p_vaddr && end <= p.p_vaddr.saturating_add(p.p_memsz)) {
                None => { bad1.push(i); if exec { bad2.push(i); } }
                Some(p) => { if (exec && p.p_flags & PF_X == 0) || (s.sh_flags & SHF_WRITE != 0 && p.p_flags & PF_W == 0) { bad1.push(i); } }
            }
        }
        // Section-to-segment relations exist only in loadable images (ET_EXEC/ET_DYN). Relocatable objects
        // (e.g. kernel modules) have no program headers and nominal section addresses, so S1/S2 do not apply.
        if image {
            v.push(c("S1", "C", "T1", pass_fail(bad1.is_empty()), format!("allocated sections outside or with incompatible PT_LOAD: {bad1:?}")));
            v.push(c("S2", "H", "T2", pass_fail(bad2.is_empty()), format!("executable sections outside loadable segments: {bad2:?}")));
        } else {
            v.push(c("S1", "C", "T1", NotApplicable, "not a loadable image (ET_REL/ET_CORE): no section-to-segment mapping"));
            v.push(c("S2", "H", "T2", NotApplicable, "not a loadable image (ET_REL/ET_CORE): no section-to-segment mapping"));
        }
        let mut seen = std::collections::HashSet::new(); let mut bad3 = vec![];
        for (i, n) in names.iter().enumerate().skip(1) {
            match n { Some(n) => { if n.is_empty() || !n.bytes().all(|b| (0x20..0x7f).contains(&b)) || !seen.insert(n.clone()) { bad3.push(i); } } None => bad3.push(i) }
        }
        v.push(c("S3", "H", "T1", pass_fail(bad3.is_empty()), format!("sections with missing, non-printable or duplicate names: {}", bad3.len())));
        let mut iv: Vec<(u64, u64, usize)> = r.shdrs.iter().enumerate().skip(1).filter(|(_, s)| s.sh_type != SHT_NOBITS && s.sh_type != SHT_NULL && s.sh_size > 0).map(|(i, s)| (s.sh_offset, s.sh_offset.saturating_add(s.sh_size), i)).collect();
        iv.sort();
        let mut bad4 = vec![]; for w in iv.windows(2) { if w[1].0 < w[0].1 { bad4.push(w[1].2); } }
        for (i, s) in r.shdrs.iter().enumerate() { if !(s.sh_addralign == 0 || s.sh_addralign.is_power_of_two()) { bad4.push(i); } }
        v.push(c("S4", "S", "T1", pass_fail(bad4.is_empty()), format!("overlapping sections or invalid sh_addralign: {bad4:?}")));
    }
    // X3 (T0): file truncated with respect to its own tables or loadable segments
    let seg_end = loads.iter().filter_map(|p| p.p_offset.checked_add(p.p_filesz)).max().unwrap_or(0);
    // An unreadable section header table is reported by H8 (T0/T1) and deliberately NOT folded into X3:
    // X3 must stay a pure T0 signal (file shorter than its own loadable segments or program header table),
    // so that a section table pointing beyond EOF is not counted as truncation by construction.
    let tr = seg_end > r.size() || !r.pht_complete;
    v.push(c("X3", "C", "T0", pass_fail(!tr), format!("file size {} ; end of last PT_LOAD {} ; PHT complete {} ; SHT {:?}", r.size(), seg_end, r.pht_complete, r.sht)));
    // Context and hygiene
    ctx.sht = format!("{:?}", r.sht);
    v.push(c("X1", "C", "context", pass_fail(r.sht != Sht::Absent), if r.sht == Sht::Absent { "section header table absent" } else { "section header table present" }));
    ctx.packed = r.data.windows(4).any(|w| w == b"UPX!");
    v.push(c("X2", "C", "context", pass_fail(!ctx.packed), if ctx.packed { "UPX marker present" } else { "no packing marker" }));
    let dbg = names.iter().flatten().any(|n| n.starts_with(".debug") || n.starts_with(".zdebug"));
    v.push(c("D1", "C", "T3", if r.sht == Sht::Present { pass_fail(!dbg) } else { NotApplicable }, if dbg { "debugging sections present" } else { "no debugging sections" }));
    let has_dyn = r.phdrs.iter().any(|p| p.p_type == PT_DYNAMIC);
    ctx.linkage = if !interps.is_empty() { "dynamic".into() } else if has_dyn { "static-pie-or-dso".into() } else { "static".into() };
    ctx.libc = conventional_interp(interp_s.as_deref().unwrap_or("")).or(libc_from_needed(&needed)).unwrap_or(if interps.is_empty() { "none-or-static" } else { "unknown" }).into();
    // R1-R4: hardening (checksec 3.2.0 semantics)
    let gs = r.phdrs.iter().find(|p| p.p_type == PT_GNU_STACK);
    v.push(match gs { _ if !image => c("R1", "C", "T3", NotApplicable, "not a loadable image (ET_REL/ET_CORE)"),
        Some(p) => c("R1", "C", "T3", pass_fail(p.p_flags & PF_X == 0), if p.p_flags & PF_X == 0 { "PT_GNU_STACK non-executable" } else { "PT_GNU_STACK executable" }),
        None => c("R1", "C", "T3", Fail, "no PT_GNU_STACK (default is architecture-dependent)") });
    let dy = r.dynamic();
    let bindnow = dy.iter().any(|(t, v)| *t == 24 || (*t == 30 && v & 0x8 != 0) || (*t == 0x6fff_fffb && v & 0x1 != 0));
    let relro = r.phdrs.iter().any(|p| p.p_type == PT_GNU_RELRO);
    let level = if relro && bindnow { "full" } else if relro { "partial" } else { "none" };
    v.push(if image { c("R2", "C", "T3", pass_fail(level == "full"), format!("RELRO {level}")) } else { c("R2", "C", "T3", NotApplicable, "not a loadable image (ET_REL/ET_CORE)") });
    let df1_pie = dy.iter().any(|(t, v)| *t == 0x6fff_fffb && v & 0x0800_0000 != 0);
    v.push(match h.e_type { 3 if !interps.is_empty() => c("R3", "C", "T3", Pass, "PIE"), 3 if df1_pie => c("R3", "C", "T3", Pass, "static PIE"),
        3 => c("R3", "C", "T3", NotApplicable, "shared object"), 2 => c("R3", "C", "T3", Fail, "ET_EXEC: not position-independent"), _ => c("R3", "C", "T3", NotApplicable, "not an executable") });
    let stripped = !names.iter().flatten().any(|n| n == ".symtab");
    v.push(match symbols {
        _ if !image => c("R4", "C", "T3", NotApplicable, "not a loadable image (ET_REL/ET_CORE)"),
        Some(sy) if sy.iter().any(|s| s.starts_with("__stack_chk_fail") || s.starts_with("__stack_chk_guard") || s.starts_with("__intel_security_cookie")) => c("R4", "C", "T3", Pass, "stack-protector symbols present"),
        Some(_) if stripped && interps.is_empty() => c("R4", "C", "T3", NotApplicable, "undecidable: stripped static binary"),
        Some(_) => c("R4", "C", "T3", Fail, "no stack-protector symbols"),
        None => c("R4", "C", "T3", Unparsable, "symbols not readable (level-2 parse failed)"),
    });
    // Static model, used by the RQ3 silent-misreading oracle
    model.entry = Some(h.e_entry);
    model.loads = loads.iter().map(|p| (p.p_vaddr, p.p_memsz, p.p_offset, p.p_filesz, p.p_flags)).collect();
    model.interp = interp_s; model.needed = needed;
    (ctx, model, v)
}

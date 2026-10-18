//! Level 1: bounds-checked, field-by-field ELF reader. Never panics; every problem is recorded
//! as an `Issue` with the field and file offset that caused it.
use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
pub struct Issue { pub field: String, pub offset: u64, pub msg: String }

#[derive(Serialize, Clone, Copy, Debug, Default)]
pub struct Header {
    pub e_type: u16, pub e_machine: u16, pub e_version: u32, pub e_entry: u64, pub e_phoff: u64,
    pub e_shoff: u64, pub e_flags: u32, pub e_ehsize: u16, pub e_phentsize: u16, pub e_phnum: u16,
    pub e_shentsize: u16, pub e_shnum: u16, pub e_shstrndx: u16,
}
#[derive(Serialize, Clone, Copy, Debug, Default)]
pub struct Phdr { pub p_type: u32, pub p_flags: u32, pub p_offset: u64, pub p_vaddr: u64, pub p_paddr: u64, pub p_filesz: u64, pub p_memsz: u64, pub p_align: u64 }
#[derive(Serialize, Clone, Copy, Debug, Default)]
pub struct Shdr { pub sh_name: u32, pub sh_type: u32, pub sh_flags: u64, pub sh_addr: u64, pub sh_offset: u64, pub sh_size: u64, pub sh_link: u32, pub sh_info: u32, pub sh_addralign: u64, pub sh_entsize: u64 }
#[derive(Serialize, Clone, Copy, Debug, PartialEq)]
pub enum Sht { Absent, Present, Unreadable }

pub const PT_LOAD: u32 = 1; pub const PT_DYNAMIC: u32 = 2; pub const PT_INTERP: u32 = 3;
pub const PT_GNU_STACK: u32 = 0x6474e551; pub const PT_GNU_RELRO: u32 = 0x6474e552;
pub const PF_X: u32 = 1; pub const PF_W: u32 = 2;
pub const SHT_NOBITS: u32 = 8; pub const SHT_STRTAB: u32 = 3; pub const SHT_NULL: u32 = 0;
pub const SHF_WRITE: u64 = 1; pub const SHF_ALLOC: u64 = 2; pub const SHF_EXECINSTR: u64 = 4; pub const SHF_TLS: u64 = 0x400;

pub struct Raw<'a> {
    pub data: &'a [u8],
    pub magic_ok: bool,
    pub ident: Option<[u8; 16]>,
    pub is64: Option<bool>,
    pub le: Option<bool>,
    pub h: Option<Header>,
    pub phdrs: Vec<Phdr>,
    pub pht_complete: bool,
    pub sht: Sht,
    pub shdrs: Vec<Shdr>,
    pub shnum: u64,
    pub shstrndx: u64,
    pub issues: Vec<Issue>,
}

fn rd<const N: usize>(d: &[u8], off: u64) -> Option<[u8; N]> {
    let o = usize::try_from(off).ok()?;
    let end = o.checked_add(N)?;
    d.get(o..end)?.try_into().ok()
}
impl<'a> Raw<'a> {
    pub fn u16(&self, off: u64) -> Option<u16> { let b = rd::<2>(self.data, off)?; Some(if self.le? { u16::from_le_bytes(b) } else { u16::from_be_bytes(b) }) }
    pub fn u32(&self, off: u64) -> Option<u32> { let b = rd::<4>(self.data, off)?; Some(if self.le? { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) }) }
    pub fn u64(&self, off: u64) -> Option<u64> { let b = rd::<8>(self.data, off)?; Some(if self.le? { u64::from_le_bytes(b) } else { u64::from_be_bytes(b) }) }
    pub fn word(&self, off: u64) -> Option<u64> { if self.is64? { self.u64(off) } else { self.u32(off).map(u64::from) } }
    fn issue(&mut self, field: &str, offset: u64, msg: impl Into<String>) { self.issues.push(Issue { field: field.into(), offset, msg: msg.into() }); }
    pub fn size(&self) -> u64 { self.data.len() as u64 }
    pub fn phsz(&self) -> u64 { if self.is64 == Some(true) { 56 } else { 32 } }
    pub fn shsz(&self) -> u64 { if self.is64 == Some(true) { 64 } else { 40 } }
    pub fn ehsz(&self) -> u64 { if self.is64 == Some(true) { 64 } else { 52 } }

    fn read_phdr(&self, off: u64) -> Option<Phdr> {
        if self.is64? {
            Some(Phdr { p_type: self.u32(off)?, p_flags: self.u32(off + 4)?, p_offset: self.u64(off + 8)?, p_vaddr: self.u64(off + 16)?,
                p_paddr: self.u64(off + 24)?, p_filesz: self.u64(off + 32)?, p_memsz: self.u64(off + 40)?, p_align: self.u64(off + 48)? })
        } else {
            Some(Phdr { p_type: self.u32(off)?, p_offset: self.u32(off + 4)? as u64, p_vaddr: self.u32(off + 8)? as u64, p_paddr: self.u32(off + 12)? as u64,
                p_filesz: self.u32(off + 16)? as u64, p_memsz: self.u32(off + 20)? as u64, p_flags: self.u32(off + 24)?, p_align: self.u32(off + 28)? as u64 })
        }
    }
    fn read_shdr(&self, off: u64) -> Option<Shdr> {
        if self.is64? {
            Some(Shdr { sh_name: self.u32(off)?, sh_type: self.u32(off + 4)?, sh_flags: self.u64(off + 8)?, sh_addr: self.u64(off + 16)?, sh_offset: self.u64(off + 24)?,
                sh_size: self.u64(off + 32)?, sh_link: self.u32(off + 40)?, sh_info: self.u32(off + 44)?, sh_addralign: self.u64(off + 48)?, sh_entsize: self.u64(off + 56)? })
        } else {
            Some(Shdr { sh_name: self.u32(off)?, sh_type: self.u32(off + 4)?, sh_flags: self.u32(off + 8)? as u64, sh_addr: self.u32(off + 12)? as u64, sh_offset: self.u32(off + 16)? as u64,
                sh_size: self.u32(off + 20)? as u64, sh_link: self.u32(off + 24)?, sh_info: self.u32(off + 28)?, sh_addralign: self.u32(off + 32)? as u64, sh_entsize: self.u32(off + 36)? as u64 })
        }
    }

    pub fn parse(data: &'a [u8]) -> Raw<'a> {
        let mut r = Raw { data, magic_ok: false, ident: None, is64: None, le: None, h: None, phdrs: vec![], pht_complete: false,
            sht: Sht::Absent, shdrs: vec![], shnum: 0, shstrndx: 0, issues: vec![] };
        if data.len() < 4 || &data[..4] != b"\x7fELF" { r.issue("e_ident[EI_MAG]", 0, "missing ELF magic"); return r; }
        r.magic_ok = true;
        let Some(id) = rd::<16>(data, 0) else { r.issue("e_ident", 0, "file shorter than e_ident"); return r; };
        r.ident = Some(id);
        r.is64 = match id[4] { 1 => Some(false), 2 => Some(true), _ => None };
        r.le = match id[5] { 1 => Some(true), 2 => Some(false), _ => None };
        if r.is64.is_none() { r.issue("e_ident[EI_CLASS]", 4, format!("invalid class {}", id[4])); }
        if r.le.is_none() { r.issue("e_ident[EI_DATA]", 5, format!("invalid data encoding {}", id[5])); }
        if r.is64.is_none() || r.le.is_none() { return r; }
        if r.size() < r.ehsz() { r.issue("ELF header", 0, "file shorter than the ELF header"); return r; }
        let w = |r: &Raw, o64: u64, o32: u64| if r.is64 == Some(true) { r.u64(o64) } else { r.u32(o32).map(u64::from) };
        let is64 = r.is64 == Some(true);
        let o = move |o64: u64, o32: u64| if is64 { o64 } else { o32 };
        let h = Header {
            e_type: r.u16(16).unwrap_or(0), e_machine: r.u16(18).unwrap_or(0), e_version: r.u32(20).unwrap_or(0),
            e_entry: w(&r, 24, 24).unwrap_or(0), e_phoff: w(&r, 32, 28).unwrap_or(0), e_shoff: w(&r, 40, 32).unwrap_or(0),
            e_flags: r.u32(o(48, 36)).unwrap_or(0), e_ehsize: r.u16(o(52, 40)).unwrap_or(0), e_phentsize: r.u16(o(54, 42)).unwrap_or(0),
            e_phnum: r.u16(o(56, 44)).unwrap_or(0), e_shentsize: r.u16(o(58, 46)).unwrap_or(0), e_shnum: r.u16(o(60, 48)).unwrap_or(0),
            e_shstrndx: r.u16(o(62, 50)).unwrap_or(0),
        };
        r.h = Some(h);
        // Program header table: read with the structure stride, as the kernel requires.
        r.pht_complete = true;
        for i in 0..h.e_phnum as u64 {
            let off = match h.e_phoff.checked_add(i * r.phsz()) { Some(v) => v, None => { r.pht_complete = false; r.issue("e_phoff", o(32, 28), "program header offset overflows"); break; } };
            match r.read_phdr(off) { Some(p) => r.phdrs.push(p), None => { r.pht_complete = false; r.issue("program header table", off, format!("program header {i} beyond end of file")); break; } }
        }
        // Section header table, honouring extended numbering.
        if h.e_shoff != 0 {
            match r.read_shdr(h.e_shoff) {
                None => { r.sht = Sht::Unreadable; r.issue("e_shoff", o(40, 32), "section header table beyond end of file"); }
                Some(s0) => {
                    let n = if h.e_shnum == 0 { s0.sh_size } else { h.e_shnum as u64 };
                    r.shnum = n;
                    r.shstrndx = if h.e_shstrndx == 0xffff { s0.sh_link as u64 } else { h.e_shstrndx as u64 };
                    r.sht = Sht::Present;
                    let cap = n.min(1 << 20);
                    for i in 0..cap {
                        let off = match h.e_shoff.checked_add(i * r.shsz()) { Some(v) => v, None => { r.sht = Sht::Unreadable; break; } };
                        match r.read_shdr(off) { Some(s) => r.shdrs.push(s), None => { r.sht = Sht::Unreadable; r.issue("section header table", off, format!("section header {i} of {n} beyond end of file")); break; } }
                    }
                }
            }
        }
        r
    }

    pub fn bytes(&self, off: u64, len: u64) -> Option<&'a [u8]> {
        let s = usize::try_from(off).ok()?; let e = s.checked_add(usize::try_from(len).ok()?)?; self.data.get(s..e)
    }
    pub fn cstr(&self, off: u64, limit: u64) -> Option<String> {
        let s = usize::try_from(off).ok()?; let lim = usize::try_from(limit).ok()?;
        let tail = self.data.get(s..)?; let tail = &tail[..tail.len().min(lim)];
        let n = tail.iter().position(|&b| b == 0)?; Some(String::from_utf8_lossy(&tail[..n]).into_owned())
    }
    pub fn section_name(&self, s: &Shdr) -> Option<String> {
        let st = self.shdrs.get(usize::try_from(self.shstrndx).ok()?)?;
        if st.sh_type == SHT_NOBITS || s.sh_name as u64 >= st.sh_size { return None; }
        self.cstr(st.sh_offset.checked_add(s.sh_name as u64)?, st.sh_size - s.sh_name as u64)
    }
    pub fn vaddr_to_off(&self, va: u64) -> Option<u64> {
        self.phdrs.iter().filter(|p| p.p_type == PT_LOAD).find_map(|p| {
            if va >= p.p_vaddr && va < p.p_vaddr.checked_add(p.p_filesz)? { p.p_offset.checked_add(va - p.p_vaddr) } else { None }
        })
    }
    pub fn interps(&self) -> Vec<(Phdr, Option<Vec<u8>>)> {
        self.phdrs.iter().filter(|p| p.p_type == PT_INTERP).map(|p| (*p, self.bytes(p.p_offset, p.p_filesz).map(|b| b.to_vec()))).collect()
    }
    /// Dynamic entries read from PT_DYNAMIC in the file (bounded, stops at DT_NULL).
    pub fn dynamic(&self) -> Vec<(u64, u64)> {
        let Some(d) = self.phdrs.iter().find(|p| p.p_type == PT_DYNAMIC) else { return vec![] };
        let esz = if self.is64 == Some(true) { 16 } else { 8 };
        let mut out = vec![];
        let mut i = 0u64;
        while i * esz + esz <= d.p_filesz && i < 4096 {
            let off = match d.p_offset.checked_add(i * esz) { Some(v) => v, None => break };
            let (Some(t), Some(v)) = (self.word(off), self.word(off + esz / 2)) else { break };
            if t == 0 { break; }
            out.push((t, v)); i += 1;
        }
        out
    }
    pub fn needed(&self) -> Vec<String> {
        let dy = self.dynamic();
        let Some(strtab_va) = dy.iter().find(|(t, _)| *t == 5).map(|x| x.1) else { return vec![] };
        let strsz = dy.iter().find(|(t, _)| *t == 10).map(|x| x.1).unwrap_or(4096);
        let Some(base) = self.vaddr_to_off(strtab_va) else { return vec![] };
        dy.iter().filter(|(t, _)| *t == 1).filter_map(|(_, v)| if *v < strsz { self.cstr(base.checked_add(*v)?, strsz - v) } else { None }).collect()
    }
}

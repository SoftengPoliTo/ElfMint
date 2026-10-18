#!/usr/bin/env python3
"""Generate the synthetic ELF fixtures used by tests/cli.rs.

All fixtures derive from one minimal statically linked x86_64 ELF64 executable
(ELF header + one PT_LOAD program header + 12 bytes of code that call exit(0)).
No real-world binary is needed, so the test suite runs on any host.
"""
import struct, pathlib

OUT = pathlib.Path(__file__).parent / "fixtures"
OUT.mkdir(exist_ok=True)

BASE = 0x400000
CODE = bytes.fromhex("b83c000000" "31ff" "0f05")  # mov eax,60 ; xor edi,edi ; syscall
EHDR = 64
PHDR = 56
ENTRY = BASE + EHDR + PHDR

def ehdr(e_shoff=0, e_shnum=0, e_shstrndx=0, ei_data=1, e_machine=62, e_type=2, e_phentsize=PHDR, e_ehsize=EHDR):
    ident = b"\x7fELF" + bytes([2, ei_data, 1, 0, 0]) + b"\x00" * 7
    return ident + struct.pack("<HHIQQQIHHHHHH", e_type, e_machine, 1, ENTRY, EHDR, e_shoff, 0,
                               e_ehsize, e_phentsize, 1, 64, e_shnum, e_shstrndx)

def phdr(filesz=None, memsz=None, flags=5):
    total = EHDR + PHDR + len(CODE)
    filesz = total if filesz is None else filesz
    memsz = total if memsz is None else memsz
    return struct.pack("<IIQQQQQQ", 1, flags, 0, BASE, BASE, filesz, memsz, 0x1000)

def write(name, data):
    (OUT / name).write_bytes(data)

base = ehdr() + phdr() + CODE
write("minimal.elf", base)
# Section header table declared beyond the end of file (H8 fail, X3 pass)
write("sht_beyond_eof.elf", ehdr(e_shoff=0x10000, e_shnum=5, e_shstrndx=4) + phdr() + CODE)
# File truncated inside its only PT_LOAD (X3 fail)
write("truncated.elf", base[:-6])
# EI_DATA flipped while every other field stays little-endian (H2 fail: machine decodes only when swapped)
write("ei_data_flipped.elf", ehdr(ei_data=2) + phdr() + CODE)
# p_filesz > p_memsz (P1 fail: the kernel kills the process after the point of no return)
write("filesz_gt_memsz.elf", ehdr() + phdr(memsz=EHDR + PHDR) + CODE)
# e_phentsize off by eight (H6 fail: the kernel rejects the file with ENOEXEC)
write("phentsize_plus8.elf", ehdr(e_phentsize=PHDR + 8) + phdr() + CODE)
# Writable and executable PT_LOAD (P6 fail)
write("rwx_segment.elf", ehdr() + phdr(flags=7) + CODE)
# 72-byte damaged prefix: valid identification, every later byte 0x41
write("damaged_prefix.elf", b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + b"\x00" * 7 + b"A" * 56)
print("fixtures written to", OUT)

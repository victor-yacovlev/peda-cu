#!/usr/bin/env python3
"""Functional verification of PEDA regexes:
1. Prove the 4 old->new pattern changes are behaviorally equivalent
   (old: literal newline char in class, new: regex \\n escape).
2. Test key parsers against realistic GDB/proc/readelf output samples."""
import re, sys
sys.path.insert(0, 'lib')

failures = []
def check(name: str, cond: object, detail: object = None) -> None:
    print("  %-55s %s" % (name, "OK" if cond else "FAIL " + str(detail)))
    if not cond:
        failures.append(name)

# --- 1. equivalence of the 4 changed patterns -----------------------------
# Old source used non-raw strings: '\n' was a REAL newline char, while
# invalid escapes like '\s' passed through as backslash+s. Reproduce the
# exact old values warning-free via r-string + newline substitution.
print("[1] old (literal \\n) vs new (regex escape \\n) equivalence")
old_newline = lambda s: s.replace(r"\n", "\n")
cases = [
    ("osx-vmmap",
     old_newline(r"([^\n]*)\s*  ([0-9a-f][^-\s]*)-([^\s]*) \[.*\]\s([^/]*).*  (.*)"),
     r"([^\n]*)\s*  ([0-9a-f][^-\s]*)-([^\s]*) \[.*\]\s([^/]*).*  (.*)"),
    ("solib-hdr",
     old_newline(r"[^\n]*\s*(0x[^ ]*) - (0x[^ ]*) is (\.[^ ]*) in (.*)"),
     r"[^\n]*\s*(0x[^ ]*) - (0x[^ ]*) is (\.[^ ]*) in (.*)"),
    ("uid", old_newline(r"Uid:\s*([^\n]*)"), r"Uid:\s*([^\n]*)"),
    ("gid", old_newline(r"Gid:\s*([^\n]*)"), r"Gid:\s*([^\n]*)"),
]
samples = [
    "__DATA 00007fff77975000-00007fff77976000 [ 4K] rw-/rw- SM=COW /usr/lib/lib.dylib",
    "  0x00007ffff7dd0000 - 0x00007ffff7dd1000 is .interp in /bin/ls",
    "Uid:\t1000\t0\t1000\t1000\nGid:\t1000\t0\t1000\t1000\n",
    "line1\nline2 with spaces\tand tabs\n",
    "", "\n", "no newlines at all",
]
for name, old, new in cases:
    same = True
    for s in samples:
        a = re.search(old, s)
        b = re.search(new, s)
        if (a is None) != (b is None) or (a and a.groups() != b.groups()):
            same = False
            break
    check(name, same)

# --- 2. realistic parser tests --------------------------------------------
print("[2] getfile: info files output")
p = re.compile(r".*exec file:\s*`(.*)'")
m = p.search("\tSymbols from \"/bin/ls\".\n\tLocal exec file:\n\t`/bin/ls', file type elf64-x86-64.\n")
check("exec file", m and m.group(1) == "/bin/ls", m and m.group(1))
p2 = re.compile(r"Symbols from \"([^\"]*)")
m2 = p2.search("\tSymbols from \"/bin/busybox\".\n")  # stripped fallback
check("stripped fallback", m2 and m2.group(1) == "/bin/busybox", m2 and m2.group(1))

print("[3] breakpoints: info break output")
bp = re.compile(r"^(\d*)\s*(.*breakpoint)\s*(keep|del)\s*(y|n)\s*(0x[^ ]*)\s*(.*)")
line = "1       breakpoint     keep     y     0x0000000000401136 in main at /tmp/t.c:11"
m = bp.match(line)
check("breakpoint full", m and m.group(1) == "1" and m.group(6).strip().startswith("in main"), m and m.groups())
bp2 = re.compile(r"^(\d*)\s*(.*point)\s*(keep|del)\s*(y|n)\s*(.*)")
m = bp2.match("2       hw breakpoint   keep     y     0x0000000000401000 <_start>")
check("breakpoint generic", m and m.group(2) == "hw breakpoint", m and m.groups())
m = re.match(r"in.*at(.*:\d*)", "in main at /tmp/t.c:11")
check("breakpoint location", m and m.group(1) == " /tmp/t.c:11", m and m.groups())

print("[4] disassembly line parsing (x/i, current_inst)")
p = re.compile(r"\s*(0x[^ ]*).*?:\s*(\S*)\s*(.*)")
m = p.search("=> 0x401136 <main+8>:\tmov    edi,0x5\n")
check("x/i intel", m and m.group(1) == "0x401136" and m.group(2) == "mov", m and m.groups())
m = p.search("   0x101ac <main+24>:\tbeq\ta0,a1,0x10234\n")
check("x/i riscv (tab-separated mnemonic)", m and m.group(2) == "beq" and m.group(3) == "a0,a1,0x10234", m and m.groups())
m = p.search("   0x101ac <main+24>:  beq    a0,a1,0x10234\n")
check("x/i space-separated mnemonic", m and m.group(2) == "beq", m and m.groups())
p2 = re.compile(r"(.*?)\s*<.*?>\s*([^ ]*)\s*(.*)")
m = p2.search("0x401136 <main+8>: mov edi,0x5")
# NOTE: pre-existing upstream quirk - for objdump --prefix-address lines with a
# colon after <sym>, group(2) captures ':'; the primary gdb x/i path (above)
# is the one actually used while a process is running
check("addr<sym> fallback (documents current behavior)", m and m.group(1) == "0x401136", m and m.groups())

print("[5] linux /proc/pid/maps (get_vmmap)")
p = re.compile(r"([0-9a-f]*)-([0-9a-f]*) ([rwxps-]*)(?: [^ ]*){3} *(.*)")
for line in [
    "00400000-0040b000 r-xp 00000000 08:02 538840  /path/to/prog",
    "7ffff7dd0000-7ffff7dd2000 rw-p 00000000 00:00 0 ",
]:
    m = p.match(line)
    check("maps: %s" % line[:20], m and m.group(3) in ("r-xp", "rw-p") , m and m.groups())

print("[6] /proc/pid/status (procinfo)")
status = "Name:\tbash\nPPid:\t1234\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n"
m = re.search(r"PPid:\s*([^\s]*)", status)
check("PPid", m and m.group(1) == "1234", m and m.group(1))
m = re.search(r"Uid:\s*([^\n]*)", status)
check("Uid (4 fields)", m and m.group(1).strip() == "1000\t1000\t1000\t1000", m and m.group(1))
m = re.search(r"Uid:\s*(\S+)", status)
check("Uid first field still parseable", m and m.group(1) == "1000")
m = re.search(r"Gid:\s*([^\n]*)", status)
check("Gid", m is not None and "1000" in m.group(1))

print("[7] elfheader solib (maintenance info sections)")
p = re.compile(r"[^\n]*\s*(0x[^ ]*) - (0x[^ ]*) is (\.[^ ]*) in (.*)")
m = p.search("        0x00007ffff7fce000 - 0x00007ffff7fcf000 is .note.gnu.build-id in /lib/x.so")
check("solib section", m and m.group(3) == ".note.gnu.build-id", m and m.groups())

print("[8] eval_target x86 syntax")
p = re.compile(r".*?:\s*[^ ]*\s*(.* PTR ).*(0x[^ ]*)")
inst = "0x40113a <main+12>:\tmov    DWORD PTR [rsp+0x4],0x2"
m = p.search(inst)
check("PTR operand", m and "PTR" in m.group(1), m and m.groups())

print("[9] JMPCALL bytes pattern (search_jmpcall)")
JMPCALL = [b"call", b"jmp"]
pat = re.compile(b'|'.join(JMPCALL).replace(b' ', b'\\ '))
check("bytes call", re.search(pat, b"\xe8\x11\x22 call foo") is not None)
check("bytes jmp only", re.search(pat, b"jmp 0x4011") is not None)

print("[10] utils.format_disasm_code line parsing")
p = re.compile(r".*(0x[^ ]*).*:\s*([^ ]*)")
m = re.search(p, "  0x401136 <main+8>:\tcall   0x401050 <puts@plt>")
check("disasm line", m and m.group(2) == "call", m and m.groups())

print("[11] search_asm wildcard")
asmcode = "mov ?ax, ?bx"
wild = re.escape(asmcode).replace("\\ ", ".*").replace("\\?", ".*")
# py3.7+ re.escape: '?' -> '\\?', ' ' stays ' ' -> the space replace is a no-op now
check("wildcard ? handled", "\\?" in re.escape(asmcode) and "?ax" not in wild)
m = re.search(wild, "mov eax, ebx")
check("wildcard match", m is not None, wild)
m = re.search(wild, "mov rax, rbx")
check("wildcard match 64", m is not None)

print("[12] pattern_offset / cyclic charset regex still intact")
import utils
cs = utils.cyclic_pattern_charset(2)
check("charset no backslash-paren", "(" in cs and "\\" not in cs, cs[:40])
p = re.compile(b"[" + re.escape(utils.to_binary_string(cs)) + b"]{4,}")
m = p.search(b"\x00\x01" + utils.cyclic_pattern(32) + b"\xff")
check("charset class match", m is not None and m.group().startswith(b"A"), m and m.group()[:8])

print()
print("FAILURES: %d" % len(failures))
sys.exit(1 if failures else 0)

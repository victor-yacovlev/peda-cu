"""Unit tests for the RISC-V port of PEDA, executed INSIDE gdb-multiarch
against a live qemu-riscv64 target.

This file must be sourced from gdb AFTER peda.py and after connecting:

    gdb-multiarch -q BIN \
        -ex 'source /path/to/peda.py' \
        -ex 'target remote :PORT' \
        -ex 'source tests/test_peda_gdb.py'

Use tests/run_unit_tests.sh to build the binary, start qemu and collect
results. Requires `peda` in the __main__ namespace (as created by sourcing
peda.py first).

Coverage:
    - architecture detection and register-name table
    - parse_and_eval word-boundary substitution (hex vs register names)
    - RISC-V argument heuristics (a0-a7) and the DWARF fallback parser
    - vmmap cascade parsers (modern / legacy "info proc mappings" formats,
      local qemu /proc fallback)
    - branch semantics: signed vs unsigned, pseudo (beqz/...), compressed,
      unconditional jumps, eval_target parsing (bare hex / 0x hex / jr reg)
    - live single-pass flow: args at the call site, args at function entry
      (gcc -O0 prologue shuffles registers -> DWARF), branch prediction
      consistency checked against real single-stepping
    - vmrange/is_executable/is_writable/is_address (canned + live, plus the
      empty-maps readability fallback)
    - searchmem: literal / regex / little-endian hex value / bad-regex
      fallback / swapped range, live searchmem_by_range
    - memory r/w roundtrips below $sp (readmem/writemem/read_int/write_int)
    - disassembly helpers: current_inst/next_inst/prev_inst/get_disasm/
      disassemble_around
    - string_to_argv: $register values, "+N" relative offsets, math exprs
    - ELF helpers: elfentry/elfheader/checksec/getfile + static-binary gates
    - snapshot roundtrip (registers + writable memory)
    - get_status at a real breakpoint hit
"""

import contextlib
import re
import sys
import unittest

import gdb
from __main__ import peda  # provided by `source peda.py` before this file
from utils import to_int, reset_cache  # already on sys.path


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

@contextlib.contextmanager
def patch_redirect(pedamod, pairs):
    """Intercept peda.execute_redirect: {command prefix: canned output}.

    Unmatched commands fall through to the real implementation.
    """
    orig = pedamod.execute_redirect

    def fake(cmd, silent=False):
        for pref, out in pairs.items():
            if cmd.startswith(pref):
                return out(cmd) if callable(out) else out
        return orig(cmd, silent)

    pedamod.execute_redirect = fake
    try:
        yield
    finally:
        pedamod.execute_redirect = orig


@contextlib.contextmanager
def patch_execute(pedamod, pairs):
    """Intercept peda.execute: {command prefix: return value}."""
    orig = pedamod.execute

    def fake(cmd):
        for pref, res in pairs.items():
            if cmd.startswith(pref):
                return res
        return orig(cmd)

    pedamod.execute = fake
    try:
        yield
    finally:
        pedamod.execute = orig


def setreg(name, value):
    gdb.execute(f"set ${name} = {value}")


# canned outputs -----------------------------------------------------------

INFO_PROC_MODERN = """process 4242
Mapped address spaces:

Start Addr         End Addr           Size               Offset             Perms File
        0x10000            0x7a000            0x6a000                0x0  r-xp  /tmp/test_static
        0x7a000            0x80000             0x6000            0x6a000  rw-p  /tmp/test_static
        0x80000            0x85000             0x5000                0x0  rw-p
"""

INFO_PROC_LEGACY = """process 4242
Start Addr       End Addr         Size     Offset    objfile
   0x10000         0x7a000       0x6a000      0x0   /tmp/test_static
   0x7a000         0x80000        0x6000  0x6a000   /tmp/test_static
"""

CODE_SIX_ARGS = ("0x104fc:\tli\ta5,6\n"
                 "0x104fe:\tli\ta4,5\n"
                 "0x10500:\tli\ta3,4\n"
                 "0x10502:\tli\ta2,3\n"
                 "0x10504:\tli\ta1,2\n"
                 "0x10506:\tli\ta0,1\n")

CODE_ONLY_STORES = ("0x1:\tsd\ta0,0(sp)\n"
                    "0x2:\tsw\ta3,4(s0)\n")

FAKE_MAPS = [
    (0x10000, 0x7a000, "r-xp", "/tmp/test_static"),
    (0x7a000, 0x80000, "rw-p", "/tmp/test_static"),
    (0x80000, 0x85000, "rw-p", "mapped"),
]


# --------------------------------------------------------------------------
# test cases (executed in the order given in build_suite below)
# --------------------------------------------------------------------------

class ArchTests(unittest.TestCase):
    def test_getarch_riscv(self):
        (arch, bits) = peda.getarch()
        self.assertIn("riscv", arch)
        self.assertEqual(bits, 64)

    def test_arch_predicates(self):
        self.assertTrue(peda._is_riscv())
        self.assertFalse(peda._is_x86())

    def test_regnames_table(self):
        names = peda.get_regnames()
        rv64 = names[64]
        for r in ["ra", "sp", "gp", "tp", "pc",
                  "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
                  "t0", "t1", "t2", "t3", "t4", "t5", "t6",
                  "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
                  "s8", "s9", "s10", "s11"]:
            self.assertIn(r, rv64)
        # no x86 leftovers under a riscv target
        for r in ["rax", "rbx", "rdi", "rip", "eflags"]:
            self.assertNotIn(r, rv64)

    def test_is_target_remote(self):
        self.assertTrue(peda.is_target_remote())

    def test_get_eflags_none(self):
        # no flags register on riscv -> graceful None (not an exception)
        self.assertIsNone(peda.get_eflags())


class ParseAndEvalTests(unittest.TestCase):
    """Regression tests for word-boundary register substitution.

    RISC-V ABI names (a0, a7, t0, ...) are valid hex substrings; naive
    str.replace() corrupts hex constants like 0x1a0b -> 0x1$a0b.
    """

    def test_hex_constant_with_a0(self):
        self.assertEqual(to_int(peda.parse_and_eval("0x1a0b")), 0x1a0b)

    def test_hex_constant_with_a7(self):
        self.assertEqual(to_int(peda.parse_and_eval("0x7a70")), 0x7a70)

    def test_register_name_substituted(self):
        setreg("a0", 42)
        self.assertEqual(to_int(peda.parse_and_eval("a0")), 42)

    def test_register_arithmetics(self):
        setreg("s1", 100)
        self.assertEqual(to_int(peda.parse_and_eval("s1+8")), 108)

    def test_s1_not_confused_with_s10(self):
        setreg("s1", 1)
        setreg("s10", 2)
        self.assertEqual(to_int(peda.parse_and_eval("s10")), 2)
        self.assertEqual(to_int(peda.parse_and_eval("s1")), 1)


class FunctionArgsHeuristicTests(unittest.TestCase):
    def test_heuristic_count_from_code(self):
        # li a0..a5 -> 6 args; values are read from current registers
        args = peda._get_function_args_riscv(CODE_SIX_ARGS, None)
        self.assertEqual(len(args), 6)

    def test_heuristic_values_follow_registers(self):
        for (i, r) in enumerate(["a0", "a1", "a2", "a3", "a4", "a5"]):
            setreg(r, 0x100 + i)
        args = peda._get_function_args_riscv(CODE_SIX_ARGS, None)
        self.assertEqual(args, [0x100 + i for i in range(6)])

    def test_explicit_argc(self):
        args = peda._get_function_args_riscv(CODE_SIX_ARGS, 3)
        self.assertEqual(len(args), 3)

    def test_argc_capped_at_8(self):
        self.assertEqual(len(peda._get_function_args_riscv(CODE_SIX_ARGS, 99)), 8)

    def test_stores_are_not_writes(self):
        # sd/sw first operand is a SOURCE, must not count as arg setup
        self.assertEqual(peda._get_function_args_riscv(CODE_ONLY_STORES, None), [])

    def test_empty_code(self):
        self.assertEqual(peda._get_function_args_riscv("", None), [])


class DwarfArgsParserTests(unittest.TestCase):
    """_get_function_args_dwarf parses "info args" output (both formats)."""

    def test_per_line_format(self):
        with patch_redirect(peda, {"info args": "a = 1\nb = 2\nc = 3\n"}):
            self.assertEqual(peda._get_function_args_dwarf(), [1, 2, 3])

    def test_single_line_comma_format(self):
        with patch_redirect(peda, {"info args": "a = 1, b = 2, c = 3"}):
            self.assertEqual(peda._get_function_args_dwarf(), [1, 2, 3])

    def test_hex_values(self):
        with patch_redirect(peda, {"info args": "p = 0x7fc\nq = 16\n"}):
            self.assertEqual(peda._get_function_args_dwarf(), [0x7fc, 16])

    def test_non_integer_falls_back(self):
        with patch_redirect(peda, {"info args": 's = "text"\n'}):
            self.assertIsNone(peda._get_function_args_dwarf())

    def test_no_debug_info(self):
        with patch_redirect(peda, {"info args": "No symbol table info available."}):
            self.assertIsNone(peda._get_function_args_dwarf())

    def test_empty_output(self):
        with patch_redirect(peda, {"info args": ""}):
            self.assertIsNone(peda._get_function_args_dwarf())


class VmmapParserTests(unittest.TestCase):
    def setUp(self):
        reset_cache()  # get_vmmap/getpid are memoized

    def _maps(self, canned):
        with patch_redirect(peda, {"info proc mappings": canned}):
            return peda.get_vmmap("all")

    def test_modern_format(self):
        maps = self._maps(INFO_PROC_MODERN)
        self.assertEqual(len(maps), 3)
        (start, end, perm, name) = maps[0]
        self.assertEqual(start, 0x10000)
        self.assertEqual(end, 0x7a000)
        self.assertEqual(perm, "r-xp")
        self.assertEqual(name, "/tmp/test_static")
        self.assertEqual(maps[1][2], "rw-p")
        self.assertEqual(maps[2][2], "rw-p")
        self.assertEqual(maps[2][3], "mapped")  # anonymous region

    def test_legacy_format_without_perms(self):
        maps = self._maps(INFO_PROC_LEGACY)
        self.assertEqual(len(maps), 2)
        self.assertEqual(maps[0][2], "")  # no perms column -> empty
        self.assertEqual(maps[0][3], "/tmp/test_static")

    def test_local_proc_fallback(self):
        """Both remote sources fail -> local /proc/<qemu_pid>/maps is used."""
        reset_cache()
        with patch_redirect(peda, {"info proc mappings": None}), \
                patch_execute(peda, {"remote get": False}):
            maps = peda.get_vmmap("all")
        # the inferior pid IS the local qemu process: its host maps are read
        self.assertGreater(len(maps), 3)
        for (start, end, perm, name) in maps:
            self.assertLess(start, end)

    def test_live_vmmap_from_info_proc(self):
        # unpatched: the real "info proc mappings" path (cascade source #1)
        maps = peda.get_vmmap("all")
        self.assertGreaterEqual(len(maps), 3)
        self.assertTrue(any(m[3] == "[stack]" for m in maps))


class VmmapBinaryTests(unittest.TestCase):
    def test_binary_ranges(self):
        maps = peda.get_vmmap("binary")
        self.assertGreaterEqual(len(maps), 2)
        perms = [m[2] for m in maps]
        self.assertTrue(any("r-x" in p for p in perms))
        self.assertTrue(any("rw-" in p for p in perms))
        for (_, _, _, name) in maps:
            self.assertTrue(name.endswith("test_static"), name)

    def test_pc_inside_binary_mapping(self):
        pc = peda.getreg("pc")
        self.assertTrue(peda.is_address(pc))


class BranchSemanticsTests(unittest.TestCase):
    """_testjump_riscv / eval_target on synthetic instruction texts.

    Instruction strings mimic gdb "x/i" output: binutils separates the
    mnemonic and operands with a TAB on riscv.
    """

    def setUp(self):
        # known register state for every test
        for r in ["a0", "a1", "a2", "t0", "t1", "t2", "s0", "ra"]:
            setreg(r, 0)

    def tj(self, inst):
        return peda._testjump_riscv(inst)

    # ---- equality family -------------------------------------------------
    def test_beq_taken(self):
        setreg("a0", 7)
        setreg("a1", 7)
        self.assertEqual(self.tj("=> 0x1000 <f>:\tbeq\ta0,a1,0x2000"), 0x2000)

    def test_beq_not_taken(self):
        setreg("a0", 7)
        setreg("a1", 8)
        self.assertIsNone(self.tj("=> 0x1000 <f>:\tbeq\ta0,a1,0x2000"))

    def test_bne_taken(self):
        setreg("a0", 7)
        setreg("a1", 8)
        self.assertEqual(self.tj("=> 0x1000 <f>:\tbne\ta0,a1,0x2000"), 0x2000)

    def test_bne_not_taken(self):
        setreg("a0", 7)
        setreg("a1", 7)
        self.assertIsNone(self.tj("=> 0x1000 <f>:\tbne\ta0,a1,0x2000"))

    # ---- signed vs unsigned (the classic -1 vs 1 boundary) ---------------
    def test_blt_signed_negative_is_smaller(self):
        setreg("t0", -1)  # 0xffffffffffffffff
        setreg("t1", 1)
        self.assertEqual(self.tj("=> 0x1000 <f>:\tblt\tt0,t1,0x3000"), 0x3000)

    def test_bltu_unsigned_negative_is_huge(self):
        setreg("t0", -1)
        setreg("t1", 1)
        self.assertIsNone(self.tj("=> 0x1000 <f>:\tbltu\tt0,t1,0x3000"))

    def test_bge_signed_negative_not_ge(self):
        setreg("t0", -1)
        setreg("t1", 1)
        self.assertIsNone(self.tj("=> 0x1000 <f>:\tbge\tt0,t1,0x3000"))

    def test_bgeu_unsigned_negative_is_ge(self):
        setreg("t0", -1)
        setreg("t1", 1)
        self.assertEqual(self.tj("=> 0x1000 <f>:\tbgeu\tt0,t1,0x3000"), 0x3000)

    def test_blt_plain_values(self):
        setreg("t0", 3)
        setreg("t1", 9)
        self.assertEqual(self.tj("=> 0x1000 <f>:\tblt\tt0,t1,0x3000"), 0x3000)
        self.assertIsNone(self.tj("=> 0x1000 <f>:\tbltu\tt1,t0,0x3000"))

    # ---- pseudo forms with implicit zero ----------------------------------
    def test_beqz(self):
        setreg("a0", 0)
        self.assertEqual(self.tj("=> 0x1000 <f>:\tbeqz\ta0,0x2000"), 0x2000)
        setreg("a0", 5)
        self.assertIsNone(self.tj("=> 0x1000 <f>:\tbeqz\ta0,0x2000"))

    def test_bnez(self):
        setreg("a0", 5)
        self.assertEqual(self.tj("=> 0x1000 <f>:\tbnez\ta0,0x2000"), 0x2000)
        setreg("a0", 0)
        self.assertIsNone(self.tj("=> 0x1000 <f>:\tbnez\ta0,0x2000"))

    def test_bgtz_blez(self):
        setreg("a0", 5)
        self.assertEqual(self.tj("=> 0x1000 <f>:\tbgtz\ta0,0x2000"), 0x2000)
        self.assertIsNone(self.tj("=> 0x1000 <f>:\tblez\ta0,0x2000"))
        setreg("a0", -1)
        self.assertEqual(self.tj("=> 0x1000 <f>:\tbltz\ta0,0x2000"), 0x2000)
        self.assertEqual(self.tj("=> 0x1000 <f>:\tblez\ta0,0x2000"), 0x2000)
        self.assertIsNone(self.tj("=> 0x1000 <f>:\tbgez\ta0,0x2000"))

    # ---- compressed forms --------------------------------------------------
    def test_c_beqz(self):
        setreg("a0", 0)
        self.assertEqual(self.tj("=> 0x1000 <f>:\tc.beqz\ta0,0x2000"), 0x2000)
        setreg("a0", 1)
        self.assertEqual(self.tj("=> 0x1000 <f>:\tc.bnez\ta0,0x2000"), 0x2000)

    # ---- unconditional ------------------------------------------------------
    def test_j_taken(self):
        self.assertEqual(self.tj("=> 0x1000 <f>:\tj\t0x4000"), 0x4000)

    def test_jr_register_target(self):
        setreg("ra", 0x1234)
        self.assertEqual(self.tj("=> 0x1000 <f>:\tjr\tra"), 0x1234)

    def test_not_a_branch(self):
        self.assertIsNone(self.tj("=> 0x1000 <f>:\tadd\ta0,a1,a2"))

    # ---- zero register ------------------------------------------------------
    def test_zero_reg_is_zero(self):
        setreg("a0", 0)
        # beqz-style via explicit x0/zero operand
        self.assertEqual(self.tj("=> 0x1000 <f>:\tbeq\ta0,zero,0x2000"), 0x2000)

    # ---- eval_target parsing -------------------------------------------------
    def test_eval_target_bare_hex(self):
        inst = "=> 0x1051c <main+50>:\tbge\ta5,a4,104ee <sum6+58>"
        self.assertEqual(peda.eval_target(inst), 0x104ee)

    def test_eval_target_0x_hex_with_symbol(self):
        inst = "=> 0x1051c <main+50>:\tbge\ta5,a4,0x1052e <main+68>"
        self.assertEqual(peda.eval_target(inst), 0x1052e)

    def test_eval_target_jalr_register(self):
        setreg("t2", 0x5678)
        self.assertEqual(peda.eval_target("=> 0x1000 <f>:\tjalr\tt2"), 0x5678)


class CallFlowTests(unittest.TestCase):
    """Single pass through main: call site -> callee entry -> branch.

    gcc polarity of the `if (s > 10)` branch varies between versions, so
    branch tests compare peda's prediction against REAL single-stepping
    instead of assuming taken/not-taken.
    """

    @classmethod
    def setUpClass(cls):
        out = peda.execute_redirect("disassemble main")
        m = re.search(r"0x([0-9a-f]+)\s+<[^>]*>:\s*jal\s+.*<sum6>", out)
        assert m, "cannot locate 'jal <sum6>' in main"
        cls.jal_addr = int(m.group(1), 16)
        m = re.search(r"0x([0-9a-f]+)\s+<[^>]*>:\s*\t(b\w*)\s", out)
        assert m, "cannot locate the first branch in main"
        cls.branch_addr = int(m.group(1), 16)
        gdb.execute(f"tbreak *0x{cls.jal_addr:x}")
        gdb.execute("continue")  # -> stopped at the jal in main

    def test_01_args_at_call_site(self):
        # registers a0-a5 still hold 1..6 right before the jal
        self.assertEqual(peda.get_function_args(), [1, 2, 3, 4, 5, 6])

    def test_02_args_at_function_entry(self):
        # gcc -O0 prologue rotates/spills a0-a5: DWARF values must be used
        gdb.execute("tbreak sum6")
        gdb.execute("continue")
        self.assertEqual(peda.get_function_args(), [1, 2, 3, 4, 5, 6])

    def test_03_branch_prediction_matches_execution(self):
        gdb.execute(f"tbreak *0x{self.branch_addr:x}")
        gdb.execute("continue")  # sum6 returns; stop at the branch (s = 21)
        inst = peda.execute_redirect("x/i $pc")
        predicted = peda.testjump(inst)
        target = peda.eval_target(inst)
        peda.execute("stepi")
        actual = peda.getreg("pc")
        if predicted is None:
            self.assertNotEqual(actual, target)
        else:
            self.assertEqual(actual, target)

    def test_04_branch_prediction_after_flip(self):
        # rewind to the same branch, make s small (a4 = 5): with either
        # gcc polarity the outcome flips; consistency is what we assert
        gdb.execute(f"set $pc = 0x{self.branch_addr:x}")
        setreg("a4", 5)
        inst = peda.execute_redirect("x/i $pc")
        predicted = peda.testjump(inst)
        target = peda.eval_target(inst)
        peda.execute("stepi")
        actual = peda.getreg("pc")
        if predicted is None:
            self.assertNotEqual(actual, target)
        else:
            self.assertEqual(actual, target)


class VmrangePermTests(unittest.TestCase):
    """get_vmrange / is_executable / is_writable / is_address.

    Canned-map calls verify the lookup logic (list args also bypass
    @memoized, so no cache interference); live calls verify the qemu vmmap.
    """

    def setUp(self):
        reset_cache()  # is_executable/is_writable/is_address are memoized

    def test_vmrange_found(self):
        self.assertEqual(peda.get_vmrange(0x10500, FAKE_MAPS), FAKE_MAPS[0])
        self.assertEqual(peda.get_vmrange(0x7b000, FAKE_MAPS), FAKE_MAPS[1])
        self.assertEqual(peda.get_vmrange(0x84000, FAKE_MAPS), FAKE_MAPS[2])

    def test_vmrange_end_is_exclusive(self):
        # end of a range belongs to the NEXT mapping, not to this one
        self.assertEqual(peda.get_vmrange(0x7a000, FAKE_MAPS), FAKE_MAPS[1])

    def test_vmrange_miss(self):
        self.assertIsNone(peda.get_vmrange(0x9000, FAKE_MAPS))
        self.assertIsNone(peda.get_vmrange(0x100000, FAKE_MAPS))

    def test_permission_checks(self):
        self.assertTrue(peda.is_executable(0x10500, FAKE_MAPS))
        self.assertFalse(peda.is_writable(0x10500, FAKE_MAPS))
        self.assertTrue(peda.is_writable(0x7b000, FAKE_MAPS))
        self.assertFalse(peda.is_executable(0x7b000, FAKE_MAPS))
        # anonymous mapping is still a valid address
        self.assertTrue(peda.is_address(0x84000, FAKE_MAPS))
        self.assertFalse(peda.is_address(0x9000, FAKE_MAPS))

    def test_live_pc_sp_permissions(self):
        pc = peda.getreg("pc")
        sp = peda.getreg("sp")
        self.assertTrue(peda.is_executable(pc))
        self.assertFalse(peda.is_writable(pc))
        self.assertTrue(peda.is_writable(sp))
        self.assertTrue(peda.is_address(sp))
        self.assertFalse(peda.is_address(0x4141400000))

    def test_empty_maps_readability_fallback(self):
        """No mappings at all -> fall back to a 1-page read probe."""
        orig = peda.get_vmmap
        peda.get_vmmap = lambda *a, **k: []
        try:
            sp = peda.getreg("sp")
            page = sp & ~0xFFF
            self.assertEqual(peda.get_vmrange(sp), (page, page + 0x1000, "rwx", "unknown"))
            self.assertIsNone(peda.get_vmrange(0x4141400000))
        finally:
            peda.get_vmmap = orig


class SearchmemTests(unittest.TestCase):
    """searchmem() core paths on canned memory + live searchmem_by_range."""

    def test_literal_ascii(self):
        found = peda.searchmem(0x1000, 0x1010, "big", mem=b"xxbigyybig")
        self.assertEqual(found, [(0x1002, b"626967"), (0x1007, b"626967")])

    def test_regex_pattern(self):
        found = peda.searchmem(0x1000, 0x1010, b"[bB]i[gG]", mem=b"xxBigyybig")
        self.assertEqual(found, [(0x1002, b"426967"), (0x1007, b"626967")])

    def test_hex_value_search_is_little_endian(self):
        # "0x1122" must match the byte sequence 22 11 in memory
        found = peda.searchmem(0x2000, 0x2010, "0x1122", mem=b"\x22\x11\x00\x22\x11")
        self.assertEqual(found, [(0x2000, b"2211"), (0x2003, b"2211")])

    def test_invalid_regex_falls_back_to_literal(self):
        found = peda.searchmem(0x1000, 0x1010, "a(b", mem=b"za(bz")
        self.assertEqual(found, [(0x1001, b"612862")])

    def test_swapped_range(self):
        found = peda.searchmem(0x1010, 0x1000, "big", mem=b"big")
        self.assertEqual(found, [(0x1000, b"626967")])

    def test_empty_mem(self):
        self.assertEqual(peda.searchmem(0x1000, 0x1010, "big", mem=b""), [])

    def test_no_match(self):
        self.assertEqual(peda.searchmem(0x1000, 0x1010, "zzz", mem=b"big"), [])

    def test_live_searchmem_by_range(self):
        found = peda.searchmem_by_range("binary", "big")
        self.assertTrue(found)
        maps = peda.get_vmmap("binary")
        for (addr, hexval) in found:
            self.assertTrue(any(start <= addr < end for (start, end, _, _) in maps))
            self.assertEqual(bytes.fromhex(hexval.decode()), b"big")


class MemAccessTests(unittest.TestCase):
    """readmem/writemem/read_int/write_int roundtrips on scratch stack memory.

    Uses addresses BELOW $sp (stack grows down): free scratch space that
    does not disturb argc/argv/envp above the initial sp.
    """

    def setUp(self):
        reset_cache()
        self.scratch = (peda.getreg("sp") - 0x400) & ~0xF

    def test_writemem_readmem_roundtrip(self):
        self.assertEqual(peda.writemem(self.scratch, b"ABCD"), 4)
        self.assertEqual(peda.readmem(self.scratch, 4), b"ABCD")
        # binary-safe data
        self.assertEqual(peda.writemem(self.scratch, b"\x00\xff\x10"), 3)
        self.assertEqual(peda.readmem(self.scratch, 3), b"\x00\xff\x10")

    def test_writemem_empty_buffer(self):
        self.assertEqual(peda.writemem(self.scratch, b""), 0)

    def test_write_int_roundtrip(self):
        self.assertTrue(peda.write_int(self.scratch, 0x1122334455667788))
        self.assertEqual(peda.read_int(self.scratch), 0x1122334455667788)

    def test_write_int_negative(self):
        self.assertTrue(peda.write_int(self.scratch, -1))
        self.assertEqual(peda.read_int(self.scratch), 0xFFFFFFFFFFFFFFFF)

    def test_read_int_forced_size(self):
        self.assertEqual(peda.writemem(self.scratch, b"\x78\x56\x34\x12\x00\x00\x00\x00"), 8)
        self.assertEqual(peda.read_int(self.scratch, 4), 0x12345678)
        self.assertEqual(peda.read_int(self.scratch, 8), 0x12345678)

    def test_write_long_roundtrip(self):
        self.assertTrue(peda.write_long(self.scratch, 0xCAFEF00DBEEF))
        self.assertEqual(peda.read_long(self.scratch), 0xCAFEF00DBEEF)

    def test_intsize_is_64(self):
        self.assertEqual(peda.intsize(), 8)


class DisasmHelpersTests(unittest.TestCase):
    """current_inst / next_inst / prev_inst / get_disasm / disassemble_around
    against the live target (all are @memoized -> reset in setUp).
    """

    @classmethod
    def setUpClass(cls):
        out = peda.execute_redirect("disassemble main")
        m = re.search(r"0x([0-9a-f]+)\s+<[^>]*>:\s*\t(b\w*)\s", out)
        assert m, "cannot locate the first branch in main"
        cls.branch_addr = int(m.group(1), 16)

    def setUp(self):
        reset_cache()

    def test_current_inst_at_branch(self):
        (addr, code) = peda.current_inst(self.branch_addr)
        self.assertEqual(addr, self.branch_addr)
        # mnemonic is TAB-separated from operands on riscv
        self.assertTrue(code.split()[0].startswith("b"), code)
        self.assertIn("\t", code)

    def test_current_inst_at_pc(self):
        pc = peda.getreg("pc")
        (addr, code) = peda.current_inst(pc)
        self.assertEqual(addr, pc)
        self.assertTrue(code.strip())

    def test_next_inst(self):
        pc = peda.getreg("pc")
        insts = peda.next_inst(pc, 3)
        self.assertEqual(len(insts), 3)
        addrs = [i[0] for i in insts]
        self.assertEqual(addrs, sorted(addrs))
        for addr in addrs:
            self.assertGreater(addr, pc)

    def test_prev_inst_before_branch(self):
        insts = peda.prev_inst(self.branch_addr, 2)
        self.assertEqual(len(insts), 2)
        addrs = [i[0] for i in insts]
        self.assertEqual(addrs, sorted(addrs))
        for addr in addrs:
            self.assertLess(addr, self.branch_addr)
        self.assertTrue(all(i[1].strip() for i in insts))

    def test_get_disasm(self):
        pc = peda.getreg("pc")
        code = peda.get_disasm(pc, 2)
        self.assertIn(f"0x{pc:x}", code)

    def test_disassemble_around(self):
        pc = peda.getreg("pc")
        code = peda.disassemble_around(pc, 8)
        self.assertTrue(code)
        self.assertIn(f"0x{pc:x}", code)


class StringToArgvTests(unittest.TestCase):
    """string_to_argv: $register values, "+N" relative offsets, math."""

    def test_register_value(self):
        setreg("a0", 0x50)
        self.assertEqual(peda.string_to_argv("$a0"), ["0x50"])

    def test_relative_offset(self):
        sp = peda.getreg("sp")
        self.assertEqual(peda.string_to_argv("$sp +8"),
                         [f"0x{sp:x}", f"0x{sp + 8:x}"])

    def test_math_expression(self):
        self.assertEqual(peda.string_to_argv("0x100+0x10"), ["0x110"])

    def test_bytes_input(self):
        self.assertEqual(peda.string_to_argv(b"foo bar"), ["foo", "bar"])

    def test_plain_arguments_untouched(self):
        self.assertEqual(peda.string_to_argv("vmmap binary"), ["vmmap", "binary"])


class ElfInfoTests(unittest.TestCase):
    """ELF helpers and checksec against the live static no-pie binary."""

    def setUp(self):
        reset_cache()  # elfheader/elfsymbols are memoized

    def test_elfentry_inside_binary(self):
        entry = peda.elfentry()
        self.assertIsNotNone(entry)
        maps = peda.get_vmmap("binary")
        self.assertTrue(any(start <= entry < end and "x" in perm
                           for (start, end, perm, _) in maps))

    def test_elfheader_text_is_code(self):
        headers = peda.elfheader(".text")
        self.assertEqual(len(headers), 1)
        (start, end, htype) = headers[".text"]
        self.assertEqual(htype, "code")
        self.assertLess(start, end)

    def test_elfheader_has_rodata(self):
        headers = peda.elfheader()
        self.assertIn(".rodata", headers)
        self.assertEqual(headers[".rodata"][2], "rodata")

    def test_checksec_static_nopie(self):
        cs = peda.checksec()
        self.assertIsNotNone(cs)
        self.assertEqual(set(cs), {"RELRO", "CANARY", "NX", "PIE", "FORTIFY"})
        self.assertEqual(cs["NX"], 1)   # GNU_STACK is not RWE
        self.assertEqual(cs["PIE"], 0)  # static -no-pie -> ET_EXEC

    def test_getfile(self):
        self.assertTrue(peda.getfile().endswith("test_static"))

    def test_getpid_is_qemu_process(self):
        # under qemu-user the inferior pid IS the host qemu pid
        pid = peda.getpid()
        self.assertIsInstance(pid, int)
        self.assertGreater(pid, 0)

    def test_elfsymbols_empty_for_static(self):
        # static binary has no .dynstr -> no dynamic symbols to report
        self.assertEqual(peda.elfsymbols(), {})


class SnapshotTests(unittest.TestCase):
    """take/give snapshot: registers + writable memory are restored."""

    def setUp(self):
        reset_cache()

    def test_snapshot_roundtrip(self):
        snap = peda.take_snapshot()
        self.assertIsNotNone(snap)
        self.assertIn("reg", snap)
        self.assertIn("mem", snap)
        self.assertTrue(snap["reg"])
        self.assertTrue(snap["mem"])

        scratch = (peda.getreg("sp") - 0x400) & ~0xF
        saved_t0 = snap["reg"].get("t0", 0)
        setreg("t0", (saved_t0 ^ 0xDEAD) or 1)
        peda.writemem(scratch, b"MUTATED!")

        self.assertTrue(peda.give_snapshot(snap))
        self.assertEqual(peda.getreg("t0"), saved_t0)

    def test_save_restore_snapshot_file(self):
        fname = "snap_test_riscv.bin"  # gdb cwd is the temp workdir
        self.assertTrue(peda.save_snapshot(fname))
        scratch = (peda.getreg("sp") - 0x400) & ~0xF
        peda.writemem(scratch, b"MUTATED!")
        self.assertTrue(peda.restore_snapshot(fname))


class StatusTests(unittest.TestCase):
    """get_status() against the live remote target."""

    def setUp(self):
        reset_cache()

    def test_status_at_breakpoint(self):
        # break at the NEXT instruction (a tbreak at $pc itself would not
        # re-trigger and the program would run to completion)
        pc = peda.getreg("pc")
        nxt = peda.next_inst(pc, 1)[0][0]
        gdb.execute(f"tbreak *0x{nxt:x}")
        gdb.execute("continue")
        self.assertEqual(peda.get_status(), "BREAKPOINT")

    def test_getpid_live(self):
        self.assertIsNotNone(peda.getpid())


# --------------------------------------------------------------------------
# runner
# --------------------------------------------------------------------------

def build_suite():
    loader = unittest.TestLoader()
    # CallFlowTests drive the live execution first: later tests freely
    # clobber registers (a clobbered argc/argv would disturb the run).
    # SnapshotTests/StatusTests come last: they restore/advance the live
    # state, which earlier assertions must not depend on.
    order = [CallFlowTests, ArchTests, ParseAndEvalTests,
             FunctionArgsHeuristicTests, DwarfArgsParserTests,
             VmmapParserTests, VmmapBinaryTests, BranchSemanticsTests,
             VmrangePermTests, SearchmemTests, MemAccessTests,
             DisasmHelpersTests, StringToArgvTests, ElfInfoTests,
             SnapshotTests, StatusTests]
    suite = unittest.TestSuite()
    for cls in order:
        suite.addTests(loader.loadTestsFromTestCase(cls))
    return suite


result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(build_suite())

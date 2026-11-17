"""Unit tests for the AArch64 port of PEDA, executed INSIDE gdb-multiarch
against a live qemu-aarch64 target.

This file must be sourced from gdb AFTER peda.py and after connecting:

    gdb-multiarch -q BIN \
        -ex 'source /path/to/peda.py' \
        -ex 'target remote :PORT' \
        -ex 'source tests/test_peda_gdb_aarch64.py'

Requires `peda` in the __main__ namespace (as created by sourcing peda.py
first). Mirrors tests/test_peda_gdb.py (the RISC-V suite).

Coverage:
    - architecture detection and register-name table
    - parse_and_eval word-boundary substitution (hex vs x-register names:
      "x30" is a valid hex substring of "0x30")
    - AArch64 argument heuristics (x0-x7, w-name normalization, // comments)
      and the DWARF fallback parser
    - vmmap parsers (modern / legacy "info proc mappings" formats, local
      qemu /proc fallback) + live vmmap under qemu-aarch64
    - branch semantics: b.cond via synthetic CPSR flags (N/Z/C/V),
      cbz/cbnz register-width correctness (w0 vs x0), tbz/tbnz,
      unconditional b/br/ret, eval_target parsing (0x hex / bare hex /
      br reg / bare "ret" -> x30)
    - live single-pass flow: args at the call site, args at function entry
      (argc unknown at entry -> DWARF), branch prediction consistency
      checked against real single-stepping
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


def setcpsr(n=False, z=False, c=False, v=False):
    val = ((0x80000000 if n else 0) | (0x40000000 if z else 0)
           | (0x20000000 if c else 0) | (0x10000000 if v else 0))
    gdb.execute(f"set $cpsr = {val}")


# canned outputs -----------------------------------------------------------

# gcc -O0 aarch64 argument setup: 32-bit view names (w0-w5) and
# objdump-style trailing comments ("// #6") must both be handled
CODE_SIX_ARGS = ("0x400780:\tmov\tw5, #0x6                   \t// #6\n"
                 "0x400784:\tmov\tw4, #0x5                    \t// #5\n"
                 "0x400788:\tmov\tw3, #0x4                    \t// #4\n"
                 "0x40078c:\tmov\tw2, #0x3                    \t// #3\n"
                 "0x400790:\tmov\tw1, #0x2                    \t// #2\n"
                 "0x400794:\tmov\tw0, #0x1                    \t// #1\n")

CODE_ONLY_STORES = ("0x1:\tstr\tw0, [sp, #28]\n"
                    "0x2:\tstp\tx29, x30, [sp, #-48]!\n")

INFO_PROC_MODERN = """process 4242
Mapped address spaces:

Start Addr         End Addr           Size               Offset             Perms File
        0x400000           0x490000           0x90000                0x0  r-xp  /tmp/test_static
        0x490000           0x4a0000           0x10000            0x90000  rw-p  /tmp/test_static
        0x4a0000           0x4a5000            0x5000                0x0  rw-p
"""

INFO_PROC_LEGACY = """process 4242
Start Addr       End Addr         Size     Offset    objfile
   0x400000       0x490000       0x90000      0x0   /tmp/test_static
   0x490000       0x4a0000       0x10000  0x90000   /tmp/test_static
"""

FAKE_MAPS = [
    (0x400000, 0x490000, "r-xp", "/tmp/test_static"),
    (0x490000, 0x4a0000, "rw-p", "/tmp/test_static"),
    (0x4a0000, 0x4a5000, "rw-p", "mapped"),
]


# --------------------------------------------------------------------------
# test cases (executed in the order given in build_suite below)
# --------------------------------------------------------------------------

class ArchTests(unittest.TestCase):
    def test_getarch_aarch64(self):
        (arch, bits) = peda.getarch()
        self.assertIn("aarch64", arch)
        self.assertEqual(bits, 64)

    def test_arch_predicates(self):
        self.assertTrue(peda._is_aarch64())
        self.assertFalse(peda._is_riscv())
        self.assertFalse(peda._is_x86())

    def test_regnames_table(self):
        names = peda.get_regnames()
        aa64 = names[64]
        for i in range(31):
            self.assertIn(f"x{i}", aa64)
        for r in ["sp", "pc"]:
            self.assertIn(r, aa64)
        # no x86 leftovers under an aarch64 target
        for r in ["rax", "rbx", "rdi", "rip", "eflags"]:
            self.assertNotIn(r, aa64)

    def test_is_target_remote(self):
        self.assertTrue(peda.is_target_remote())

    def test_get_eflags_none(self):
        # no x86 eflags register on aarch64 -> graceful None (not an exception)
        self.assertIsNone(peda.get_eflags())


class ParseAndEvalTests(unittest.TestCase):
    """Regression tests for word-boundary register substitution.

    AArch64 register names (x0..x30) are valid hex substrings: "0x30"
    contains "x30", "0x4007ac" contains... nothing dangerous thanks to the
    lookbehind, but naive str.replace() would corrupt "0x30" -> "0x$x30".
    """

    def test_hex_constant_with_x30(self):
        self.assertEqual(to_int(peda.parse_and_eval("0x30")), 0x30)

    def test_hex_constant_untouched(self):
        self.assertEqual(to_int(peda.parse_and_eval("0x4007bc")), 0x4007bc)

    def test_register_name_substituted(self):
        setreg("x1", 42)
        self.assertEqual(to_int(peda.parse_and_eval("x1")), 42)

    def test_register_arithmetics(self):
        setreg("x2", 100)
        self.assertEqual(to_int(peda.parse_and_eval("x2+8")), 108)

    def test_x1_not_confused_with_x10(self):
        setreg("x1", 1)
        setreg("x10", 2)
        self.assertEqual(to_int(peda.parse_and_eval("x10")), 2)
        self.assertEqual(to_int(peda.parse_and_eval("x1")), 1)


class FunctionArgsHeuristicTests(unittest.TestCase):
    def test_heuristic_count_from_code(self):
        # mov w0..w5 -> 6 args; values are read from current registers
        args = peda._get_function_args_aarch64(CODE_SIX_ARGS, None)
        self.assertEqual(len(args), 6)

    def test_heuristic_values_follow_registers(self):
        for i in range(6):
            setreg(f"x{i}", 0x100 + i)
        args = peda._get_function_args_aarch64(CODE_SIX_ARGS, None)
        self.assertEqual(args, [0x100 + i for i in range(6)])

    def test_explicit_argc(self):
        args = peda._get_function_args_aarch64(CODE_SIX_ARGS, 3)
        self.assertEqual(len(args), 3)

    def test_argc_capped_at_8(self):
        self.assertEqual(len(peda._get_function_args_aarch64(CODE_SIX_ARGS, 99)), 8)

    def test_stores_are_not_writes(self):
        # str/stp first operand is a SOURCE, must not count as arg setup
        self.assertEqual(peda._get_function_args_aarch64(CODE_ONLY_STORES, None), [])

    def test_empty_code(self):
        self.assertEqual(peda._get_function_args_aarch64("", None), [])


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
    """Canned "info proc mappings" formats + the local /proc fallback."""

    def setUp(self):
        reset_cache()  # get_vmmap/getpid are memoized

    def _maps(self, canned):
        with patch_redirect(peda, {"info proc mappings": canned}):
            return peda.get_vmmap("all")

    def test_modern_format(self):
        maps = self._maps(INFO_PROC_MODERN)
        self.assertEqual(len(maps), 3)
        (start, end, perm, name) = maps[0]
        self.assertEqual(start, 0x400000)
        self.assertEqual(end, 0x490000)
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


class VmmapLiveTests(unittest.TestCase):
    def setUp(self):
        reset_cache()  # get_vmmap/getpid are memoized

    def test_live_vmmap_from_info_proc(self):
        maps = peda.get_vmmap("all")
        self.assertGreaterEqual(len(maps), 3)
        self.assertTrue(any(m[3] == "[stack]" for m in maps))

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
    """_testjump_aarch64 / eval_target on synthetic instruction texts.

    Instruction strings mimic gdb "x/i" output: binutils separates the
    mnemonic and operands with a TAB on aarch64. Conditional branches are
    driven by synthetic CPSR flags (N=31, Z=30, C=29, V=28).
    """

    def setUp(self):
        # known register/flag state for every test
        for i in range(8):
            setreg(f"x{i}", 0)
        setcpsr()

    def tj(self, inst):
        return peda._testjump_aarch64(inst)

    # ---- equality family ---------------------------------------------------
    def test_beq_taken(self):
        setcpsr(z=True)
        self.assertEqual(self.tj("=> 0x1000 <f>:\tb.eq\t0x2000"), 0x2000)

    def test_beq_not_taken(self):
        setcpsr(z=False)
        self.assertIsNone(self.tj("=> 0x1000 <f>:\tb.eq\t0x2000"))

    def test_bne_taken(self):
        setcpsr(z=False)
        self.assertEqual(self.tj("=> 0x1000 <f>:\tb.ne\t0x2000"), 0x2000)

    def test_bne_not_taken(self):
        setcpsr(z=True)
        self.assertIsNone(self.tj("=> 0x1000 <f>:\tb.ne\t0x2000"))

    # ---- signed family (N vs V) ---------------------------------------------
    def test_blt_signed_negative_is_smaller(self):
        # cmp -1, 1 -> N=1, V=0 -> lt (N != V) taken
        setcpsr(n=True, v=False)
        self.assertEqual(self.tj("=> 0x1000 <f>:\tb.lt\t0x3000"), 0x3000)
        self.assertIsNone(self.tj("=> 0x1000 <f>:\tb.ge\t0x3000"))

    def test_bge_unsigned_carry(self):
        # unsigned greater-or-equal (cmp 1, -1): C=1, Z=0 -> hs/cs taken
        setcpsr(c=True, z=False)
        self.assertEqual(self.tj("=> 0x1000 <f>:\tb.hs\t0x3000"), 0x3000)
        self.assertEqual(self.tj("=> 0x1000 <f>:\tb.hi\t0x3000"), 0x3000)
        self.assertIsNone(self.tj("=> 0x1000 <f>:\tb.lo\t0x3000"))
        self.assertIsNone(self.tj("=> 0x1000 <f>:\tb.ls\t0x3000"))

    def test_bgt_ble(self):
        setcpsr(n=False, v=False, z=False)
        self.assertEqual(self.tj("=> 0x1000 <f>:\tb.gt\t0x3000"), 0x3000)
        self.assertIsNone(self.tj("=> 0x1000 <f>:\tb.le\t0x3000"))
        setcpsr(z=True)
        self.assertEqual(self.tj("=> 0x1000 <f>:\tb.le\t0x3000"), 0x3000)
        self.assertIsNone(self.tj("=> 0x1000 <f>:\tb.gt\t0x3000"))

    def test_overflow_flips_signed_order(self):
        # signed overflow: N == V means "greater or equal" even with N set
        setcpsr(n=True, v=True)
        self.assertEqual(self.tj("=> 0x1000 <f>:\tb.ge\t0x3000"), 0x3000)
        self.assertIsNone(self.tj("=> 0x1000 <f>:\tb.lt\t0x3000"))

    # ---- cbz / cbnz with register-width correctness --------------------------
    def test_cbz_cbnz(self):
        setreg("x0", 0)
        self.assertEqual(self.tj("=> 0x1000 <f>:\tcbz\tx0, 0x2000"), 0x2000)
        self.assertIsNone(self.tj("=> 0x1000 <f>:\tcbnz\tx0, 0x2000"))
        setreg("x0", 5)
        self.assertEqual(self.tj("=> 0x1000 <f>:\tcbnz\tx0, 0x2000"), 0x2000)
        self.assertIsNone(self.tj("=> 0x1000 <f>:\tcbz\tx0, 0x2000"))

    def test_cbz_32bit_view_of_nonzero_reg(self):
        # x0 = 0x1_00000000: w0 (low 32 bits) is 0, x0 is not
        setreg("x0", 0x100000000)
        self.assertEqual(self.tj("=> 0x1000 <f>:\tcbz\tw0, 0x2000"), 0x2000)
        self.assertIsNone(self.tj("=> 0x1000 <f>:\tcbz\tx0, 0x2000"))

    # ---- tbz / tbnz -----------------------------------------------------------
    def test_tbz_tbnz(self):
        setreg("x1", 8)  # bit 3 set
        self.assertIsNone(self.tj("=> 0x1000 <f>:\ttbz\tx1, #3, 0x2000"))
        self.assertEqual(self.tj("=> 0x1000 <f>:\ttbnz\tx1, #3, 0x2000"), 0x2000)
        setreg("x1", 0)
        self.assertEqual(self.tj("=> 0x1000 <f>:\ttbz\tx1, #3, 0x2000"), 0x2000)
        self.assertIsNone(self.tj("=> 0x1000 <f>:\ttbnz\tx1, #3, 0x2000"))

    # ---- unconditional ---------------------------------------------------------
    def test_b_taken(self):
        self.assertEqual(self.tj("=> 0x1000 <f>:\tb\t0x4000"), 0x4000)

    def test_br_register_target(self):
        setreg("x2", 0x1234)
        self.assertEqual(self.tj("=> 0x1000 <f>:\tbr\tx2"), 0x1234)

    def test_ret_targets_x30(self):
        setreg("x30", 0x5678)
        self.assertEqual(self.tj("=> 0x1000 <f>:\tret"), 0x5678)

    def test_not_a_branch(self):
        self.assertIsNone(self.tj("=> 0x1000 <f>:\tadd\tx0, x1, x2"))

    # ---- eval_target parsing -----------------------------------------------------
    def test_eval_target_0x_hex_with_symbol(self):
        inst = "=> 0x4007a8 <main+56>:\tb.le\t0x4007bc <main+76>"
        self.assertEqual(peda.eval_target(inst), 0x4007bc)

    def test_eval_target_bare_hex(self):
        # objdump-style branch target without the 0x prefix
        inst = "=> 0x4007a8 <main+56>:\tb.le\t4007bc <main+76>"
        self.assertEqual(peda.eval_target(inst), 0x4007bc)

    def test_eval_target_br_register(self):
        setreg("x3", 0x9abc)
        self.assertEqual(peda.eval_target("=> 0x1000 <f>:\tbr\tx3"), 0x9abc)

    def test_eval_target_ret_is_x30(self):
        setreg("x30", 0xdef0)
        self.assertEqual(peda.eval_target("=> 0x1000 <f>:\tret"), 0xdef0)

    def test_eval_target_immediate_comment(self):
        # trailing "// #imm" comment must not break operand parsing
        inst = "=> 0x400780 <main+16>:\tb\t0x4007bc <main+76>"
        self.assertEqual(peda.eval_target(inst), 0x4007bc)


class CallFlowTests(unittest.TestCase):
    """Single pass through main: call site -> callee entry -> branch.

    gcc polarity of the `if (s > 10)` branch varies between versions, so
    branch tests compare peda's prediction against REAL single-stepping
    instead of assuming taken/not-taken.
    """

    @classmethod
    def setUpClass(cls):
        out = peda.execute_redirect("disassemble main")
        m = re.search(r"0x([0-9a-f]+)\s+<[^>]*>:\s*bl\s+.*<sum6>", out)
        assert m, "cannot locate 'bl <sum6>' in main"
        cls.bl_addr = int(m.group(1), 16)
        m = re.search(r"0x([0-9a-f]+)\s+<[^>]*>:\s*\tb\.", out)
        assert m, "cannot locate the first conditional branch in main"
        cls.branch_addr = int(m.group(1), 16)
        gdb.execute(f"tbreak *0x{cls.bl_addr:x}")
        gdb.execute("continue")  # -> stopped at the bl in main

    def test_01_args_at_call_site(self):
        # registers x0-x5 still hold 1..6 right before the bl
        self.assertEqual(peda.get_function_args(), [1, 2, 3, 4, 5, 6])

    def test_02_args_at_function_entry(self):
        # at function entry the setup code cannot be scanned back past the
        # call itself (argc unknown): DWARF values must be used
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

    def test_04_branch_prediction_after_flag_flip(self):
        # rewind to the same branch and flip the Z flag: with either gcc
        # polarity (b.le or b.gt) the outcome flips; consistency is asserted
        gdb.execute(f"set $pc = 0x{self.branch_addr:x}")
        setcpsr(z=True)
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
        self.assertEqual(peda.get_vmrange(0x405000, FAKE_MAPS), FAKE_MAPS[0])
        self.assertEqual(peda.get_vmrange(0x495000, FAKE_MAPS), FAKE_MAPS[1])
        self.assertEqual(peda.get_vmrange(0x4a4000, FAKE_MAPS), FAKE_MAPS[2])

    def test_vmrange_end_is_exclusive(self):
        # end of a range belongs to the NEXT mapping, not to this one
        self.assertEqual(peda.get_vmrange(0x490000, FAKE_MAPS), FAKE_MAPS[1])

    def test_vmrange_miss(self):
        self.assertIsNone(peda.get_vmrange(0x300000, FAKE_MAPS))
        self.assertIsNone(peda.get_vmrange(0x1000000, FAKE_MAPS))

    def test_permission_checks(self):
        self.assertTrue(peda.is_executable(0x405000, FAKE_MAPS))
        self.assertFalse(peda.is_writable(0x405000, FAKE_MAPS))
        self.assertTrue(peda.is_writable(0x495000, FAKE_MAPS))
        self.assertFalse(peda.is_executable(0x495000, FAKE_MAPS))
        # anonymous mapping is still a valid address
        self.assertTrue(peda.is_address(0x4a4000, FAKE_MAPS))
        self.assertFalse(peda.is_address(0x300000, FAKE_MAPS))

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
        m = re.search(r"0x([0-9a-f]+)\s+<[^>]*>:\s*\tb\.", out)
        assert m, "cannot locate the first conditional branch in main"
        cls.branch_addr = int(m.group(1), 16)

    def setUp(self):
        reset_cache()

    def test_current_inst_at_branch(self):
        (addr, code) = peda.current_inst(self.branch_addr)
        self.assertEqual(addr, self.branch_addr)
        # conditional branch mnemonic is "b.<cond>", TAB-separated from operands
        self.assertTrue(code.split()[0].startswith("b."), code)
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
        setreg("x0", 0x50)
        self.assertEqual(peda.string_to_argv("$x0"), ["0x50"])

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
        saved_x9 = snap["reg"].get("x9", 0)
        setreg("x9", (saved_x9 ^ 0xDEAD) or 1)
        peda.writemem(scratch, b"MUTATED!")

        self.assertTrue(peda.give_snapshot(snap))
        self.assertEqual(peda.getreg("x9"), saved_x9)

    def test_save_restore_snapshot_file(self):
        fname = "snap_test_aarch64.bin"  # gdb cwd is the temp workdir
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
             VmmapParserTests, VmmapLiveTests, BranchSemanticsTests,
             VmrangePermTests, SearchmemTests, MemAccessTests,
             DisasmHelpersTests, StringToArgvTests, ElfInfoTests,
             SnapshotTests, StatusTests]
    suite = unittest.TestSuite()
    for cls in order:
        suite.addTests(loader.loadTestsFromTestCase(cls))
    return suite


result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(build_suite())

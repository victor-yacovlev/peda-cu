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
"""

import contextlib
import re
import sys
import unittest

import gdb

from utils import to_int, reset_cache  # noqa: E402  (already on sys.path)


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
    gdb.execute("set $%s = %d" % (name, value))


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
        with patch_redirect(peda, {"info proc mappings": None}):
            with patch_execute(peda, {"remote get": False}):
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
        gdb.execute("tbreak *0x%x" % cls.jal_addr)
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
        gdb.execute("tbreak *0x%x" % self.branch_addr)
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
        gdb.execute("set $pc = 0x%x" % self.branch_addr)
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


# --------------------------------------------------------------------------
# runner
# --------------------------------------------------------------------------

def build_suite():
    loader = unittest.TestLoader()
    # CallFlowTests drive the live execution first: later tests freely
    # clobber registers (a clobbered argc/argv would disturb the run)
    order = [CallFlowTests, ArchTests, ParseAndEvalTests,
             FunctionArgsHeuristicTests, DwarfArgsParserTests,
             VmmapParserTests, VmmapBinaryTests, BranchSemanticsTests]
    suite = unittest.TestSuite()
    for cls in order:
        suite.addTests(loader.loadTestsFromTestCase(cls))
    return suite


result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(build_suite())

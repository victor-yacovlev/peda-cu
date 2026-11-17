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
    - vmmap live under qemu-aarch64
    - branch semantics: b.cond via synthetic CPSR flags (N/Z/C/V),
      cbz/cbnz register-width correctness (w0 vs x0), tbz/tbnz,
      unconditional b/br/ret, eval_target parsing (0x hex / bare hex /
      br reg / bare "ret" -> x30)
    - live single-pass flow: args at the call site, args at function entry
      (argc unknown at entry -> DWARF), branch prediction consistency
      checked against real single-stepping
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


def setreg(name, value):
    gdb.execute("set $%s = %d" % (name, value))


def setcpsr(n=False, z=False, c=False, v=False):
    val = (0x80000000 if n else 0) | (0x40000000 if z else 0) \
        | (0x20000000 if c else 0) | (0x10000000 if v else 0)
    gdb.execute("set $cpsr = %d" % val)


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
            self.assertIn("x%d" % i, aa64)
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
            setreg("x%d" % i, 0x100 + i)
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

    def test_non_integer_falls_back(self):
        with patch_redirect(peda, {"info args": 's = "text"\n'}):
            self.assertIsNone(peda._get_function_args_dwarf())


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
            setreg("x%d" % i, 0)
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
        gdb.execute("tbreak *0x%x" % cls.bl_addr)
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

    def test_04_branch_prediction_after_flag_flip(self):
        # rewind to the same branch and flip the Z flag: with either gcc
        # polarity (b.le or b.gt) the outcome flips; consistency is asserted
        gdb.execute("set $pc = 0x%x" % self.branch_addr)
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


# --------------------------------------------------------------------------
# runner
# --------------------------------------------------------------------------

def build_suite():
    loader = unittest.TestLoader()
    # CallFlowTests drive the live execution first: later tests freely
    # clobber registers (a clobbered argc/argv would disturb the run)
    order = [CallFlowTests, ArchTests, ParseAndEvalTests,
             FunctionArgsHeuristicTests, DwarfArgsParserTests,
             VmmapLiveTests, BranchSemanticsTests]
    suite = unittest.TestSuite()
    for cls in order:
        suite.addTests(loader.loadTestsFromTestCase(cls))
    return suite


result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(build_suite())

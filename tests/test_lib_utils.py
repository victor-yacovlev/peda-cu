#!/usr/bin/env python3
"""Standalone unit tests for lib/utils.py (no GDB required).

Run:  python3 tests/test_lib_utils.py
"""
import os
import sys
import unittest
from io import StringIO

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from utils import message, memoized, to_int, to_hex  # sys.path set above


class TestToInt(unittest.TestCase):
    def test_decimal(self):
        self.assertEqual(to_int("10"), 10)

    def test_hex_prefixed(self):
        self.assertEqual(to_int("0x10"), 16)

    def test_octal_and_binary(self):
        self.assertEqual(to_int("0o17"), 15)
        self.assertEqual(to_int("0b101"), 5)

    def test_bare_hex_is_rejected(self):
        # no 0x prefix -> not a number for to_int (callers add prefixes)
        self.assertIsNone(to_int("deadbeef"))

    def test_garbage(self):
        self.assertIsNone(to_int(""))

    def test_negative(self):
        self.assertEqual(to_int("-5"), -5)

    def test_int_passthrough(self):
        self.assertEqual(to_int(5), 5)


class TestToHex(unittest.TestCase):
    def test_positive(self):
        self.assertEqual(to_hex(255), "0xff")

    def test_negative(self):
        self.assertEqual(to_hex(-255), "-0xff")


class TestMemoized(unittest.TestCase):
    def test_caches_by_args(self):
        calls = []

        @memoized
        def f(x):
            calls.append(x)
            return x * 2

        self.assertEqual(f(2), 4)
        self.assertEqual(f(2), 4)
        self.assertEqual(calls, [2])  # second call served from cache

        self.assertEqual(f(3), 6)
        self.assertEqual(calls, [2, 3])

    def test_cache_reset(self):
        calls = []

        @memoized
        def f(x):
            calls.append(x)
            return x + 1

        self.assertEqual(f(1), 2)
        f._reset()
        self.assertEqual(f(1), 2)
        self.assertEqual(calls, [1, 1])


class TestMessageBufferize(unittest.TestCase):
    def _capture(self, func):
        captured = StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        m = message()
        try:
            func(m)
        finally:
            sys.stdout = old_stdout
        return captured.getvalue(), captured, m

    def test_normal_buffering(self):
        def run(m):
            @m.bufferize
            def ok():
                m("line1")
                m("line2")
            ok()
        out, captured, m = self._capture(run)
        self.assertIn("line1", out)
        self.assertIn("line2", out)
        self.assertEqual(m.buffering, 0)  # counter restored
        self.assertIs(m.out, captured)  # stream restored to current stdout

    def test_flush_on_exception(self):
        """Regression: an exception inside a buffered command must not leak
        the buffering counter - otherwise all subsequent peda output is
        swallowed (this is what masked every failure under RISC-V)."""
        def run(m):
            @m.bufferize
            def boom():
                m("captured-before-failure")
                raise RuntimeError("boom")
            self.assertRaises(RuntimeError, boom)
            # output written after the failure must go to real stdout again
            m("after-failure")
        out, captured, m = self._capture(run)
        self.assertIn("captured-before-failure", out)  # partial buffer flushed
        self.assertIn("after-failure", out)
        self.assertEqual(m.buffering, 0)
        self.assertIs(m.out, captured)

    def test_nested_bufferize_manual_api(self):
        def run(m):
            m.bufferize()
            m("hidden")
            m.flush()
            m("visible")
        out, captured, m = self._capture(run)
        self.assertIn("hidden", out)
        self.assertIn("visible", out)
        self.assertEqual(m.buffering, 0)
        self.assertIs(m.out, captured)

    def test_flush_without_bufferize_raises(self):
        m = message()
        self.assertRaises(ValueError, m.flush)


if __name__ == "__main__":
    unittest.main(verbosity=2)

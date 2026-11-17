#!/bin/sh
# Unit test runner for the RISC-V / AArch64 ports of PEDA.
#
# 1. standalone tests of lib/utils.py (plain python3, no gdb)
# 2. gdb-embedded tests (tests/test_peda_gdb.py) executed inside
#    gdb-multiarch against a live qemu-riscv64 target
# 3. gdb-embedded tests (tests/test_peda_gdb_aarch64.py) executed inside
#    gdb-multiarch against a live qemu-aarch64 target (skipped gracefully
#    when the aarch64 toolchain is not installed)
#
# Requirements: python3, riscv64-linux-gnu-gcc, qemu-riscv64, gdb-multiarch;
# optionally aarch64-linux-gnu-gcc + qemu-aarch64 for stage 3.
#
# Usage: tests/run_unit_tests.sh   (from anywhere)

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT="$SCRIPT_DIR/.."
PEDA="$ROOT/peda.py"
WORK=$(mktemp -d /tmp/peda-unit.XXXXXX)
PORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
QPID=""
cleanup() { [ -n "$QPID" ] && kill "$QPID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

fail=0

echo "== [1/3] standalone lib/utils.py tests =="
if python3 "$SCRIPT_DIR/test_lib_utils.py" > "$WORK/utils.out" 2>&1; then
    tail -1 "$WORK/utils.out"
else
    fail=1
    echo "FAILED (full log: $WORK/utils.out):"
    cat "$WORK/utils.out"
fi

echo "== [2/3] gdb-embedded tests (qemu-riscv64 target) =="

if ! riscv64-linux-gnu-gcc -static -no-pie -g -O0 "$SCRIPT_DIR/assets/test.c" -o "$WORK/test_static"; then
    echo "FAIL: cannot build test binary (riscv64-linux-gnu-gcc missing?)"
    exit 1
fi

qemu-riscv64 -g "$PORT" "$WORK/test_static" &
QPID=$!
sleep 0.5

cd "$WORK" || exit 1  # keep peda session autosave files out of the repo
gdb-multiarch -batch -q "$WORK/test_static" \
    -ex 'set pagination off' \
    -ex 'set confirm off' \
    -ex "source $PEDA" \
    -ex "target remote :$PORT" \
    -ex "source $SCRIPT_DIR/test_peda_gdb.py" > "$WORK/gdb.out" 2>&1
kill "$QPID" 2>/dev/null; QPID=""

# hook-stop prints peda context between test results; show only the
# unittest-relevant lines plus a failure context
grep -E '^test_|^(OK|FAILED|Ran )|^(FAIL|ERROR):|^Traceback|AssertionError' "$WORK/gdb.out" > "$WORK/summary.out"
cat "$WORK/summary.out"

if grep -q '^OK' "$WORK/gdb.out"; then
    echo "UNIT OK"
else
    fail=1
    echo "UNIT FAILED, failure details:"
    grep -B2 -A15 -E '^(FAIL|ERROR):' "$WORK/gdb.out" | head -80
fi

echo "== [3/3] gdb-embedded tests (qemu-aarch64 target) =="

if ! command -v aarch64-linux-gnu-gcc >/dev/null 2>&1 || ! command -v qemu-aarch64 >/dev/null 2>&1; then
    echo "SKIPPED: aarch64-linux-gnu-gcc / qemu-aarch64 not installed"
else
    PORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
    mkdir -p "$WORK/aarch64"
    if ! aarch64-linux-gnu-gcc -static -no-pie -g -O0 "$SCRIPT_DIR/assets/test.c" -o "$WORK/aarch64/test_static"; then
        echo "FAIL: cannot build aarch64 test binary"
        fail=1
    else
        qemu-aarch64 -g "$PORT" "$WORK/aarch64/test_static" &
        QPID=$!
        sleep 0.5

        gdb-multiarch -batch -q "$WORK/aarch64/test_static" \
            -ex 'set pagination off' \
            -ex 'set confirm off' \
            -ex "source $PEDA" \
            -ex "target remote :$PORT" \
            -ex "source $SCRIPT_DIR/test_peda_gdb_aarch64.py" > "$WORK/gdb_aarch64.out" 2>&1
        kill "$QPID" 2>/dev/null; QPID=""

        grep -E '^test_|^(OK|FAILED|Ran )|^(FAIL|ERROR):|^Traceback|AssertionError' "$WORK/gdb_aarch64.out" > "$WORK/summary_aarch64.out"
        cat "$WORK/summary_aarch64.out"

        if grep -q '^OK' "$WORK/gdb_aarch64.out"; then
            echo "UNIT OK (aarch64)"
        else
            fail=1
            echo "UNIT FAILED (aarch64), failure details:"
            grep -B2 -A15 -E '^(FAIL|ERROR):' "$WORK/gdb_aarch64.out" | head -80
        fi
    fi
fi

if [ "$fail" -eq 0 ]; then
    exit 0
else
    exit 1
fi

#!/bin/sh
# Smoke test for the AArch64 port of PEDA (mirrors tests/smoke_riscv.sh).
#
# Requirements: aarch64-linux-gnu-gcc, qemu-aarch64, gdb-multiarch.
#
# Builds a small test program, runs it under qemu-user gdbstub and checks
# the key PEDA commands in gdb batch mode:
#   - is_target_remote / vmmap / vmmap binary
#   - peda context: x-register names, no x86 leftovers, branch annotation
#   - dumpargs: AArch64 ABI (x0-x7) at function entry
#   - eflags: graceful degradation on a flags-less architecture
#   - searchmem / checksec
#
# Usage: tests/smoke_aarch64.sh   (from anywhere, paths are self-resolved)

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PEDA="$SCRIPT_DIR/../peda.py"
WORK=$(mktemp -d /tmp/peda-aarch64-smoke.XXXXXX)
PORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
QPID=""
cleanup() { [ -n "$QPID" ] && kill "$QPID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

failures=0
check() { # check <description> <pattern> [file] - pattern MUST be present
    desc=$1; pat=$2; file=${3:-$GDB_OUT}
    if grep -qE "$pat" "$file"; then
        printf 'PASS: %s\n' "$desc"
    else
        printf 'FAIL: %s (pattern "%s" not found, see %s)\n' "$desc" "$pat" "$file"
        failures=$((failures + 1))
    fi
}
check_absent() { # check_absent <description> <pattern> [file] - pattern MUST NOT be present
    desc=$1; pat=$2; file=${3:-$GDB_OUT}
    if grep -qE "$pat" "$file"; then
        printf 'FAIL: %s (pattern "%s" found, see %s)\n' "$desc" "$pat" "$file"
        failures=$((failures + 1))
    else
        printf 'PASS: %s\n' "$desc"
    fi
}

# ---------------------------------------------------------------- build ----
if ! aarch64-linux-gnu-gcc -static -no-pie -g -O0 "$SCRIPT_DIR/assets/test.c" -o "$WORK/test_static"; then
    echo "FAIL: cannot build test binary (aarch64-linux-gnu-gcc missing?)"
    exit 1
fi

# python helper: set a temp breakpoint on the first conditional branch inside main
cat > "$WORK/setbp.py" <<'EOF'
import re
import gdb

out = gdb.execute("disassemble main", to_string=True)
for line in out.splitlines():
    # mnemonic/operands are TAB-separated on aarch64; first b.<cond> branch
    m = re.search(r"0x([0-9a-f]+)\s+<[^>]*>:\s*b\.[a-z]+\s", line)
    if m:
        gdb.execute("tbreak *0x%s" % m.group(1))
        break
EOF

# ----------------------------------------------------------------- run -----
cd "$WORK" || exit 1  # keep peda session autosave files out of the repo
qemu-aarch64 -g "$PORT" "$WORK/test_static" &
QPID=$!
sleep 0.5

GDB_OUT="$WORK/gdb.out"
gdb-multiarch -q "$WORK/test_static" \
    -ex 'set pagination off' -ex 'set confirm off' \
    -ex "source $PEDA" \
    -ex "target remote :$PORT" \
    -ex 'echo \n==REMOTE==\n' \
    -ex 'python print("is_target_remote:", peda.is_target_remote())' \
    -ex 'echo \n==VMMAP==\n' -ex 'vmmap' \
    -ex 'echo \n==VMMAP-BINARY==\n' -ex 'vmmap binary' \
    -ex 'echo \n==START==\n' -ex 'peda start' \
    -ex 'echo \n==CONTEXT==\n' -ex 'peda context' \
    -ex 'echo \n==EFLAGS==\n' -ex 'eflags' \
    -ex 'echo \n==DUMPARGS-ENTRY==\n' \
    -ex 'break sum6' -ex 'continue' -ex 'dumpargs' \
    -ex 'echo \n==SEARCHMEM==\n' -ex 'searchmem "big" binary' \
    -ex 'echo \n==CHECKSEC==\n' -ex 'checksec' \
    -ex 'echo \n==BRANCH==\n' \
    -ex "source $WORK/setbp.py" -ex 'continue' -ex 'peda context code' \
    -ex 'kill' > "$GDB_OUT" 2>&1
kill "$QPID" 2>/dev/null; QPID=""

# ------------------------------------------------------------- asserts ----
check "remote target detected"            'is_target_remote: True'
check "vmmap: binary r-x mapping"         'r-xp.*/test_static'
check "vmmap: binary rw mapping"           'rw-p.*/test_static'
check "vmmap: stack mapping"                '\[stack\]'
check "context: ABI register names"         'X0 .*: 0x'
check_absent "context: no x86 register names" '[[:space:]]RAX[[:space:]]*:'
check "context: stack section"              '\[[-]*stack[-]*\]'
check "eflags: graceful warning"            'eflags is not supported on this architecture'
check "dumpargs: 6 args 1..6 at entry"      'arg\[5\]: 0x6'
check "dumpargs: first arg is 1"            'arg\[0\]: 0x1'
check "searchmem: finds big in binary"      "\('big'\)"
check "checksec: runs on aarch64 ELF"       'NX[[:space:]]*:'
check "branch: JUMP annotation rendered"    'JUMP is (NOT )?taken'

echo
if [ "$failures" -eq 0 ]; then
    echo "SMOKE OK: all checks passed ($WORK kept for inspection until exit)"
    exit 0
else
    echo "SMOKE FAILED: $failures check(s) failed; full log: $GDB_OUT"
    exit 1
fi

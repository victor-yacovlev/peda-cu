#!/bin/sh
# x86-64 regression test for PEDA (HANDOFF-Linux.md, rule 1: "do not break x86").
#
# Requirements: gcc, gdb (or gdb-multiarch).
#
# Checks that the native x86-64 workflow keeps working after RISC-V changes:
# peda start / context (EFLAGS line, intel syntax) / vmmap / dumpargs
# at the call site / eflags / checksec / pattern create.

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PEDA="$SCRIPT_DIR/../peda.py"
WORK=$(mktemp -d /tmp/peda-x86-smoke.XXXXXX)
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

failures=0
check() { # check <description> <pattern>
    if grep -qE "$1" "$GDB_OUT"; then
        printf 'PASS: %s\n' "$2"
    else
        printf 'FAIL: %s (pattern "%s" not found, see %s)\n' "$2" "$1" "$GDB_OUT"
        failures=$((failures + 1))
    fi
}

if ! gcc -g -O0 "$SCRIPT_DIR/assets/test.c" -o "$WORK/test_x64" 2>/dev/null; then
    if ! gcc -g -O0 -no-pie "$SCRIPT_DIR/assets/test.c" -o "$WORK/test_x64"; then
        echo "FAIL: cannot build x86-64 test binary (gcc missing?)"
        exit 1
    fi
fi

cd "$WORK" || exit 1
GDB_OUT="$WORK/gdb.out"
GDB_BIN=gdb
command -v "$GDB_BIN" >/dev/null 2>&1 || GDB_BIN=gdb-multiarch

"$GDB_BIN" -q "$WORK/test_x64" \
    -ex 'set pagination off' -ex 'set confirm off' \
    -ex "source $PEDA" \
    -ex 'echo \n==START==\n' -ex 'peda start' \
    -ex 'echo \n==REMOTE==\n' -ex 'python print("is_target_remote:", peda.is_target_remote())' \
    -ex 'echo \n==VMMAP==\n' -ex 'vmmap binary' \
    -ex 'echo \n==CONTEXT==\n' -ex 'peda context' \
    -ex 'echo \n==EFLAGS==\n' -ex 'eflags' \
    -ex 'echo \n==SEARCHMEM==\n' -ex 'searchmem "big" binary' \
    -ex 'echo \n==DUMPARGS==\n' \
    -ex 'break sum6' -ex 'continue' -ex 'dumpargs' \
    -ex 'echo \n==CHECKSEC==\n' -ex 'checksec' \
    -ex 'echo \n==PATTERN==\n' -ex 'pattern create 32' \
    -ex 'kill' > "$GDB_OUT" 2>&1

check 'is_target_remote: False'                    'is_target_remote: False' 'remote detection (native)'
check 'r-xp.*test_x64'                             'vmmap binary mapping'
check 'EFLAGS.*0x'                                 'eflags displayed (x86)'
check 'RIP|DWORD PTR'                              'intel syntax + x86 regs in context'
check 'JUMP is|arg\[|mov'                          'context code section rendered'
check "Found .* results|\\('big'\\)"               'searchmem'
check 'NX[[:space:]]*:'                            'checksec'
check 'AAA%AAsAABAA'                               'pattern create'

# dumpargs at the call site (in main, right before "call sum6")
cat > "$WORK/setbp.py" <<'EOF'
import re
import gdb

out = gdb.execute("disassemble main", to_string=True)
m = re.search(r"0x([0-9a-f]+)\s+<[^>]*>:\s*call\s+.*<sum6>", out)
if m:
    gdb.execute("tbreak *0x%s" % m.group(1))
EOF

"$GDB_BIN" -q "$WORK/test_x64" \
    -ex 'set pagination off' -ex 'set confirm off' \
    -ex "source $PEDA" \
    -ex 'start' \
    -ex "source $WORK/setbp.py" \
    -ex 'continue' -ex 'dumpargs' -ex 'kill' >> "$GDB_OUT" 2>&1
check 'arg\[0\]: 0x1'                              'dumpargs first arg at call site'
check 'arg\[5\]: 0x6'                              'dumpargs sixth arg at call site'

echo
if [ "$failures" -eq 0 ]; then
    echo "SMOKE OK: all checks passed"
    exit 0
else
    echo "SMOKE FAILED: $failures check(s) failed; full log: $GDB_OUT"
    exit 1
fi

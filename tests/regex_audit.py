#!/usr/bin/env python3
"""Audit all regex call sites: extract patterns via AST, compile them,
compare old (git HEAD) vs new values to prove raw-string conversion is
value-preserving."""
import ast, re, subprocess, sys, collections

RE_FUNCS = {"compile", "search", "match", "fullmatch", "findall", "finditer", "sub", "split"}

def extract(src: str, fname: str) -> dict[tuple[str, int], str | bytes | None]:
    """Return {(file, lineno): pattern_value} for constant patterns."""
    out = {}
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr in RE_FUNCS:
            mod = node.func.value
            is_re = (isinstance(mod, ast.Name) and mod.id == "re")
            if not is_re:
                continue
            if not node.args:
                continue
            pat = node.args[0]
            try:
                val = ast.literal_eval(pat)
            except Exception:
                val = None  # dynamic pattern
            out[(fname, node.lineno)] = val
    return out

def audit(files: dict[str, str]) -> dict[tuple[str, int], str | bytes | None]:
    pats = {}
    for fname, src in files.items():
        pats.update(extract(src, fname))
    return pats

def from_git() -> dict[str, str]:
    files = {}
    for f in ["peda.py", "lib/config.py", "lib/nasm.py", "lib/shellcode.py",
              "lib/skeleton.py", "lib/utils.py"]:
        out = subprocess.run(["git", "show", "HEAD:%s" % f],
                             capture_output=True, text=True, check=True)
        files[f] = out.stdout
    return files

def from_disk() -> dict[str, str]:
    files = {}
    for f in ["peda.py", "lib/config.py", "lib/nasm.py", "lib/shellcode.py",
              "lib/skeleton.py", "lib/utils.py"]:
        files[f] = open(f, encoding="utf-8").read()
    return files

old = audit(from_git())
new = audit(from_disk())

# 1. compile every constant pattern in new code
fails = []
dynamic_new = 0
for (fname, lineno), val in sorted(new.items()):
    if val is None:
        dynamic_new += 1
        continue
    try:
        re.compile(val)
    except re.error as e:
        fails.append((fname, lineno, val, str(e)))
print("== NEW: %d regex call sites (%d constant, %d dynamic)" %
      (len(new), len(new) - dynamic_new, dynamic_new))
if fails:
    print("COMPILE FAILURES:")
    for f in fails:
        print("  %s:%d  %r  ->  %s" % f)
else:
    print("ALL constant patterns compile OK")

# 2. compare constant pattern VALUES old vs new (semantic equivalence of the conversion)
old_const = collections.Counter(v for v in old.values() if v is not None)
new_const = collections.Counter(v for v in new.values() if v is not None)
only_old = old_const - new_const
only_new = new_const - old_const
print("\n== OLD vs NEW pattern values")
print("old sites: %d, new sites: %d" % (len(old), len(new)))
if not only_old and not only_new:
    print("multisets of pattern values IDENTICAL -> conversion is value-preserving")
else:
    print("only in OLD (count, value):")
    for v, c in only_old.items():
        print("   %dx %r" % (c, v))
    print("only in NEW (count, value):")
    for v, c in only_new.items():
        print("   %dx %r" % (c, v))

# 3. list dynamic (non-constant) sites for manual review
print("\n== DYNAMIC pattern sites (manual review needed)")
for (fname, lineno), val in sorted(new.items()):
    if val is None:
        print("  %s:%d" % (fname, lineno))

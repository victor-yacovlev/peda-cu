peda
====

PEDA - Python Exploit Development Assistance for GDB

## Key Features:
* Enhance the display of gdb: colorize and display disassembly codes, registers, memory information during debugging.
* Add commands to support debugging and exploit development (for a full list of commands use `peda help`):
  * `aslr` -- Show/set ASLR setting of GDB
  * `checksec` -- Check for various security options of binary
  * `dumpargs` -- Display arguments passed to a function when stopped at a call instruction
  * `dumprop` -- Dump all ROP gadgets in specific memory range
  * `elfheader` -- Get headers information from debugged ELF file
  * `elfsymbol` -- Get non-debugging symbol information from an ELF file
  * `lookup` -- Search for all addresses/references to addresses which belong to a memory range
  * `patch` -- Patch memory start at an address with string/hexstring/int
  * `pattern` -- Generate, search, or write a cyclic pattern to memory
  * `procinfo` -- Display various info from /proc/pid/
  * `pshow` -- Show various PEDA options and other settings
  * `pset` -- Set various PEDA options and other settings
  * `readelf` -- Get headers information from an ELF file
  * `ropgadget` -- Get common ROP gadgets of binary or library
  * `ropsearch` -- Search for ROP gadgets in memory
  * `searchmem|find` -- Search for a pattern in memory; support regex search
  * `shellcode` -- Generate or download common shellcodes.
  * `skeleton` -- Generate python exploit code template
  * `vmmap` -- Get virtual mapping address ranges of section(s) in debugged process
  * `xormem` -- XOR a memory region with a key

## Installation

    git clone https://github.com/longld/peda.git ~/peda
    echo "source ~/peda/peda.py" >> ~/.gdbinit
    echo "DONE! debug your program with gdb and enjoy"

Requires GDB built with Python 3 (>= 3.13). Python 2 is not supported.

## Notes

* The `find` alias overrides GDB's built-in `find` command (it maps to `peda
  searchmem`). Use `searchmem` directly, or `pipe find ...`/`maintenance ...`
  if you need the original GDB behavior.
* RISC-V targets are supported: works with `gdb-multiarch` + `qemu-riscv64 -g
  PORT` (`target remote :PORT`), including `vmmap`, `dumpargs` (RISC-V ABI,
  a0-a7), branch-taken hints in `context` and register display. x86 remains
  the primary target.

## Tests

Run before committing (Linux host):

    tests/run_unit_tests.sh   # unit tests: lib/utils.py + gdb-embedded suite
                              # against a live qemu-riscv64 target (67 tests)
    tests/smoke_riscv.sh      # command-level smoke test under qemu (13 checks)
    tests/smoke_x86.sh        # x86-64 regression (10 checks)

The unit suite covers vmmap parsers (modern/legacy `info proc mappings`,
local /proc fallback), word-boundary register substitution, RISC-V argument
heuristics + DWARF fallback, and branch semantics including the signed vs
unsigned (`blt`/`bltu`) boundary.

## Screenshot
![start](http://i.imgur.com/P1BF5mp.png)

![pattern arg](http://i.imgur.com/W97OWRC.png)

![patts](http://i.imgur.com/Br24IpC.png)

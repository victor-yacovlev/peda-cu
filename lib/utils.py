#
#       PEDA - Python Exploit Development Assistance for GDB
#
#       Copyright (C) 2012 Long Le Dinh <longld at vnsecurity.net>
#
#       License: see LICENSE file for details
#

import codecs
import functools
import inspect
import pprint
import re
import string
import struct
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterator
from io import StringIO
from typing import Any, Self

import config

# http://wiki.python.org/moin/PythonDecoratorLibrary#Memoize
# http://stackoverflow.com/questions/8856164/class-decorator-decorating-method-in-python
class memoized:
    """
    Decorator. Caches a function's return value each time it is called.
    If called later with the same arguments, the cached value is returned
    (not reevaluated).
    """
    def __init__(self, func: Callable[..., Any]) -> None:
        self.func = func
        self.instance = None # bind with instance class of decorated method
        self.cache: dict[tuple[Any, ...], Any] = {}
        self.__doc__ = inspect.getdoc(self.func)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        try:
            return self.cache[(self.func, self.instance, args) + tuple(kwargs.items())]
        except KeyError:
            if self.instance is None:
                value = self.func(*args, **kwargs)
            else:
                value = self.func(self.instance, *args, **kwargs)
            self.cache[(self.func, self.instance, args) + tuple(kwargs.items())] = value
            return value
        except TypeError:
            # uncachable -- for instance, passing a list as an argument.
            # Better to not cache than to blow up entirely.
            if self.instance is None:
                return self.func(*args, **kwargs)
            else:
                return self.func(self.instance, *args, **kwargs)

    def __repr__(self) -> str:
        """Return the function's docstring."""
        return self.__doc__ or self.func.__name__

    def __get__(self, obj: Any, objtype: Any) -> Self:
        """Support instance methods."""
        if obj is None:
            return self
        else:
            self.instance = obj
            return self

    def _reset(self) -> None:
        """Reset the cache"""
        # Make list to prevent modifying dictionary while iterating
        for cached in list(self.cache.keys()):
            if cached[0] == self.func and cached[1] == self.instance:
                del self.cache[cached]

def reset_cache(module: Any = None) -> bool:
    """
    Reset memoized caches of an instance/module
    """
    if module is None:
        module = sys.modules['__main__']

    for m in dir(module):
        m = getattr(module, m)
        if isinstance(m, memoized):
            m._reset()
        else:
            for f in dir(m):
                f = getattr(m, f)
                if isinstance(f, memoized):
                    f._reset()

    return True

def tmpfile(pref: str = "peda-", is_binary_file: bool = False) -> Any:
    """Create and return a temporary file with custom prefix"""

    mode = 'w+b' if is_binary_file else 'w+'
    return tempfile.NamedTemporaryFile(mode=mode, prefix=pref)

def colorize(text: str, color: str | None = None, attrib: str | None = None) -> str:
    """
    Colorize text using ansicolor
    ref: https://github.com/hellman/libcolors/blob/master/libcolors.py
    """
    # ansicolor definitions
    COLORS = {"black": "30", "red": "31", "green": "32", "yellow": "33",
                "blue": "34", "purple": "35", "cyan": "36", "white": "37"}
    CATTRS = {"regular": "0", "bold": "1", "underline": "4", "strike": "9",
                "light": "1", "dark": "2", "invert": "7"}

    CPRE = '\033['
    CSUF = '\033[0m'

    if config.Option.get("ansicolor") != "on":
        return text

    ccode = ""
    if attrib:
        for attr in attrib.lower().split():
            attr = attr.strip(",+|")
            if attr in CATTRS:
                ccode += ";" + CATTRS[attr]
    if color in COLORS:
        ccode += ";" + COLORS[color]
    return CPRE + ccode + "m" + text + CSUF

def green(text: str, attrib: str | None = None) -> str:
    """Wrapper for colorize(text, 'green')"""
    return colorize(text, "green", attrib)

def red(text: str, attrib: str | None = None) -> str:
    """Wrapper for colorize(text, 'red')"""
    return colorize(text, "red", attrib)

def yellow(text: str, attrib: str | None = None) -> str:
    """Wrapper for colorize(text, 'yellow')"""
    return colorize(text, "yellow", attrib)

def blue(text: str, attrib: str | None = None) -> str:
    """Wrapper for colorize(text, 'blue')"""
    return colorize(text, "blue", attrib)

def clearscreen() -> None:
    """Clear terminal screen"""
    sys.stdout.write("\x1b[2J\x1b[H")

class message:
    """
    Generic pretty printer with redirection.
    It also suports buffering using bufferize() and flush().
    """

    def __init__(self) -> None:
        self.out: StringIO | Any = sys.stdout
        self.buffering = 0

    def bufferize(self, f: Callable[..., Any] | None = None) -> Callable[..., Any] | None:
        """Activate message's bufferization, can also be used as a decorater."""

        if f is not None:
            @functools.wraps(f)
            def wrapper(*args: Any, **kwargs: Any) -> None:
                self.bufferize()
                try:
                    f(*args, **kwargs)
                finally:
                    # flush even if the command raised: otherwise the buffering
                    # counter leaks and all subsequent peda output is swallowed
                    self.flush()
            return wrapper

        # If we are still using stdio we need to change it.
        if not self.buffering:
            self.out = StringIO()
        self.buffering += 1

    def flush(self) -> None:
        if not self.buffering:
            raise ValueError("Tried to flush a message that is not bufferising.")
        self.buffering -= 1

        # We only need to flush if this is the lowest recursion level.
        if not self.buffering:
            self.out.flush()
            sys.stdout.write(self.out.getvalue())
            self.out = sys.stdout

    def __call__(self, text: Any, color: str | None = None, attrib: str | None = None, teefd: Any = None) -> None:
        if not teefd:
            teefd = config.Option.get("_teefd")

        if isinstance(text, str) and "\x00" not in text:
            print(colorize(text, color, attrib), file=self.out)
            if teefd:
                print(colorize(text, color, attrib), file=teefd)
        else:
            pprint.pprint(text, self.out)
            if teefd:
                pprint.pprint(text, teefd)

msg = message()

def warning_msg(text: Any) -> None:
    """Colorize warning message with prefix"""
    msg(colorize("Warning: " + str(text), "yellow"))

def error_msg(text: Any) -> None:
    """Colorize error message with prefix"""
    msg(colorize("Error: " + str(text), "red"))

def debug_msg(text: Any, prefix: str = "Debug") -> None:
    """Colorize debug message with prefix"""
    msg(colorize(f"{prefix}: {text!s}", "cyan"))

def trim(docstring: str | None) -> str:
    """
    Handle docstring indentation, ref: PEP257
    """
    if not docstring:
        return ''
    # Convert tabs to spaces (following the normal Python rules)
    # and split into a list of lines:
    lines = docstring.expandtabs().splitlines()
    # Determine minimum indentation (first line doesn't count):
    max_indent = sys.maxsize
    indent = max_indent
    for line in lines[1:]:
        stripped = line.lstrip()
        if stripped:
            indent = min(indent, len(line) - len(stripped))
    # Remove indentation (first line is special):
    trimmed = [lines[0].strip()]
    if indent < max_indent:
        for line in lines[1:]:
            trimmed.append(line[indent:].rstrip())
    # Strip off trailing and leading blank lines:
    while trimmed and not trimmed[-1]:
        trimmed.pop()
    while trimmed and not trimmed[0]:
        trimmed.pop(0)
    # Return a single string:
    return '\n'.join(trimmed)

def pager(text: str, pagesize: int | None = None) -> None:
    """
    Paging output, mimic external command less/more
    """
    if not pagesize:
        pagesize = to_int(config.Option.get("pagesize"))

    if not pagesize or pagesize <= 0:
        msg(text)
        return

    i = 1
    lines = text.splitlines()
    l = len(lines)

    for line in lines:
        msg(line)
        if i % pagesize == 0:
            ans = input(f"--More--({i}/{l})")
            if ans.lower().strip() == "q":
                break
        i += 1

def execute_external_command(command: str, cmd_input: bytes | None = None) -> str:
    """
    Execute external command and capture its output

    Args:
        - command (String)

    Returns:
        - output of command (String)
    """
    result = ""
    P = subprocess.Popen([command], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    (result, err) = P.communicate(cmd_input)
    if err and config.Option.get("debug") == "on":
        warning_msg(err)

    return decode_string_escape(result)

def is_printable(text: bytes | str, printables: str = "") -> bool:
    """
    Check if a string is printable
    """
    if isinstance(text, str):
        text = text.encode('latin-1')
    return set(text) - set(string.printable.encode('ascii') + printables.encode('ascii')) == set()

def is_math_exp(str: str) -> bool:
    """
    Check if a string is a math exprssion
    """
    charset = set("0123456789abcdefx+-*/%^")
    opers = set("+-*/%^")
    exp = set(str.lower())
    return (exp & opers != set()) and (exp - charset == set())

def normalize_argv(args: list[Any] | tuple[Any, ...], size: int = 0) -> list[Any]:
    """
    Normalize argv to list with predefined length
    """
    args = list(args)
    for (idx, val) in enumerate(args):
        if to_int(val) is not None:
            args[idx] = to_int(val)
        if size and idx == size:
            return args[:idx]

    if size == 0:
        return args
    for i in range(len(args), size):
        args += [None]
    return args

def to_hexstr(str_: str | bytes) -> str:
    """
    Convert a binary string to hex escape format
    """
    if isinstance(str_, str):
        str_ = str_.encode('latin-1')
    return "".join([f"\\x{ord(i):02x}" for i in bytes_iterator(str_)])

def to_hex(num: int) -> str:
    """
    Convert a number to hex format
    """
    if num < 0:
        return f"-0x{-num:x}"
    return f"0x{num:x}"

def to_address(num: int) -> str:
    """
    Convert a number to address format in hex
    """
    if num < 0:
        return to_hex(num)
    if num > 0xffffffff: # 64 bit
        return f"0x{num:016x}"
    return f"0x{num:08x}"

def to_int(val: Any) -> int | None:
    """
    Convert a string to int number
    """
    try:
        return int(str(val), 0)
    except (TypeError, ValueError):
        return None

def str2hex(str: bytes) -> bytes:
    """
    Convert a string to hex encoded format
    """
    result = codecs.encode(str, 'hex')
    return result

def hex2str(hexnum: str | int, intsize: int = 4) -> bytes:
    """
    Convert a number in hex format to string
    """
    if not isinstance(hexnum, str):
        nbits = intsize * 8
        hexnum = f"0x{(hexnum + (1 << nbits)) % (1 << nbits):x}"
    s = hexnum[2:]
    if len(s) % 2 != 0:
        s = "0" + s
    result = codecs.decode(s, 'hex')[::-1]
    return result

def int2hexstr(num: int, intsize: int = 4) -> bytes:
    """
    Convert a number to hexified string
    """
    if intsize == 8:
        if num < 0:
            result = struct.pack("<q", num)
        else:
            result = struct.pack("<Q", num)
    else:
        if num < 0:
            result = struct.pack("<l", num)
        else:
            result = struct.pack("<L", num)
    return result

def list2hexstr(intlist: list[Any], intsize: int = 4) -> bytes:
    """
    Convert a list of number/string to hexified string (bytes)
    """
    result = b""
    for value in intlist:
        if isinstance(value, bytes):
            result += value
        elif isinstance(value, str):
            result += value.encode('latin-1')
        else:
            result += int2hexstr(value, intsize)
    return result

def str2intlist(data: bytes | str, intsize: int = 4) -> list[int]:
    """
    Convert a string to list of int
    """
    result = []
    data = decode_string_escape(data)[::-1].encode('latin-1')
    l = len(data)
    data = (b"\x00" * (intsize - l%intsize) + data) if l%intsize != 0 else data
    for i in range(0, l, intsize):
        if intsize == 8:
            val = struct.unpack(">Q", data[i:i+intsize])[0]
        else:
            val = struct.unpack(">L", data[i:i+intsize])[0]
        result = [val] + result
    return result

@memoized
def check_badchars(data: str | int, chars: str | None = None) -> bool:
    """
    Check an address or a value if it contains badchars
    """
    val = to_int(data)
    if val is None:
        to_search = to_binary_string(str(data))
    else:
        hexstr = to_hex(val)[2:]
        if len(hexstr) % 2 != 0:
            hexstr = "0" + hexstr
        to_search = codecs.decode(hexstr, 'hex')

    if not chars:
        chars = str(config.Option.get("badchars"))

    if chars:
        for c in decode_string_escape(chars):
            if c.encode('latin-1') in to_search:
                return True
    return False

@memoized
def format_address(addr: str, type: str) -> str:
    """Colorize an address"""
    colorcodes = {
        "data": "blue",
        "code": "red",
        "rodata": "green",
        "value": None
    }
    return colorize(addr, colorcodes[type])

@memoized
def format_reference_chain(chain: list[tuple[str, str, str]] | None) -> str:
    """
    Colorize a chain of references
    """
    v = t = vn = None
    text = ""
    if not chain:
        text += "Cannot access memory address"
    else:
        first = True
        for (v, t, vn) in chain:
            prefix = "" if first else "--> "
            if t != "value":
                text += f"{prefix}{format_address(v, t)} "
            else:
                text += f"{prefix}{v} "
            first = False

        if vn:
            text += f"({vn})"
        else:
            if v != "0x0":
                s = hex2str(v or "")
                if is_printable(s, "\x00"):
                    text += f"({string_repr(s.split(b'\x00')[0])})"
    return text

# vulnerable C functions, source: rats/flawfinder
VULN_FUNCTIONS = [
    "exec", "system", "gets", "popen", "getenv", "strcpy", "strncpy", "strcat", "strncat",
    "memcpy", "bcopy", "printf", "sprintf", "snprintf", "scanf",  "getchar", "getc", "read",
    "recv", "tmp", "temp"
]
@memoized
def format_disasm_code(code: str, nearby: int | None = None) -> str:
    """
    Format output of disassemble command with colors to highlight:
        - dangerous functions (rats/flawfinder)
        - branching: jmp, call, ret
        - testing: cmp, test

    Args:
        - code: input asm code (String)
        - nearby: address for nearby style format (Int)

    Returns:
        - colorized text code (String)
    """
    colorcodes = {
        "cmp": "red",
        "test": "red",
        "call": "green",
        "j": "yellow", # jump
        "ret": "blue",
    }
    result = ""

    if not code:
        return result

    target = to_int(nearby)
    if target is None:
        target = 0

    for line in code.splitlines():
        if ":" not in line: # not an assembly line
            result += line + "\n"
        else:
            color = style = None
            m = re.search(r".*(0x[^ ]*).*:\s*([^ ]*)", line)
            if not m: # failed to parse
                result += line + "\n"
                continue
            addr, opcode = to_int(m.group(1)), m.group(2)
            for c, ccolor in colorcodes.items():
                if c in opcode:
                    color = ccolor
                    if c == "call":
                        for f in VULN_FUNCTIONS:
                            if f in line.split(":\t", 1)[-1]:
                                style = "bold, underline"
                                color = "red"
                                break
                    break

            prefix = line.split(":\t")[0]
            addr = re.search(r"(0x[^\s]*)", prefix)
            addr = to_int(addr.group(1)) if addr else None
            if addr is None:
                addr = -1
            line = "\t" + line.split(":\t", 1)[-1]
            if addr < target:
                style = "dark"
            elif addr == target:
                style = "bold"
                color = "green"

            code = colorize(line.split(";")[0], color, style)
            if ";" in line:
                comment = colorize(";" + line.split(";", 1)[1], color, "dark")
            else:
                comment = ""
            line = f"{prefix}:{code}{comment}"
            result += line + "\n"

    return result.rstrip()

def cyclic_pattern_charset(charset_type: int | str | None = None) -> str:
    """
    Generate charset for cyclic pattern

    Args:
        - charset_type: charset type
            0: basic (0-9A-Za-z)
            1: extended (default)
            2: maximum (almost printable chars)

    Returns:
        - list of charset
    """

    charset = []
    charset += ["ABCDEFGHIJKLMNOPQRSTUVWXYZ"] # string.uppercase
    charset += ["abcdefghijklmnopqrstuvwxyz"] # string.lowercase
    charset += ["0123456789"] # string.digits

    if not charset_type:
        charset_type = config.Option.get("pattern")

    if charset_type == 1: # extended type
        charset[1] = "%$-;" + re.sub("[sn]", "", charset[1])
        charset[2] = "sn()" + charset[2]

    if charset_type == 2: # maximum type
        charset += ['!"#$%&()*+,-./:;<=>?@[]^_{|}~'] # string.punctuation

    mixed_charset = mixed = ''
    k = 0
    while True:
        for i in range(len(charset)): mixed += charset[i][k:k+1]
        if not mixed: break
        mixed_charset += mixed
        mixed = ''
        k+=1

    return mixed_charset

def de_bruijn(charset: str, n: int, maxlen: int) -> str:
    """
    Generate the De Bruijn Sequence up to `maxlen` characters for the charset `charset`
    and subsequences of length `n`.
    Algorithm modified from wikipedia http://en.wikipedia.org/wiki/De_Bruijn_sequence
    """
    k = len(charset)
    a = [0] * k * n
    sequence = []
    def db(t: int, p: int) -> None:
        if len(sequence) == maxlen:
            return

        if t > n:
            if n % p == 0:
                for j in range(1, p + 1):
                    sequence.append(charset[a[j]])
                    if len(sequence) == maxlen:
                        return
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)
    db(1,1)
    return ''.join(sequence)

@memoized
def cyclic_pattern(size: int | None = None, start: int | None = None, charset_type: int | None = None) -> bytes:
    """
    Generate a cyclic pattern

    Args:
        - size: size of generated pattern (Int)
        - start: the start offset of the generated pattern (Int)
        - charset_type: charset type
            0: basic (0-9A-Za-z)
            1: extended (default)
            2: maximum (almost printable chars)

    Returns:
        - pattern text (byte string) (str in Python 2; bytes in Python 3)
    """
    charset = config.Option.get("p_charset")
    if not charset:
        charset = cyclic_pattern_charset(charset)
    else:
        charset = ''.join(set(str(charset)))

    if start is None:
        start = 0
    if size is None:
        size = 0x10000

    size += start

    pattern = de_bruijn(charset, 3, size)

    return pattern[start:size].encode('utf-8')

@memoized
def cyclic_pattern_offset(value: str | int) -> int | None:
    """
    Search a value if it is a part of cyclic pattern

    Args:
        - value: value to search for (String/Int)

    Returns:
        - offset in pattern if found
    """
    pattern = cyclic_pattern()
    val = to_int(value)
    if val is None:
        search = str(value).encode('utf-8')
    else:
        search = hex2str(val)

    pos = pattern.find(search)
    return pos if pos != -1 else None

def cyclic_pattern_search(buf: bytes) -> list[tuple[int, int, int]]:
    """
    Search all cyclic pattern pieces in a buffer

    Args:
        - buf: buffer to search for (String)

    Returns:
        - list of tuple (buffer_offset, pattern_len, pattern_offset)
    """
    result = []
    pattern = cyclic_pattern()

    p = re.compile(b"[" + re.escape(to_binary_string(cyclic_pattern_charset())) + b"]{4,}")
    found = p.finditer(buf)
    found = list(found)
    for m in found:
        s = buf[m.start():m.end()]
        i = pattern.find(s)
        k = 0
        while i == -1 and len(s) > 4:
            s = s[1:]
            k += 1
            i = pattern.find(s)
        if i != -1:
            result += [(m.start()+k, len(s), i)]

    return result


def decode_string_escape(str_: bytes | str) -> str:
    """Decode escape sequences in a string, e.g. "\\n" -> newline (bytes input returns str)"""
    # Based on: http://stackoverflow.com/a/4020824
    return codecs.decode(str_, "unicode_escape")


def bytes_iterator(bytes_: bytes) -> Iterator[bytes]:
    """
    Iterate over a bytes object, yielding 1-byte bytes objects
    (in contrast to iterating bytes directly, which yields ints).
    """
    for b in bytes_:
        yield bytes([b])


def bytes_chr(i: int) -> bytes:
    """Returns a byte string of length 1 whose ordinal value is i"""
    return bytes([i])


def to_binary_string(text: bytes | str) -> bytes:
    """
    Converts a str to bytes (latin-1) if it is not already a bytes object.
    """
    if isinstance(text, bytes):
        return text
    elif isinstance(text, str):
        return text.encode('latin-1')
    else:
        raise TypeError("only takes string types")


def dbg_print_vars(*args: Any) -> None:
    """Prints name and repr of each arg on a separate line"""
    frame = inspect.currentframe()
    parent_locals = frame.f_back.f_locals if frame is not None and frame.f_back is not None else {}
    maps = []
    for arg in args:
        for name, value in parent_locals.items():
            if id(arg) == id(value):
                maps.append((name, repr(value)))
                break
    print('\n'.join(name + '=' + value for name, value in maps))


def string_repr(text: Any, show_quotes: bool = True) -> str:
    """
    Prints the repr of a string. Eliminates the leading 'b' for bytes input.

    Optionally can show or include quotes.
    """
    if isinstance(text, (bytes, bytearray)):
        # Skip leading 'b' at the beginning of repr
        output = repr(text)[1:]
    else:
        output = repr(text)

    if show_quotes:
        return output
    else:
        return output[1:-1]

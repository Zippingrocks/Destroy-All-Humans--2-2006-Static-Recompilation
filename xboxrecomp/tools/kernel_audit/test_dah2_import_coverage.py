"""
Every kernel ordinal Destroy All Humans! 2 imports must be routed.

Run: py -3 tools/kernel_audit/test_dah2_import_coverage.py

The startup line "Thunk table: 146/378 resolved, 232 unresolved" that
xbox_kernel_init used to print was not a measure of this title: it counted a
hard-coded Burnout 3 ordinal list zero-padded out to the 378 kernel export
slots, so 231 of the 232 "unresolved" entries were padding. The title's own
coverage is whatever its XBE thunk table imports, which is read here directly
(DAH2 imports 107 ordinals).

An import is covered when it is a DATA export (kernel_data_va_for_ordinal) or
has a function route (bridge_for_ordinal). An unrouted function import is not
fatal by itself -- the generic stub pops the argument bytes and returns 0 --
but a return of 0 is "success" to every caller, which is how a wait that never
waits or a size query that always answers zero goes unnoticed. Every routed
function ordinal must also have an explicit stdcall-argument entry: a missing
one silently defaults to 0 and leaks the arguments off the guest stack.

Skipped (not failed) when game_files/default.xbe is absent; no game data is
distributed with this project.
"""

import os
import re
import struct
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
BRIDGE_C = os.path.join(ROOT, "src", "kernel", "kernel_bridge.c")
XBE = os.path.join(ROOT, "..", "game_files", "default.xbe")

# Retail XBE header obfuscation keys (entry point / kernel thunk address).
RETAIL_THUNK_KEY = 0x5B6D40B6


def load_imports():
    """Kernel ordinals imported by the XBE, in thunk-table order."""
    with open(XBE, "rb") as fh:
        d = fh.read()
    assert d[:4] == b"XBEH", "not an XBE"
    base, = struct.unpack_from("<I", d, 0x104)
    thunk_enc, = struct.unpack_from("<I", d, 0x158)
    nsec, sechdr = struct.unpack_from("<II", d, 0x11C)
    secs = [struct.unpack_from("<IIIII", d, sechdr - base + i * 56)[1:]
            for i in range(nsec)]
    thunk = thunk_enc ^ RETAIL_THUNK_KEY
    off = None
    for va, vsz, raw, rsz in secs:
        if va <= thunk < va + max(vsz, rsz):
            off = raw + (thunk - va)
            break
    assert off is not None, "kernel thunk table is not inside any section"
    ordinals = []
    while True:
        v, = struct.unpack_from("<I", d, off + 4 * len(ordinals))
        if v == 0:
            break
        assert v & 0x80000000, "thunk entry %08X is not an ordinal import" % v
        ordinals.append(v & 0x7FFFFFFF)
    assert ordinals, "empty import table"
    return ordinals


def _function_body(src_lines, header_regex):
    start = next(i for i, l in enumerate(src_lines) if re.match(header_regex, l))
    end = next(i for i in range(start + 1, len(src_lines))
               if src_lines[i].startswith("}"))
    return src_lines[start:end]


def _live_cases(body):
    """case labels that are real code, not inside a /* ... */ comment line."""
    out = {}
    for line in body:
        m = re.match(r"\s*case\s+(\d+)\s*:\s*(.*)", line)
        if m:
            out[int(m.group(1))] = m.group(2).strip()
    return out


def load_tables():
    with open(BRIDGE_C, encoding="utf-8", errors="replace") as fh:
        lines = fh.read().split("\n")
    data = _live_cases(_function_body(lines, r"static uint32_t kernel_data_va_for_ordinal"))
    args = _live_cases(_function_body(lines, r"static int stdcall_args_for_ordinal"))
    routes = _live_cases(_function_body(lines, r"static bridge_func_t bridge_for_ordinal"))
    return data, args, routes


def _skip_if_no_xbe():
    if not os.path.exists(XBE):
        print("skip  game_files/default.xbe not present")
        return True
    return False


def test_every_dah2_import_is_routed():
    if _skip_if_no_xbe():
        return
    imports = load_imports()
    data, _args, routes = load_tables()
    unrouted = [o for o in imports if o not in data and o not in routes]
    assert not unrouted, (
        "%d of %d DAH2 imports have no data export or bridge route "
        "(they return 0 = STATUS_SUCCESS): %s"
        % (len(unrouted), len(imports), unrouted))
    print("ok  every_dah2_import_is_routed (%d/%d: %d data, %d function)" % (
        len(imports), len(imports),
        sum(1 for o in imports if o in data),
        sum(1 for o in imports if o not in data)))


def test_every_routed_dah2_function_has_an_explicit_arg_size():
    if _skip_if_no_xbe():
        return
    imports = load_imports()
    data, args, routes = load_tables()
    missing = [o for o in imports if o in routes and o not in data and o not in args]
    assert not missing, (
        "routed function ordinals with no stdcall-argument entry (defaults "
        "to 0 bytes and leaks the arguments): %s" % missing)
    print("ok  every_routed_dah2_function_has_an_explicit_arg_size")


def test_known_arg_sizes_against_retail_call_sites():
    """Argument counts confirmed by reading the retail call site's pushes."""
    _data, args, _routes = load_tables()
    known = {
        217: 8,    # NtQueryVirtualMemory(BaseAddress, Info): 2 pushes at 0xFDEB2
        304: 8,    # RtlTimeFieldsToTime(TimeFields, Time): 2 pushes at 0x1CE77F
        327: 4,    # XeLoadSection(Section): 1 push (the other is a saved esi)
    }
    bad = []
    for ordinal, want in known.items():
        m = re.match(r"return\s+(\d+)", args.get(ordinal, ""))
        got = int(m.group(1)) if m else None
        if got != want:
            bad.append("ordinal %d: table says %s bytes, retail call site pushes %d"
                       % (ordinal, got, want))
    assert not bad, "\n  ".join(bad)
    print("ok  known_arg_sizes_against_retail_call_sites (%d ordinals)" % len(known))


if __name__ == "__main__":
    _tests = [v for k, v in sorted(globals().items())
              if k.startswith("test_") and callable(v)]
    for _t in _tests:
        _t()
    print("all passed (%d checks)" % len(_tests))

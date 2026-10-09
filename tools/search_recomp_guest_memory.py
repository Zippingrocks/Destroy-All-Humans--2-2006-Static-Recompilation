"""Search a running private recomp's 64 MiB Xbox RAM for bounded text patterns."""
from __future__ import annotations

import argparse
import ctypes
import json
from pathlib import Path
import re
import struct

IMAGE_BASE = 0x140000000


def symbol_rva(map_path: Path, name: str) -> int:
    text = map_path.read_text(errors="replace")
    match = re.search(rf"(?m)^\s*[0-9A-Fa-f]+:[0-9A-Fa-f]+\s+{re.escape(name)}\s+([0-9A-Fa-f]+)\s", text)
    if not match:
        raise SystemExit(f"symbol not found in map: {name}")
    return int(match.group(1), 16) - IMAGE_BASE


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--map", required=True, type=Path)
    parser.add_argument("--pattern", action="append", default=[])
    parser.add_argument("--hex-pattern", action="append", default=[])
    parser.add_argument("--start", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--length", type=lambda value: int(value, 0), default=0x04000000)
    parser.add_argument("--chunk-size", type=lambda value: int(value, 0), default=0x100000)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 0 <= args.start < 0x04000000 or not 1 <= args.length <= 0x04000000 - args.start:
        raise SystemExit("search range must remain inside the 64 MiB Xbox RAM window")
    if not 0x1000 <= args.chunk_size <= 0x100000:
        raise SystemExit("chunk size must be between 4 KiB and 1 MiB")

    needles: list[tuple[str, str, bytes]] = []
    for value in args.pattern:
        if not value:
            raise SystemExit("empty pattern")
        needles.extend(((value, "ascii", value.encode("ascii")),
                        (value, "ascii-lower", value.lower().encode("ascii")),
                        (value, "utf16le", value.encode("utf-16le")),
                        (value, "utf16le-lower", value.lower().encode("utf-16le"))))
    for value in args.hex_pattern:
        try:
            needle = bytes.fromhex(value)
        except ValueError as exc:
            raise SystemExit(f"invalid hex pattern: {value}") from exc
        if not needle:
            raise SystemExit("empty hex pattern")
        needles.append((value.lower(), "hex", needle))
    if not needles:
        raise SystemExit("at least one --pattern or --hex-pattern is required")
    overlap = max(len(needle) for _, _, needle in needles) - 1

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                         ctypes.c_void_p, ctypes.c_size_t,
                                         ctypes.POINTER(ctypes.c_size_t)]
    kernel.ReadProcessMemory.restype = ctypes.c_int
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    psapi.EnumProcessModules.argtypes = [ctypes.c_void_p,
                                         ctypes.POINTER(ctypes.c_void_p),
                                         ctypes.c_uint32,
                                         ctypes.POINTER(ctypes.c_uint32)]
    handle = kernel.OpenProcess(0x0C10, False, args.pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        module = ctypes.c_void_p()
        needed = ctypes.c_uint32()
        if not psapi.EnumProcessModules(handle, ctypes.byref(module), ctypes.sizeof(module), ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())

        def read_native(address: int, length: int) -> bytes:
            data = ctypes.create_string_buffer(length)
            received = ctypes.c_size_t()
            if not kernel.ReadProcessMemory(handle, ctypes.c_void_p(address), data, length, ctypes.byref(received)):
                raise ctypes.WinError(ctypes.get_last_error())
            return data.raw[:received.value]

        offset_address = module.value + symbol_rva(args.map, "g_xbox_mem_offset")
        offset = struct.unpack("<Q", read_native(offset_address, 8))[0]
        hits = []
        tail = b""
        cursor = args.start
        end = args.start + args.length
        while cursor < end:
            size = min(args.chunk_size, end - cursor)
            data = read_native(offset + cursor, size)
            haystack = tail + data
            haystack_lower = haystack.lower()
            base = cursor - len(tail)
            for label, encoding, needle in needles:
                search = haystack_lower if encoding.endswith("-lower") else haystack
                at = 0
                while True:
                    at = search.find(needle, at)
                    if at < 0:
                        break
                    guest = base + at
                    if guest >= args.start and not any(hit["guestAddress"] == f"0x{guest:08X}" and hit["pattern"] == label for hit in hits):
                        lo, hi = max(0, at - 24), min(len(haystack), at + len(needle) + 24)
                        hits.append({"pattern": label, "encoding": encoding,
                                     "guestAddress": f"0x{guest:08X}",
                                     "contextHex": haystack[lo:hi].hex()})
                    at += 1
            tail = haystack[-overlap:] if overlap else b""
            cursor += len(data)
            if len(data) != size:
                break
        result = {"schema": "dah2-recomp-guest-text-search-v1", "pid": args.pid,
                  "moduleBase": f"0x{module.value:x}", "guestOffset": f"0x{offset:x}",
                  "start": f"0x{args.start:08X}", "length": args.length, "hits": hits}
    finally:
        kernel.CloseHandle(handle)

    encoded = json.dumps(result, indent=2) + "\n"
    if args.output:
        if args.output.exists():
            raise SystemExit(f"refusing to overwrite {args.output}")
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")


if __name__ == "__main__":
    main()
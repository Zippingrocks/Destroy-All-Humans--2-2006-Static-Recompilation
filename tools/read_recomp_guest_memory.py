"""Read bounded Xbox virtual-memory ranges from a running private recomp."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
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
    parser.add_argument("--read", action="append", required=True,
                        help="NAME:ADDRESS:LENGTH, with numbers accepted by int(..., 0)")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--summary-only", action="store_true",
                        help="Report hashes/statistics without embedding captured bytes")
    args = parser.parse_args()

    ranges = []
    for spec in args.read:
        try:
            name, address, length = spec.split(":")
            address, length = int(address, 0), int(length, 0)
        except ValueError as exc:
            raise SystemExit(f"invalid range: {spec}") from exc
        if not name or not 0 <= address <= 0xFFFFFFFF or not 1 <= length <= 0x100000:
            raise SystemExit(f"invalid range: {spec}")
        ranges.append((name, address, length))

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
        if not psapi.EnumProcessModules(handle, ctypes.byref(module),
                                        ctypes.sizeof(module), ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())

        def read_native(address: int, length: int) -> bytes:
            data = ctypes.create_string_buffer(length)
            received = ctypes.c_size_t()
            if not kernel.ReadProcessMemory(handle, ctypes.c_void_p(address), data,
                                            length, ctypes.byref(received)):
                raise ctypes.WinError(ctypes.get_last_error())
            if received.value != length:
                raise RuntimeError(f"short read: {received.value}/{length}")
            return data.raw

        offset_address = module.value + symbol_rva(args.map, "g_xbox_mem_offset")
        offset = struct.unpack("<Q", read_native(offset_address, 8))[0]
        captures = []
        for name, address, length in ranges:
            data = read_native(offset + address, length)
            capture = {"name": name, "address": f"0x{address:08X}",
                       "length": length, "sha256": hashlib.sha256(data).hexdigest(),
                       "nonzeroBytes": sum(value != 0 for value in data)}
            if not args.summary_only:
                capture["hex"] = data.hex()
                capture["words"] = [f"{value:08X}" for value in struct.unpack(
                    f"<{length // 4}I", data[:length // 4 * 4])]
            captures.append(capture)
        result = {"schema": "dah2-recomp-guest-memory-v1", "pid": args.pid,
                  "moduleBase": f"0x{module.value:x}",
                  "guestOffset": f"0x{offset:x}", "ranges": captures}
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

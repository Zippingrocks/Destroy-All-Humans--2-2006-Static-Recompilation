"""Dump one bounded DXT texture from a running private recomp as a DDS file."""
from __future__ import annotations

import argparse
import ctypes
from pathlib import Path
import re
import struct

IMAGE_BASE = 0x140000000


def symbol_rva(map_path: Path, name: str) -> int:
    text = map_path.read_text(errors="replace")
    match = re.search(
        rf"(?m)^\s*[0-9A-Fa-f]+:[0-9A-Fa-f]+\s+{re.escape(name)}\s+([0-9A-Fa-f]+)\s",
        text,
    )
    if not match:
        raise SystemExit(f"symbol not found in map: {name}")
    return int(match.group(1), 16) - IMAGE_BASE


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--map", required=True, type=Path)
    parser.add_argument("--physical-offset", required=True, type=lambda value: int(value, 0))
    parser.add_argument("--width", required=True, type=int)
    parser.add_argument("--height", required=True, type=int)
    parser.add_argument("--format", required=True, choices=("DXT1", "DXT3", "DXT5"))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit(f"refusing to overwrite {args.output}")
    if not 1 <= args.width <= 2048 or not 1 <= args.height <= 2048:
        raise SystemExit("invalid dimensions")
    if not 0 <= args.physical_offset < 0x08000000:
        raise SystemExit("physical offset outside 128 MiB Xbox RAM")

    block_bytes = 8 if args.format == "DXT1" else 16
    size = ((args.width + 3) // 4) * ((args.height + 3) // 4) * block_bytes
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
        guest_offset = struct.unpack("<Q", read_native(offset_address, 8))[0]
        data = read_native(guest_offset + 0x80000000 + args.physical_offset, size)
    finally:
        kernel.CloseHandle(handle)

    flags = 0x00081007
    caps = 0x00001000
    pixel_format = struct.pack("<II4sIIIII", 32, 4, args.format.encode("ascii"), 0, 0, 0, 0, 0)
    header = struct.pack(
        "<IIIIIII11I", 124, flags, args.height, args.width, size, 0, 0, *([0] * 11)
    ) + pixel_format + struct.pack("<IIIII", caps, 0, 0, 0, 0)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(b"DDS " + header + data)
    print(f"{args.output}: {args.width}x{args.height} {args.format}, {size} payload bytes")


if __name__ == "__main__":
    main()
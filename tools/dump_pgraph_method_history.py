"""Atomically capture attributed PGRAPH method history from a private recomp."""

from __future__ import annotations

import argparse
import ctypes
import json
from pathlib import Path
import re
import struct

CAPACITY = 65536
RECORD = struct.Struct("<4IQ2I")
IMAGE_BASE = 0x140000000


def symbol_rva(map_path: Path, name: str) -> int:
    text = map_path.read_text(errors="replace")
    pattern = rf"(?m)^\s*[0-9A-Fa-f]+:[0-9A-Fa-f]+\s+{re.escape(name)}\s+([0-9A-Fa-f]+)\s"
    match = re.search(pattern, text)
    if not match:
        raise SystemExit(f"symbol not found in map: {name}")
    return int(match.group(1), 16) - IMAGE_BASE


class Reader:
    def __init__(self, pid: int):
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel = kernel
        self.ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                             ctypes.c_void_p, ctypes.c_size_t,
                                             ctypes.POINTER(ctypes.c_size_t)]
        kernel.ReadProcessMemory.restype = ctypes.c_int
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        self.ntdll.NtSuspendProcess.argtypes = [ctypes.c_void_p]
        self.ntdll.NtSuspendProcess.restype = ctypes.c_long
        self.ntdll.NtResumeProcess.argtypes = [ctypes.c_void_p]
        self.ntdll.NtResumeProcess.restype = ctypes.c_long
        psapi.EnumProcessModules.argtypes = [ctypes.c_void_p,
                                             ctypes.POINTER(ctypes.c_void_p),
                                             ctypes.c_uint32,
                                             ctypes.POINTER(ctypes.c_uint32)]
        self.handle = kernel.OpenProcess(0x0C10, False, pid)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        module = ctypes.c_void_p()
        needed = ctypes.c_uint32()
        if not psapi.EnumProcessModules(self.handle, ctypes.byref(module),
                                        ctypes.sizeof(module), ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        self.base = module.value
        self.suspended = False

    def suspend(self) -> None:
        status = self.ntdll.NtSuspendProcess(self.handle)
        if status < 0:
            raise OSError(f"NtSuspendProcess failed: 0x{status & 0xffffffff:08X}")
        self.suspended = True

    def read(self, address: int, length: int) -> bytes:
        data = ctypes.create_string_buffer(length)
        received = ctypes.c_size_t()
        if not self.kernel.ReadProcessMemory(self.handle, ctypes.c_void_p(address),
                                             data, length, ctypes.byref(received)):
            raise ctypes.WinError(ctypes.get_last_error())
        if received.value != length:
            raise RuntimeError(f"short read: {received.value}/{length}")
        return data.raw

    def close(self) -> None:
        try:
            if self.suspended:
                status = self.ntdll.NtResumeProcess(self.handle)
                self.suspended = False
                if status < 0:
                    raise OSError(f"NtResumeProcess failed: 0x{status & 0xffffffff:08X}")
        finally:
            self.kernel.CloseHandle(self.handle)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--map", required=True, type=Path)
    parser.add_argument("--limit", type=int, default=20000)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    reader = Reader(args.pid)
    try:
        cursor_rva = symbol_rva(args.map, "g_dah2_pgraph_method_history_cursor")
        ring_rva = symbol_rva(args.map, "g_dah2_pgraph_method_history")
        reader.suspend()
        cursor = struct.unpack("<I", reader.read(reader.base + cursor_rva, 4))[0]
        raw = reader.read(reader.base + ring_rva, CAPACITY * RECORD.size)
        first = max(0, cursor - min(max(args.limit, 1), CAPACITY))
        records = []
        for sequence in range(first, cursor):
            frame, subchannel, method, parameter, caller, thread_id, _ = RECORD.unpack_from(
                raw, (sequence & (CAPACITY - 1)) * RECORD.size)
            preferred_caller = caller - reader.base + IMAGE_BASE if caller else 0
            records.append({
                "sequence": sequence,
                "frame": frame,
                "subchannel": subchannel,
                "method": f"0x{method:04X}",
                "parameter": f"0x{parameter:08X}",
                "caller": f"0x{caller:016X}",
                "preferredCaller": f"0x{preferred_caller:016X}",
                "threadId": thread_id,
            })
        result = {
            "pid": args.pid,
            "moduleBase": f"0x{reader.base:016X}",
            "cursor": cursor,
            "firstSequence": first,
            "records": records,
        }
    finally:
        reader.close()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.output), "cursor": cursor,
                      "records": len(records)}, indent=2))


if __name__ == "__main__":
    main()
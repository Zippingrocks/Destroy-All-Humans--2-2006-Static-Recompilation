"""Read DAH2's bounded matrix, skeleton, and transform rings from a private recomp."""
from __future__ import annotations

import argparse
import ctypes
import json
from pathlib import Path
import re
import struct

IMAGE_BASE = 0x140000000
RINGS = {
    "anim_writer": ("g_dah2_anim_writer_probe_sequence", "g_dah2_anim_writer_probe_ring", 4096, 16),
    "quat_decode": ("g_dah2_quat_decode_probe_sequence", "g_dah2_quat_decode_probe_ring", 4096, 12),
    "slerp": ("g_dah2_slerp_probe_sequence", "g_dah2_slerp_probe_ring", 4096, 20),
    "matrix": ("g_dah2_matrix_probe_sequence", "g_dah2_matrix_probe_ring", 512, 52),
    "skeleton": ("g_dah2_skeleton_probe_sequence", "g_dah2_skeleton_probe_ring", 512, 55),
    "transform": ("g_dah2_transform_probe_sequence", "g_dah2_transform_probe_ring", 8192, 36),
    "menu_stage": ("g_dah2_menu_stage_sequence", "g_dah2_menu_stage_ring", 4096, 12),
    "draw_record": ("g_dah2_draw_record_sequence", "g_dah2_draw_record_ring", 4096, 16),
    "visibility": ("g_dah2_visibility_sequence", "g_dah2_visibility_ring", 4096, 60),
    "natalia_transform": ("g_dah2_natalia_transform_sequence", "g_dah2_natalia_transform_ring", 8192, 20),
    "natalia_x_access": ("g_dah2_natalia_x_access_sequence", "g_dah2_natalia_x_access_ring", 256, 8),
    "timing_link_access": ("g_dah2_timing_link_access_sequence", "g_dah2_timing_link_access_ring", 64, 16),
    "anim_sampler": ("g_dah2_anim_sampler_sequence", "g_dah2_anim_sampler_ring", 256, 16),
    "anim_event": ("g_dah2_anim_event_sequence", "g_dah2_anim_event_ring", 256, 8),
}


def symbol_rva(map_path: Path, name: str) -> int:
    text = map_path.read_text(errors="replace")
    match = re.search(rf"(?m)^\s*[0-9A-Fa-f]+:[0-9A-Fa-f]+\s+{re.escape(name)}\s+([0-9A-Fa-f]+)\s", text)
    if not match:
        raise SystemExit(f"symbol not found in map: {name}")
    return int(match.group(1), 16) - IMAGE_BASE


class Reader:
    def __init__(self, pid: int):
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        self.kernel = kernel
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
        self.handle = kernel.OpenProcess(0x0C10, False, pid)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        module = ctypes.c_void_p()
        needed = ctypes.c_uint32()
        if not psapi.EnumProcessModules(self.handle, ctypes.byref(module),
                                        ctypes.sizeof(module), ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        self.base = module.value
        ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
        ntdll.NtSuspendProcess.argtypes = [ctypes.c_void_p]
        ntdll.NtSuspendProcess.restype = ctypes.c_long
        ntdll.NtResumeProcess.argtypes = [ctypes.c_void_p]
        ntdll.NtResumeProcess.restype = ctypes.c_long
        self.ntdll = ntdll
        self.suspended = False
        status = ntdll.NtSuspendProcess(self.handle)
        if status < 0:
            kernel.CloseHandle(self.handle)
            raise OSError(f"NtSuspendProcess failed: NTSTATUS 0x{status & 0xFFFFFFFF:08X}")
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
        if self.suspended:
            status = self.ntdll.NtResumeProcess(self.handle)
            self.suspended = False
            if status < 0:
                self.kernel.CloseHandle(self.handle)
                raise OSError(f"NtResumeProcess failed: NTSTATUS 0x{status & 0xFFFFFFFF:08X}")
        self.kernel.CloseHandle(self.handle)


def words_to_hex(values: tuple[int, ...]) -> list[str]:
    return [f"{value:08X}" for value in values]


def decode(kind: str, values: tuple[int, ...]) -> dict[str, object]:
    if kind == "anim_writer":
        return {
            "sequence": values[0], "key": f"{values[1]:08X}",
            "edx": f"{values[2]:08X}", "stack": f"{values[3]:08X}",
            "descriptor": f"{values[4]:08X}", "time": f"{values[5]:08X}",
            "indexPointer": f"{values[6]:08X}", "output": f"{values[7]:08X}",
            "keyWords": words_to_hex(values[8:12]),
            "outputQuaternionBefore": words_to_hex(values[12:16]),
        }
    if kind == "quat_decode":
        return {
            "sequence": values[0], "input": f"{values[1]:08X}",
            "output": f"{values[2]:08X}", "logicalOutput": f"{values[3]:08X}",
            "inputWords": words_to_hex(values[4:6]), "stack": f"{values[6]:08X}",
            "outputWords": words_to_hex(values[7:11]), "completed": values[11],
        }
    if kind == "slerp":
        return {
            "sequence": values[0], "destination": f"{values[1]:08X}",
            "left": f"{values[2]:08X}", "right": f"{values[3]:08X}",
            "time": f"{values[4]:08X}", "leftWords": words_to_hex(values[5:9]),
            "rightWords": words_to_hex(values[9:13]), "outputWords": words_to_hex(values[13:17]),
            "weight0": f"{values[17]:08X}", "weight1": f"{values[18]:08X}",
            "completed": values[19],
        }
    if kind == "matrix":
        return {
            "sequence": values[0], "destination": f"{values[1]:08X}",
            "left": f"{values[2]:08X}", "right": f"{values[3]:08X}",
            "leftWords": words_to_hex(values[4:20]),
            "rightWords": words_to_hex(values[20:36]),
            "destinationWords": words_to_hex(values[36:52]),
        }
    if kind == "skeleton":
        return {
            "sequence": values[0], "stage": values[1], "owner": f"{values[2]:08X}",
            "parent": f"{values[3]:08X}", "bone": f"{values[4]:08X}",
            "local": f"{values[5]:08X}", "index": ctypes.c_int32(values[6]).value,
            "ownerWords": words_to_hex(values[7:39]),
            "localWords": words_to_hex(values[39:55]),
        }
    if kind == "menu_stage":
        return {
            "sequence": values[0], "node": f"{values[1]:08X}",
            "object": f"{values[2]:08X}", "flags": f"{values[3]:08X}",
            "stage": values[4], "gateResult": values[5],
            "dispatchTarget": f"{values[6]:08X}",
            "commandBegin": values[7], "commandEnd": values[8],
            "worldCall": values[9], "candidateIndex": values[10],
            "objectType": values[11],
        }
    if kind == "draw_record":
        return {
            "sequence": values[0], "destination": f"{values[1]:08X}",
            "returnAddress": f"{values[2]:08X}",
            "arguments": words_to_hex(values[3:15]),
            "activeObject": f"{values[15]:08X}",
        }
    if kind == "visibility":
        return {
            "sequence": values[0], "node": f"{values[1]:08X}",
            "object": f"{values[2]:08X}", "flags": f"{values[3]:08X}",
            "result": values[4], "renderer": f"{values[5]:08X}",
            "matrix": words_to_hex(values[6:22]),
            "vector": words_to_hex(values[22:26]),
            "bounds": words_to_hex(values[26:42]),
            "context": words_to_hex(values[42:58]),
            "output": f"{values[58]:08X}", "outputValue": values[59],
        }
    if kind == "natalia_transform":
        return {"sequence": values[0], "words": words_to_hex(values[1:])}
    if kind == "natalia_x_access":
        return {
            "sequence": values[0], "address": f"{values[1]:08X}",
            "oldValue": f"{values[2]:08X}", "newValue": f"{values[3]:08X}",
            "writerFunction": f"{values[4]:08X}", "writerLine": values[5],
            "observerFunction": f"{values[6]:08X}", "observerLine": values[7],
        }
    if kind == "timing_link_access":
        return {
            "sequence": values[0], "address": f"{values[1]:08X}",
            "oldValue": f"{values[2]:08X}", "newValue": f"{values[3]:08X}",
            "previousAccessFunction": f"{values[4]:08X}", "previousAccessLine": values[5],
            "observerFunction": f"{values[6]:08X}", "observerLine": values[7],
            "previousRegisters": dict(zip(("eax", "ecx", "edx", "esi", "edi", "esp"),
                                          words_to_hex(values[8:14]))),
            "threadId": values[14], "publishedSequence": values[15],
        }
    if kind == "anim_sampler":
        return {
            "sequence": values[0], "stage": values[1],
            "sampler": f"{values[2]:08X}", "target": f"{values[3]:08X}",
            "time": f"{values[4]:08X}", "cursor": f"{values[5]:08X}",
            "positionChannel": f"{values[6]:08X}", "targetVtable": f"{values[7]:08X}",
            "icallTarget": f"{values[8]:08X}", "targetX": f"{values[9]:08X}",
            "esp": f"{values[10]:08X}", "eax": f"{values[11]:08X}",
            "ecx": f"{values[12]:08X}", "edx": f"{values[13]:08X}",
            "esi": f"{values[14]:08X}", "edi": f"{values[15]:08X}",
        }
    if kind == "anim_event":
        return {
            "sequence": values[0], "stage": values[1],
            "object": f"{values[2]:08X}", "delta": f"{values[3]:08X}",
            "auxiliary": f"{values[4]:08X}", "esp": f"{values[5]:08X}",
            "objectAgain": f"{values[6]:08X}", "timeBefore": f"{values[7]:08X}",
        }
    return {
        "sequence": values[0], "destination": f"{values[1]:08X}",
        "source": f"{values[2]:08X}", "returnAddress": f"{values[3]:08X}",
        "sourceWords": words_to_hex(values[4:20]),
        "destinationWords": words_to_hex(values[20:36]),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--map", required=True, type=Path)
    parser.add_argument("--kind", action="append", choices=RINGS, default=[])
    parser.add_argument("--limit", type=int, default=512)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    kinds = args.kind or list(RINGS)
    if args.limit < 1:
        parser.error("--limit must be positive")
    reader = Reader(args.pid)
    captures: dict[str, object] = {}
    try:
        module_base = reader.base
        for kind in kinds:
            sequence_name, ring_name, capacity, width = RINGS[kind]
            sequence = struct.unpack("<I", reader.read(
                module_base + symbol_rva(args.map, sequence_name), 4))[0]
            raw = reader.read(module_base + symbol_rva(args.map, ring_name),
                              capacity * width * 4)
            if kind in {"draw_record", "visibility", "natalia_transform", "natalia_x_access", "timing_link_access", "anim_sampler", "anim_event"}:
                first = max(0, sequence - min(args.limit, capacity))
                current_range = range(first, sequence)
                slot_for = lambda current: current % capacity
            else:
                first = max(1, sequence - min(args.limit, capacity) + 1)
                current_range = range(first, sequence + 1)
                slot_for = lambda current: (current - 1) % capacity
            samples = []
            for current in current_range:
                values = struct.unpack_from(f"<{width}I", raw,
                                            slot_for(current) * width * 4)
                if values[0] == current and (kind != "timing_link_access" or values[15] == current + 1):
                    samples.append(decode(kind, values))
            captures[kind] = {"sequence": sequence, "capacity": capacity,
                              "sampleWords": width, "samples": samples}
    finally:
        reader.close()
    result = {"schema": "dah2-title-probe-rings-v1", "pid": args.pid,
              "moduleBase": f"0x{module_base:x}", "rings": captures}
    encoded = json.dumps(result, indent=2) + "\n"
    if args.output:
        if args.output.exists():
            raise SystemExit(f"refusing to overwrite {args.output}")
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")


if __name__ == "__main__":
    main()

"""Read DAH2's semantic ring; --no-suspend leaves the private process running.

The compatibility default suspends/resumes the target. Non-suspending snapshots
validate publication and stable record bytes, and report missing/raced records.
"""

from __future__ import annotations

import argparse
import ctypes
import json
from pathlib import Path
import re
import struct

CAPACITY = 4096
SAMPLE = struct.Struct("<QQ7Ii6I8I20I36I17I4x")
SAMPLE_V2 = struct.Struct("<QQ7Ii6I8I20I36I17I40I4x")
SAMPLE_LAYOUTS = {1: SAMPLE, 2: SAMPLE_V2}
IMAGE_BASE = 0x140000000


def symbol_rva(map_path: Path, name: str, *, required: bool = True) -> int | None:
    match = re.search(rf"(?m)^\s*[0-9A-Fa-f]+:[0-9A-Fa-f]+\s+{re.escape(name)}\s+([0-9A-Fa-f]+)\s", map_path.read_text(errors="replace"))
    if not match:
        if not required:
            return None
        raise SystemExit(f"symbol not found in map: {name}")
    return int(match.group(1), 16) - IMAGE_BASE


def resolve_sample_layout(reader, map_path: Path, requested: str = "auto"):
    """Strictly detect old 400-byte or new 560-byte samples before decoding."""
    size_rva = symbol_rva(map_path, "g_dah2_parity_state_sample_size", required=False)
    if size_rva is None:
        size, source = SAMPLE.size, "legacy_missing_size_symbol"
    else:
        size = struct.unpack("<I", reader.read(reader.base + size_rva, 4))[0]
        source = "exported_sample_size"
    versions = {sample.size: version for version, sample in SAMPLE_LAYOUTS.items()}
    if size not in versions:
        raise RuntimeError(f"unsupported parity sample size: {size}; expected 400 or 560")
    version = versions[size]
    if requested != "auto" and requested != str(version):
        raise RuntimeError(f"--sample-version {requested} disagrees with detected v{version} ({size} bytes)")
    return version, SAMPLE_LAYOUTS[version], source


class Reader:
    def __init__(self, pid: int, *, suspend: bool = True):
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
        self.handle = kernel.OpenProcess(0x0C10 if suspend else 0x0410, False, pid)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        module = ctypes.c_void_p()
        needed = ctypes.c_uint32()
        if not psapi.EnumProcessModules(self.handle, ctypes.byref(module), ctypes.sizeof(module), ctypes.byref(needed)):
            error = ctypes.get_last_error()
            kernel.CloseHandle(self.handle)
            raise ctypes.WinError(error)
        self.base = module.value

        self.suspended = False
        self.ntdll = None
        if not suspend:
            return
        ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
        ntdll.NtSuspendProcess.argtypes = [ctypes.c_void_p]
        ntdll.NtSuspendProcess.restype = ctypes.c_long
        ntdll.NtResumeProcess.argtypes = [ctypes.c_void_p]
        ntdll.NtResumeProcess.restype = ctypes.c_long
        self.ntdll = ntdll
        status = ntdll.NtSuspendProcess(self.handle)
        if status < 0:
            kernel.CloseHandle(self.handle)
            raise OSError(f"NtSuspendProcess failed: NTSTATUS 0x{status & 0xFFFFFFFF:08X}")
        self.suspended = True

    def read(self, address: int, length: int) -> bytes:
        data = ctypes.create_string_buffer(length)
        received = ctypes.c_size_t()
        if not self.kernel.ReadProcessMemory(self.handle, ctypes.c_void_p(address), data, length, ctypes.byref(received)):
            raise ctypes.WinError(ctypes.get_last_error())
        if received.value != length:
            raise RuntimeError(f"short read: {received.value}/{length}")
        return data.raw

    def close(self):
        if self.suspended:
            status = self.ntdll.NtResumeProcess(self.handle)
            self.suspended = False
            if status < 0:
                self.kernel.CloseHandle(self.handle)
                raise OSError(f"NtResumeProcess failed: NTSTATUS 0x{status & 0xFFFFFFFF:08X}")
        self.kernel.CloseHandle(self.handle)


def _missing_ranges(sequences: list[int]) -> list[list[int]]:
    ranges: list[list[int]] = []
    for sequence in sequences:
        if ranges and sequence == ranges[-1][1] + 1:
            ranges[-1][1] = sequence
        else:
            ranges.append([sequence, sequence])
    return ranges


def read_coherent_snapshot(reader, latest_address: int, ring_address: int,
                           limit: int = 120, retries: int = 3, sample=SAMPLE):
    """Copy published records without suspending; never treat a torn slot as data.

    The producer clears a slot's sequence, writes its payload, then publishes its
    new sequence and latest. Two identical full record reads with the requested
    sequence validate that historical record, not an atomic whole-ring instant.
    The initial publication bounds the requested range. Retries only recover
    missing records from that same range; later presents are never substituted.
    """
    if not 1 <= retries <= 16:
        raise ValueError("snapshot retries must be between 1 and 16")
    wanted_count = min(max(limit, 1), CAPACITY)
    target_latest = None
    stable: dict[int, bytes] = {}
    publications: list[list[int]] = []
    sequence_mismatches = payload_changes = 0
    for _ in range(retries):
        before = struct.unpack("<Q", reader.read(latest_address, 8))[0]
        if publications and before < publications[-1][1]:
            raise RuntimeError("ring publication moved backwards between attempts")
        if target_latest is None:
            target_latest = before
            first = max(1, before - wanted_count + 1)
            requested = list(range(first, before + 1))
        left = reader.read(ring_address, CAPACITY * sample.size)
        right = reader.read(ring_address, CAPACITY * sample.size)
        if len(left) != CAPACITY * sample.size or len(right) != CAPACITY * sample.size:
            raise RuntimeError("short ring snapshot")
        after = struct.unpack("<Q", reader.read(latest_address, 8))[0]
        if after < before:
            raise RuntimeError("ring publication moved backwards during snapshot")
        publications.append([before, after])
        for sequence in requested:
            if sequence in stable:
                continue
            offset = ((sequence - 1) % CAPACITY) * sample.size
            a = left[offset:offset + sample.size]
            b = right[offset:offset + sample.size]
            if len(a) != sample.size or len(b) != sample.size:
                raise RuntimeError("short ring snapshot")
            if struct.unpack_from("<Q", a)[0] != sequence or struct.unpack_from("<Q", b)[0] != sequence:
                sequence_mismatches += 1
            elif a != b:
                payload_changes += 1
            else:
                stable[sequence] = a
        if len(stable) == len(requested):
            break
    raw = bytearray(CAPACITY * sample.size)
    for sequence, record in stable.items():
        offset = ((sequence - 1) % CAPACITY) * sample.size
        raw[offset:offset + sample.size] = record
    missing = [sequence for sequence in requested if sequence not in stable]
    details = {
        "mode": "non_suspending_record_stable", "processSuspended": False,
        "atomicWholeRing": False, "attempts": len(publications),
        "requestedRecords": len(requested), "validRecords": len(stable),
        "complete": not missing, "missingSequences": missing,
        "missingRanges": _missing_ranges(missing),
        "inconsistentRecordObservations": sequence_mismatches + payload_changes,
        "sequenceMismatchObservations": sequence_mismatches,
        "payloadChangeObservations": payload_changes,
        "publicationReads": publications,
        "observedLatestAfter": publications[-1][1],
        "note": "Stable historical records bounded by initial publication; no target suspend/resume commands. Remote memory reads still consume host resources.",
    }
    return target_latest, bytes(raw), details


def decode_sample(values, version: int = 1):
    if version not in SAMPLE_LAYOUTS:
        raise ValueError(f"unsupported sample version: {version}")
    result = {
    "present": values[0], "wallMs": values[1],
    "title": dict(zip(("state", "count", "fieldB8", "fieldC0", "fieldCC", "movie", "fieldD4", "gate"), values[2:10])),
    "movieHeader": list(values[10:16]),
    "gpu": dict(zip(("frames", "draws", "vertices", "handled", "ignored", "clears", "indexed", "rejected"), values[16:24])),
    "frameMethods": {
        "methods": values[24], "begins": values[25], "ends": values[26],
        "beginModes": list(values[27:38]), "element16": values[38],
        "element32": values[39], "drawArrays": values[40],
        "drawArrayVertices": values[41], "inline": values[42],
        "clears": values[43],
    },
    "recentDraws": [dict(zip(("kind", "profile", "count", "mode", "target", "texture", "clipH", "clipV", "combiner"), values[44 + index * 9:53 + index * 9])) for index in range(4)],
    "surfaceProbePresent": values[80],
    "drawSurfaceProbe": [dict(zip(("target", "texture", "sourceBeforeNonblack", "targetAfterNonblack"), values[81 + index * 4:85 + index * 4])) for index in range(4)],
    }
    if version == 2:
        result["frameProfiles"] = {
            "accepted": list(values[97:107]), "rejected": list(values[107:117]),
            "acceptedInline": list(values[117:127]), "clipped": list(values[127:137]),
        }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--map", required=True, type=Path)
    parser.add_argument("--limit", type=int, default=120)
    parser.add_argument("--sample-version", choices=("auto", "1", "2"), default="auto",
                        help="Check sample layout; absence of size export is legacy v1/400")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--no-suspend", action="store_true",
                        help="Read stable published records without suspend/resume access")
    parser.add_argument("--snapshot-retries", type=int, default=3,
                        help="Bounded attempts for --no-suspend (1..16; default 3)")
    args = parser.parse_args()
    if not 1 <= args.snapshot_retries <= 16:
        parser.error("--snapshot-retries must be between 1 and 16")
    reader = Reader(args.pid, suspend=not args.no_suspend)
    try:
        latest_rva = symbol_rva(args.map, "g_dah2_parity_state_latest")
        ring_rva = symbol_rva(args.map, "g_dah2_parity_state_ring")
        version, sample, layout_source = resolve_sample_layout(reader, args.map, args.sample_version)
        if args.no_suspend:
            latest, raw, snapshot = read_coherent_snapshot(
                reader, reader.base + latest_rva, reader.base + ring_rva,
                args.limit, args.snapshot_retries, sample)
        else:
            latest = struct.unpack("<Q", reader.read(reader.base + latest_rva, 8))[0]
            raw = reader.read(reader.base + ring_rva, CAPACITY * sample.size)
        module_base = reader.base
    finally:
        reader.close()
    first = max(1, latest - min(max(args.limit, 1), CAPACITY) + 1)
    samples = []
    for sequence in range(first, latest + 1):
        values = sample.unpack_from(raw, ((sequence - 1) % CAPACITY) * sample.size)
        if values[0] != sequence:
            continue
        samples.append(decode_sample(values, version))
    result = {"schema": f"dah2-parity-state-ring-v{version}", "pid": args.pid,
              "moduleBase": f"0x{module_base:x}", "latest": latest,
              "sampleSize": sample.size, "sampleVersion": version,
              "layoutSource": layout_source, "samples": samples}
    if args.no_suspend:
        result["snapshot"] = snapshot
    encoded = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)


if __name__ == "__main__":
    main()
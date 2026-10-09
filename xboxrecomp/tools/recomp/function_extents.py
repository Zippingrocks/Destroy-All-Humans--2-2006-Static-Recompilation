"""Apply opt-in, binary-verified project function extents before translation.

All entries are validated before any metadata changes. This deliberately does
not remove interior entry symbols or infer ABI/classification from an extent.
"""
import hashlib
import json
import re
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

from .config import _classify


def _hex(value, field):
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{1,8}", value):
        raise ValueError(f"function extents: {field} must be a 32-bit hex address")
    return int(value, 16)


def _sha(value, field):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise ValueError(f"function extents: invalid {field}")
    return value.lower()


def _code_sections(image):
    """Read mappings from these bytes, not a potentially stale global layout."""
    if len(image) < 0x124 or image[:4] != b"XBEH":
        raise ValueError("function extents: invalid XBE header")
    base = struct.unpack_from("<I", image, 0x104)[0]
    count, table_va = struct.unpack_from("<II", image, 0x11C)
    table = table_va - base
    if not 0 < count <= 4096 or table < 0 or table + count * 56 > len(image):
        raise ValueError("function extents: invalid XBE section table")
    sections = []
    for index in range(count):
        flags, va, size, raw, raw_size, name_va = struct.unpack_from(
            "<6I", image, table + index * 56)
        name_offset = name_va - base
        if not 0 <= name_offset < len(image):
            raise ValueError("function extents: invalid XBE section name")
        end = image.find(b"\0", name_offset, min(len(image), name_offset + 64))
        if end < 0:
            raise ValueError("function extents: unterminated XBE section name")
        name = image[name_offset:end].decode("ascii", errors="strict")
        if _classify(name, flags):
            sections.append((va, size, raw, raw_size))
    return sections


def apply_function_extents(image, func_db, manifest_path):
    """Return applied starts; without a manifest, leave the database unchanged."""
    if manifest_path is None:
        return ()
    with open(manifest_path, encoding="utf-8") as source:
        manifest = json.load(source)
    if not isinstance(manifest, dict) or manifest.get("schema") != "verified-function-extents-v1":
        raise ValueError("function extents: unsupported manifest schema")
    expected = _sha(manifest.get("xbe_sha256"), "xbe_sha256")
    if hashlib.sha256(image).hexdigest() != expected:
        raise ValueError("function extents: XBE SHA256 mismatch")
    entries = manifest.get("functions")
    if not isinstance(entries, list) or not entries:
        raise ValueError("function extents: functions must be a nonempty list")
    sections = _code_sections(image)
    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    pending = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("function extents: function entry must be an object")
        start = _hex(entry.get("start"), "start")
        end = _hex(entry.get("end"), "end")
        if start in pending or start not in func_db or end <= start:
            raise ValueError(f"function extents: duplicate, unknown or invalid start 0x{start:08X}")
        count = entry.get("num_instructions")
        if type(count) is not int or count <= 0:
            raise ValueError("function extents: num_instructions must be a positive integer")
        mappings = [(raw + start - va, end - start)
                    for va, size, raw, raw_size in sections
                    if va <= start < end <= va + min(size, raw_size)]
        if len(mappings) != 1:
            raise ValueError(f"function extents: 0x{start:08X} range is not in one code section")
        offset, length = mappings[0]
        if offset < 0 or offset + length > len(image):
            raise ValueError("function extents: range is outside raw XBE bytes")
        raw = image[offset:offset + length]
        if hashlib.sha256(raw).hexdigest() != _sha(entry.get("sha256"), "function sha256"):
            raise ValueError(f"function extents: range SHA256 mismatch at 0x{start:08X}")
        instructions = list(disassembler.disasm(raw, start))
        if (len(instructions) != count or sum(i.size for i in instructions) != length
                or instructions[-1].address + instructions[-1].size != end
                or not (instructions[-1].mnemonic in ("ret", "jmp")
                        # a trailing call to a no-return helper (assert/throw), followed by int3 alignment padding
                        or (instructions[-1].mnemonic == "call" and offset + length < len(image)
                            and image[offset + length] == 0xCC))):
            raise ValueError(f"function extents: instruction/return boundary mismatch at 0x{start:08X}")
        pending[start] = {"end": end, "size": length, "num_instructions": count}
    for start, fields in pending.items():
        func_db[start].update(fields)
    return tuple(pending)

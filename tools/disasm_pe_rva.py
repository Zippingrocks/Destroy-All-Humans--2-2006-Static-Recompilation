"""Disassemble a small RVA range from a PE image without external PE tools."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("image", type=Path)
    parser.add_argument("rva", type=lambda value: int(value, 0))
    parser.add_argument("--before", type=lambda value: int(value, 0), default=0x40)
    parser.add_argument("--after", type=lambda value: int(value, 0), default=0x80)
    args = parser.parse_args()

    image = args.image.read_bytes()
    pe = u32(image, 0x3C)
    if image[pe : pe + 4] != b"PE\0\0":
        raise SystemExit("not a PE image")
    coff = pe + 4
    section_count = u16(image, coff + 2)
    optional_size = u16(image, coff + 16)
    section_table = coff + 20 + optional_size

    start_rva = args.rva - args.before
    end_rva = args.rva + args.after
    for index in range(section_count):
        entry = section_table + index * 40
        virtual_size = u32(image, entry + 8)
        virtual_address = u32(image, entry + 12)
        raw_size = u32(image, entry + 16)
        raw_offset = u32(image, entry + 20)
        span = max(virtual_size, raw_size)
        if virtual_address <= start_rva and end_rva <= virtual_address + span:
            file_offset = raw_offset + start_rva - virtual_address
            code = image[file_offset : file_offset + end_rva - start_rva]
            disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
            for instruction in disassembler.disasm(code, start_rva):
                marker = "=>" if instruction.address == args.rva else "  "
                print(
                    f"{marker} 0x{instruction.address:08X}: "
                    f"{instruction.mnemonic:<8} {instruction.op_str}"
                )
            return
    raise SystemExit(f"RVA 0x{args.rva:X} is not in one raw PE section")


if __name__ == "__main__":
    main()
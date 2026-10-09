"""Dump DAH2's opt-in per-draw NV2A state snapshots from a private process."""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from read_parity_state_ring import Reader, symbol_rva


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--map", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    reader = Reader(args.pid)
    try:
        def read_symbol(name: str, size: int) -> bytes:
            return reader.read(reader.base + symbol_rva(args.map, name), size)

        cursor = struct.unpack("<I", read_symbol("g_dah2_pgraph_draw_telemetry_cursor", 4))[0]
        telemetry = read_symbol("g_dah2_pgraph_draw_telemetry", 64 * 48)
        registers = read_symbol("g_dah2_pgraph_draw_registers", 64 * 0x2000)
        programs = read_symbol("g_dah2_pgraph_draw_programs", 64 * 136 * 4 * 4)
        program_valid = read_symbol("g_dah2_pgraph_draw_program_valid", 64 * 136 * 4)
        constants = read_symbol("g_dah2_pgraph_draw_constants", 64 * 192 * 4 * 4)
        constant_valid = read_symbol("g_dah2_pgraph_draw_constant_valid", 64 * 192 * 4)
        outputs = read_symbol("g_dah2_pgraph_draw_outputs", 64 * 13 * 4 * 4)
        output_masks = read_symbol("g_dah2_pgraph_draw_output_masks", 64 * 13)
        memory_failures = read_symbol("g_dah2_pgraph_draw_memory_failures", 64 * 11 * 4)
        module_base = reader.base
    finally:
        reader.close()

    draws = []
    first = max(0, cursor - 64)
    for sequence in range(first, cursor):
        slot = sequence % 64
        profile, count, mode, target, texture, clip_h, clip_v, combiner, reason, detail, source_object, source_node = struct.unpack_from("<12I", telemetry, slot * 48)
        register_values = struct.unpack_from("<2048I", registers, slot * 0x2000)
        program_values = struct.unpack_from("<544I", programs, slot * 136 * 16)
        constant_values = struct.unpack_from("<768f", constants, slot * 192 * 16)
        draws.append({
            "sequence": sequence,
            "slot": slot,
            "telemetry": {
                "profile": profile, "count": count, "mode": mode,
                "target": f"0x{target:08X}", "texture": f"0x{texture:08X}",
                "clipH": f"0x{clip_h:08X}", "clipV": f"0x{clip_v:08X}",
                "combiner": f"0x{combiner:08X}", "reason": reason,
                "detail": f"0x{detail:08X}",
                "sourceObject": f"0x{source_object:08X}",
                "sourceNode": f"0x{source_node:08X}",
            },
            "registers": [f"0x{value:08X}" for value in register_values],
            "program": [f"0x{value:08X}" for value in program_values],
            "programValid": list(program_valid[slot * 544:(slot + 1) * 544]),
            "constants": list(constant_values),
            "constantValid": list(constant_valid[slot * 768:(slot + 1) * 768]),
            "outputs": list(struct.unpack_from("<52f", outputs, slot * 13 * 16)),
            "outputMasks": list(output_masks[slot * 13:(slot + 1) * 13]),
            "memoryFailure": list(struct.unpack_from("<11I", memory_failures, slot * 44)),
        })

    result = {
        "schema": "dah2-pgraph-draw-state-v1", "pid": args.pid,
        "moduleBase": f"0x{module_base:x}", "cursor": cursor, "draws": draws,
    }
    encoded = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(encoded + "\n", encoding="utf-8")
    else:
        print(encoded)


if __name__ == "__main__":
    main()
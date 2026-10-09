"""Decode one captured DAH2 NV2A push buffer without mutating the guest."""
from __future__ import annotations
import argparse
import json
from pathlib import Path

PACKET_MASK = 0xE0030003
INCREMENTING = 0
NON_INCREMENTING = 0x40000000
RETURN = 0x00020000
BEGIN_END = 0x17FC
ELEMENT16 = 0x1800
ELEMENT32 = 0x1808
DRAW_ARRAYS = 0x1810
INLINE_ARRAY = 0x1818
FLIP_STALL = 0x0130
SURFACE_PITCH = 0x020C
SURFACE_COLOR_OFFSET = 0x0210
CONTEXT_DMA_VERTEX_A = 0x019C
CONTEXT_DMA_VERTEX_B = 0x01A0
ARRAY_OFFSET = 0x1720
ARRAY_FORMAT = 0x1760
TEXTURE_OFFSET = 0x1B00
TEXTURE_FORMAT = 0x1B04
TRANSFORM_PROGRAM_START = 0x1EA0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--cpu-base", required=True, type=lambda value: int(value, 0))
    parser.add_argument("--cpu-end", required=True, type=lambda value: int(value, 0))
    parser.add_argument("--cpu-put", required=True, type=lambda value: int(value, 0))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--tail-method-limit", type=int, default=4096,
                        help="number of unframed trailing methods to preserve (0 keeps all)")
    parser.add_argument("--frame-limit", type=int, default=8,
                        help="number of trailing complete frames to preserve (0 keeps all)")
    args = parser.parse_args()
    if args.tail_method_limit < 0:
        parser.error("--tail-method-limit must be non-negative")
    if args.frame_limit < 0:
        parser.error("--frame-limit must be non-negative")
    if args.output.exists():
        raise SystemExit(f"refusing to overwrite {args.output}")
    document = json.loads(args.snapshot.read_text(encoding="utf-8"))
    memory = {}
    for record in document.get("ranges", []):
        address = int(record["address"], 0)
        data = bytes.fromhex(record["xemu"]["hex"])
        for offset in range(0, len(data), 4):
            memory[(address + offset) & 0x0FFFFFFC] = int.from_bytes(data[offset:offset + 4], "little")
    start = args.cpu_base & 0x0FFFFFFC
    end = args.cpu_end & 0x0FFFFFFC
    put = args.cpu_put & 0x0FFFFFFC
    cursor = start
    return_cursor = None
    commands = []
    consumed_words = 0
    budget = (end - start) // 4 + 32
    error = None
    while cursor != put and budget:
        packet_address = cursor
        header = memory.get(cursor)
        if header is None:
            error = f"uncaptured header at 0x{cursor:08x}"
            break
        cursor += 4
        budget -= 1
        consumed_words += 1
        if header & 0xE0000003 == 0x20000000:
            cursor = header & 0x1FFFFFFF
            continue
        if header & 3 == 1:
            cursor = header & 0xFFFFFFFC
            continue
        if header & 3 == 2:
            if return_cursor is not None:
                error = f"nested call at 0x{packet_address:08x}"
                break
            return_cursor, cursor = cursor, header & 0xFFFFFFFC
            continue
        if header == RETURN:
            if return_cursor is None:
                error = f"return without call at 0x{packet_address:08x}"
                break
            cursor, return_cursor = return_cursor, None
            continue
        kind = header & PACKET_MASK
        if kind not in (INCREMENTING, NON_INCREMENTING):
            error = f"reserved header 0x{header:08x} at 0x{packet_address:08x}"
            break
        count = header >> 18 & 0x7FF
        method = header & 0x1FFC
        subchannel = header >> 13 & 7
        incrementing = kind == INCREMENTING
        if count > budget:
            error = f"packet exceeds budget at 0x{packet_address:08x}"
            break
        budget -= count
        for index in range(count):
            parameter = memory.get(cursor)
            if parameter is None:
                error = f"uncaptured parameter at 0x{cursor:08x}"
                break
            commands.append({"address": f"0x{cursor:08x}", "subchannel": subchannel,
                             "method": method + (index * 4 if incrementing else 0),
                             "parameter": parameter})
            cursor += 4
            consumed_words += 1
        if error:
            break
    frames = []
    frame_start = 0
    registers = {}
    for index, command in enumerate(commands):
        if command["method"] == FLIP_STALL:
            frame_commands = commands[frame_start:index + 1]
            draws, active = [], None
            for item in frame_commands:
                registers[item["method"]] = item["parameter"]
                if item["method"] == BEGIN_END:
                    if item["parameter"]:
                        active = {"mode": item["parameter"], "methods": 0, "element16Words": 0,
                                  "element32Words": 0, "drawArraysWords": 0,
                                  "drawArrayVertices": 0, "inlineWords": 0,
                                  "element16Indices": [], "element32Indices": [],
                                  "contextDmaVertexA": registers.get(CONTEXT_DMA_VERTEX_A),
                                  "contextDmaVertexB": registers.get(CONTEXT_DMA_VERTEX_B),
                                  "surfacePitch": registers.get(SURFACE_PITCH),
                                  "surfaceColorOffset": registers.get(SURFACE_COLOR_OFFSET),
                                  "textureOffset": registers.get(TEXTURE_OFFSET),
                                  "textureFormat": registers.get(TEXTURE_FORMAT),
                                  "programStart": registers.get(TRANSFORM_PROGRAM_START),
                                  "arrayOffsets": [registers.get(ARRAY_OFFSET + slot * 4) for slot in range(16)],
                                  "arrayFormats": [registers.get(ARRAY_FORMAT + slot * 4) for slot in range(16)]}
                    elif active is not None:
                        draws.append(active)
                        active = None
                elif active is not None:
                    active["methods"] += 1
                    if item["method"] == ELEMENT16:
                        active["element16Words"] += 1
                        active["element16Indices"].extend((item["parameter"] & 0xFFFF,
                                                            item["parameter"] >> 16))
                    elif item["method"] == ELEMENT32:
                        active["element32Words"] += 1
                        active["element32Indices"].append(item["parameter"])
                    elif item["method"] == DRAW_ARRAYS:
                        active["drawArraysWords"] += 1
                        active["drawArrayVertices"] += (item["parameter"] >> 24) + 1
                    elif item["method"] == INLINE_ARRAY: active["inlineWords"] += 1
            for draw in draws:
                indices = draw.pop("element16Indices") + draw.pop("element32Indices")
                draw["indexCount"] = len(indices)
                draw["restartCount"] = sum(value == 0xFFFF for value in indices)
                draw["minIndex"] = min(indices) if indices else None
                draw["maxIndex"] = max(indices) if indices else None
                draw["firstIndices"] = indices[:16]
                draw["lastIndices"] = indices[-16:]
            frames.append({"firstCommand": frame_start, "lastCommand": index,
                           "methodCount": len(frame_commands), "draws": draws})
            frame_start = index + 1
    tail = commands[frame_start:]
    retained_tail = tail if args.tail_method_limit == 0 else tail[-args.tail_method_limit:]
    tracked_methods = [TEXTURE_OFFSET, TEXTURE_FORMAT]
    tracked_writes = [item for item in commands if item["method"] in tracked_methods]
    output = {"schema": "dah2-pushbuffer-decode-v1", "source": str(args.snapshot.resolve()),
              "cpuBase": f"0x{args.cpu_base:08x}", "cpuEnd": f"0x{args.cpu_end:08x}",
              "cpuPut": f"0x{args.cpu_put:08x}", "physicalBase": f"0x{start:08x}",
              "physicalPut": f"0x{put:08x}", "cursor": f"0x{cursor:08x}",
              "consumedWords": consumed_words, "methodCount": len(commands),
              "error": error, "complete": cursor == put and error is None,
              "frames": frames if args.frame_limit == 0 else frames[-args.frame_limit:],
              "frameCount": len(frames), "tailMethodCount": len(tail),
              "tailMethods": retained_tail, "trackedWrites": tracked_writes}
    args.output.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: output[key] for key in ("complete", "error", "methodCount", "consumedWords", "cursor", "physicalPut", "tailMethodCount")}, indent=2))
    for number, frame in enumerate(output["frames"], max(0, len(frames) - len(output["frames"]))):
        print(f"frame {number}: methods={frame['methodCount']} draws={frame['draws']}")


if __name__ == "__main__":
    main()
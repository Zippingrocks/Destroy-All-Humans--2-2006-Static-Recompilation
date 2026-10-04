"""Pause the owned xemu guest and locate Lua source strings and Proto references."""
import argparse
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
from parity_boot_trace import ControlGDB, ControlQMP, wait_stopped


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--qmp-port", type=int, required=True)
    ap.add_argument("--gdb-port", type=int, required=True)
    ap.add_argument("--needle", required=True)
    ap.add_argument("--object-address", type=lambda x: int(x, 0), action="append", default=[])
    ap.add_argument("--start", type=lambda x: int(x, 0), default=0x81000000)
    ap.add_argument("--end", type=lambda x: int(x, 0), default=0x84000000)
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    if a.output.exists():
        ap.error("output must be new")
    q = ControlQMP(a.qmp_port, 5)
    g = None
    result = {"needle": a.needle, "start": hex(a.start), "end": hex(a.end),
              "string_hits": [], "pointer_hits": [], "errors": []}
    try:
        q.execute("stop")
        wait_stopped(q, 5, 0.05)
        g = ControlGDB(a.gdb_port, 10)
        g.request("?")
        needle = a.needle.encode("ascii")
        chunk_size = 0x100000
        chunks = []
        for base in range(a.start, a.end, chunk_size):
            size = min(chunk_size, a.end - base)
            try:
                data = g.memory(base, size)
            except Exception as exc:
                result["errors"].append({"address": hex(base), "error": str(exc)})
                continue
            chunks.append((base, data))
            pos = 0
            while True:
                pos = data.find(needle, pos)
                if pos < 0:
                    break
                result["string_hits"].append(base + pos)
                pos += 1
        object_addresses = [address - 20 for address in result["string_hits"]] + a.object_address
        patterns = {struct.pack("<I", address): address for address in object_addresses}
        for base, data in chunks:
            for pattern, target in patterns.items():
                pos = 0
                while True:
                    pos = data.find(pattern, pos)
                    if pos < 0:
                        break
                    result["pointer_hits"].append({"address": base + pos,
                                                   "target": target,
                                                   "proto_candidate": base + pos - 0x40})
                    pos += 1
    finally:
        try:
            q.execute("cont")
            result["resumed"] = True
        except Exception as exc:
            result["errors"].append({"resume": str(exc)})
        if g:
            g.close()
        q.close()
        a.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

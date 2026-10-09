"""Trace retail Lua callbacks until the active Proto source matches a needle."""

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
from parity_boot_trace import ControlGDB, ControlQMP, ProbeError, memory_record, stamp, wait_stopped


ENTRY = 0x001A8EB0
RETURN = 0x002117FD


def u32(gdb, address):
    return int.from_bytes(gdb.memory(address, 4), "little")


def cstring(gdb, address, limit=512):
    data = gdb.memory(address, limit)
    return data.split(b"\0", 1)[0].decode("latin1", errors="replace")


def active_proto(gdb, stack_bytes):
    words = [int.from_bytes(stack_bytes[i:i + 4], "little") for i in range(0, len(stack_bytes), 4)]
    candidates = []
    for index in range(2, len(words)):
        func = words[index]
        if not 0x80000000 <= func < 0x90000000:
            continue
        try:
            fields = gdb.memory(func, 0x48)
            f08 = int.from_bytes(fields[8:12], "little")
            pc = words[index - 2]
            code = int.from_bytes(fields[0x18:0x1c], "little")
            count = int.from_bytes(fields[0x1c:0x20], "little")
            source_obj = int.from_bytes(fields[0x40:0x44], "little")
            if words[index - 1] != f08 or not code <= pc <= code + max(4, count * 4):
                continue
            source = cstring(gdb, source_obj + 20) if 0x80000000 <= source_obj < 0x90000000 else ""
            candidates.append({"stack_index": index, "function": f"0x{func:08x}",
                               "pc": f"0x{pc:08x}", "source_object": f"0x{source_obj:08x}",
                               "source": source, "fields_hex": fields.hex()})
        except Exception:
            continue
    return candidates


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--qmp-port", type=int, required=True)
    ap.add_argument("--gdb-port", type=int, required=True)
    ap.add_argument("--needle", required=True)
    ap.add_argument("--max-calls", type=int, default=256)
    ap.add_argument("--timeout", type=float, default=180)
    ap.add_argument("--reset", action="store_true")
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    if a.output.exists():
        ap.error("output must be new")
    result = {"schema": "dah2-xemu-loader-calls-v1", "started": stamp(),
              "needle": a.needle, "calls": [],
              "cleanup": {"breakpoints_remaining": [], "resumed": False}}
    q = ControlQMP(a.qmp_port, 5)
    g = None
    active = set()
    deadline = time.monotonic() + a.timeout

    def bp(address, install):
        if install:
            active.add(address)
        g.breakpoint(address, install)
        if not install:
            active.discard(address)
        result["cleanup"]["breakpoints_remaining"] = [f"0x{x:08x}" for x in sorted(active)]

    try:
        q.execute("stop")
        wait_stopped(q, 5, 0.02)
        if a.reset:
            q.execute("system_reset")
            q.execute("stop")
            wait_stopped(q, 5, 0.02)
        g = ControlGDB(a.gdb_port, 5)
        result["initial_stop"] = g.request("?").decode(errors="replace")
        bp(ENTRY, True)
        for ordinal in range(1, a.max_calls + 1):
            q.execute("cont")
            wait_stopped(q, max(0.1, deadline - time.monotonic()), 0.02)
            regs = g.registers()["i386"]
            pc = int(regs["eip"], 16)
            if pc != ENTRY:
                raise ProbeError(f"stopped at unexpected 0x{pc:08x}")
            sp = int(regs["esp"], 16)
            stack_bytes = g.memory(sp, 0x100)
            row = {"ordinal": ordinal, "captured": stamp(), "registers": regs,
                   "stack": memory_record(g, sp, 0x100),
                   "proto_candidates": active_proto(g, stack_bytes)}
            if row["proto_candidates"]:
                row.update(row["proto_candidates"][0])
            state = int(regs["ecx"], 16)
            row["lua_state"] = memory_record(g, state, 0x40)
            result["calls"].append(row)
            a.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            matched = any(a.needle.lower() in item.get("source", "").lower()
                          for item in row["proto_candidates"])
            bp(ENTRY, False)
            bp(RETURN, True)
            q.execute("cont")
            wait_stopped(q, max(0.1, deadline - time.monotonic()), 0.02)
            ret_regs = g.registers()["i386"]
            row["return_registers"] = ret_regs
            bp(RETURN, False)
            if matched:
                result["match_ordinal"] = ordinal
                break
            bp(ENTRY, True)
    finally:
        try:
            q.execute("stop")
            wait_stopped(q, 5, 0.02)
        except Exception as exc:
            result["cleanup"].setdefault("errors", []).append(f"stop before cleanup: {exc}")
        if g:
            for address in list(active):
                try:
                    bp(address, False)
                except Exception as exc:
                    result["cleanup"].setdefault("errors", []).append(str(exc))
        try:
            q.execute("cont")
            result["cleanup"]["resumed"] = True
        except Exception as exc:
            result["cleanup"]["resume_error"] = str(exc)
        result["finished"] = stamp()
        a.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        if g:
            g.close()
        q.close()
    print(json.dumps({"calls": len(result["calls"]), "match": result.get("match_ordinal"),
                      "cleanup": result["cleanup"]}))


if __name__ == "__main__":
    main()

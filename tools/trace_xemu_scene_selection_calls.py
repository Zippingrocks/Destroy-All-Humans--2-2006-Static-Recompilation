"""Trace retail calls that select the active scene record (sub_0015EE60)."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from parity_boot_trace import (  # noqa: E402
    ControlGDB,
    ControlQMP,
    memory_record,
    stamp,
    wait_stopped,
)

ENTRY = 0x0015EE60
SCENE_GLOBAL = 0x002CA6A0


def u32(gdb: ControlGDB, address: int) -> int:
    return int.from_bytes(gdb.memory(address, 4), "little")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qmp-port", required=True, type=int)
    parser.add_argument("--gdb-port", required=True, type=int)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--max-hits", type=int, default=32)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must be new")

    output = {
        "schema": "dah2-xemu-scene-selection-calls-v1",
        "started": stamp(),
        "calls": [],
        "cleanup": {"breakpoints_remaining": [], "resumed": False},
    }
    qmp = ControlQMP(args.qmp_port, 5)
    gdb = None
    active = set()
    deadline = time.monotonic() + args.timeout

    def breakpoint(address: int, install: bool) -> None:
        assert gdb is not None
        gdb.breakpoint(address, install)
        if install:
            active.add(address)
        else:
            active.discard(address)
        output["cleanup"]["breakpoints_remaining"] = [
            f"0x{x:08x}" for x in sorted(active)
        ]

    try:
        qmp.execute("stop")
        wait_stopped(qmp, 5, 0.01)
        qmp.execute("system_reset")
        qmp.execute("stop")
        wait_stopped(qmp, 5, 0.01)
        gdb = ControlGDB(args.gdb_port, 5)
        output["initial_stop"] = gdb.request("?").decode(errors="replace")
        breakpoint(ENTRY, True)

        for ordinal in range(1, args.max_hits + 1):
            qmp.execute("cont")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                output["timeout"] = True
                break
            try:
                wait_stopped(qmp, remaining, 0.01)
            except Exception as exc:
                output["timeout"] = True
                output["timeout_error"] = str(exc)
                break
            regs = gdb.registers()["i386"]
            eip = int(regs["eip"], 16)
            if eip != ENTRY:
                output["unexpected_stop"] = f"0x{eip:08x}"
                break
            esp = int(regs["esp"], 16)
            scene = u32(gdb, SCENE_GLOBAL)
            argument_pointer = u32(gdb, esp + 4)
            row = {
                "ordinal": ordinal,
                "return_address": f"0x{u32(gdb, esp):08x}",
                "registers": regs,
                "stack": memory_record(gdb, esp, 0x40),
                "scene_global": f"0x{scene:08x}",
                "argument_pointer": f"0x{argument_pointer:08x}",
            }
            if 0x10000 <= argument_pointer < 0x90000000:
                row["selection_value"] = f"0x{u32(gdb, argument_pointer):08x}"
                row["argument_memory"] = memory_record(gdb, argument_pointer, 0x40)
            if 0x10000 <= scene < 0x90000000:
                row["scene_count"] = u32(gdb, scene + 0x524)
                row["scene_memory"] = memory_record(gdb, scene + 0x500, 0x40)
            output["calls"].append(row)
    finally:
        try:
            qmp.execute("stop")
            wait_stopped(qmp, 5, 0.01)
        except Exception as exc:
            output["cleanup"].setdefault("errors", []).append(f"stop: {exc}")
        if gdb is not None:
            for address in list(active):
                try:
                    breakpoint(address, False)
                except Exception as exc:
                    output["cleanup"].setdefault("errors", []).append(str(exc))
        try:
            qmp.execute("cont")
            output["cleanup"]["resumed"] = True
        except Exception as exc:
            output["cleanup"]["resume_error"] = str(exc)
        output["finished"] = stamp()
        args.output.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
        if gdb is not None:
            gdb.close()
        qmp.close()

    print(json.dumps({"calls": len(output["calls"]), "cleanup": output["cleanup"]}))


if __name__ == "__main__":
    main()
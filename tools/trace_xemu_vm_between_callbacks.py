"""Trace retail Lua VM dispatches between two post-loader callbacks."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from parity_boot_trace import ControlQMP, ProbeError, memory_record, stamp, wait_stopped
from trace_xemu_vm_handoff import StepGDB

LOADER = 0x001A8EB0
CALLBACK = 0x002117F9
CALLBACK_RETURN = 0x002117FD
VM_DISPATCH = 0x00218DF1


def u32(gdb: StepGDB, address: int) -> int:
    return int.from_bytes(gdb.memory(address, 4), "little")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qmp-port", required=True, type=int)
    parser.add_argument("--gdb-port", required=True, type=int)
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--start-callback", type=int, default=5)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must be new")

    out = {
        "schema": "dah2-xemu-vm-between-callbacks-v1",
        "started": stamp(),
        "dispatches": [],
        "cleanup": {"breakpoints_remaining": [], "resumed": False},
    }
    qmp = ControlQMP(args.qmp_port, 5)
    gdb = None
    active: set[int] = set()
    deadline = time.monotonic() + args.timeout

    def breakpoint(address: int, install: bool) -> None:
        assert gdb is not None
        gdb.breakpoint(address, install)
        if install:
            active.add(address)
        else:
            active.discard(address)
        out["cleanup"]["breakpoints_remaining"] = [
            f"0x{value:08x}" for value in sorted(active)
        ]

    def run() -> tuple[int, dict]:
        assert gdb is not None
        qmp.execute("cont")
        wait_stopped(qmp, max(0.1, deadline - time.monotonic()), 0.01)
        regs = gdb.registers()["i386"]
        return int(regs["eip"], 16), regs

    try:
        qmp.execute("stop")
        wait_stopped(qmp, 5, 0.01)
        qmp.execute("system_reset")
        qmp.execute("stop")
        wait_stopped(qmp, 5, 0.01)
        gdb = StepGDB(args.gdb_port, 5)
        out["initial_stop"] = gdb.request("?").decode(errors="replace")

        breakpoint(LOADER, True)
        eip, out["loader_registers"] = run()
        if eip != LOADER:
            raise ProbeError(f"expected loader, stopped at 0x{eip:08x}")
        breakpoint(LOADER, False)

        breakpoint(CALLBACK, True)
        for ordinal in range(1, args.start_callback + 1):
            eip, regs = run()
            if eip != CALLBACK:
                raise ProbeError(f"expected callback {ordinal}, stopped at 0x{eip:08x}")
            target = u32(gdb, int(regs["ebx"], 16))
            if ordinal == args.start_callback:
                out["start_callback"] = {
                    "ordinal": ordinal,
                    "target": f"0x{target:08x}",
                    "registers": regs,
                    "stack": memory_record(gdb, int(regs["esp"], 16), 0x100),
                }
            breakpoint(CALLBACK, False)
            breakpoint(CALLBACK_RETURN, True)
            eip, _ = run()
            if eip != CALLBACK_RETURN:
                raise ProbeError(f"expected callback return, stopped at 0x{eip:08x}")
            breakpoint(CALLBACK_RETURN, False)
            if ordinal != args.start_callback:
                breakpoint(CALLBACK, True)

        breakpoint(CALLBACK, True)
        breakpoint(VM_DISPATCH, True)
        while len(out["dispatches"]) < 2048:
            eip, regs = run()
            if eip == CALLBACK:
                target = u32(gdb, int(regs["ebx"], 16))
                out["next_callback"] = {
                    "ordinal": args.start_callback + 1,
                    "target": f"0x{target:08x}",
                    "registers": regs,
                    "stack": memory_record(gdb, int(regs["esp"], 16), 0x100),
                }
                break
            if eip != VM_DISPATCH:
                raise ProbeError(f"unexpected stop at 0x{eip:08x}")
            esp = int(regs["esp"], 16)
            pc = u32(gdb, esp + 0x10)
            function = u32(gdb, esp + 0x18)
            out["dispatches"].append({
                "ordinal": len(out["dispatches"]) + 1,
                "pc": f"0x{pc:08x}",
                "opcode": f"0x{u32(gdb, pc):08x}",
                "top": regs["ebp"],
                "state": regs["edi"],
                "function": f"0x{function:08x}",
                "code": f"0x{u32(gdb, esp + 0x0c):08x}",
                "source_object": f"0x{u32(gdb, function + 0x40):08x}",
            })
            gdb.step()
        else:
            raise ProbeError("next callback not reached within 2048 dispatches")
    finally:
        try:
            qmp.execute("stop")
            wait_stopped(qmp, 5, 0.01)
        except Exception as exc:
            out["cleanup"].setdefault("errors", []).append(f"stop: {exc}")
        if gdb is not None:
            for address in list(active):
                try:
                    breakpoint(address, False)
                except Exception as exc:
                    out["cleanup"].setdefault("errors", []).append(str(exc))
        try:
            qmp.execute("cont")
            out["cleanup"]["resumed"] = True
        except Exception as exc:
            out["cleanup"]["resume_error"] = str(exc)
        out["finished"] = stamp()
        args.output.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
        if gdb is not None:
            gdb.close()
        qmp.close()

    print(json.dumps({
        "dispatches": len(out["dispatches"]),
        "start_callback": out.get("start_callback", {}).get("target"),
        "next_callback": out.get("next_callback", {}).get("target"),
        "cleanup": out["cleanup"],
    }))


if __name__ == "__main__":
    main()

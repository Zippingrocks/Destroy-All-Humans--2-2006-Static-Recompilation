"""Trace the retail Lua CALL that follows loader callback six."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from parity_boot_trace import ControlQMP, ProbeError, memory_record, stamp, wait_stopped  # noqa: E402
from trace_xemu_loader_calls import active_proto  # noqa: E402
from trace_xemu_vm_handoff import StepGDB  # noqa: E402

LOADER = 0x001A8EB0
CALLBACK = 0x002117F9
CALLBACK_RETURN = 0x002117FD
VM_DISPATCH = 0x00218DF1
PRECALL = 0x00211810
CALL_HANDLER = 0x00218E25
LANDMARKS = {0x0021964C, 0x00211896, 0x0021198B, 0x002115C7, 0x002119BF, 0x00103FE6, 0x00103FF0, 0x00103FFD, 0x00104012, 0x00104016, 0x00104021, 0x00104077, 0x001037A0, 0x001037AD, 0x001047F2, 0x000F7C76, VM_DISPATCH}


def u32(gdb: StepGDB, address: int) -> int:
    return int.from_bytes(gdb.memory(address, 4), "little")


def snapshot(gdb: StepGDB, address: int) -> dict:
    regs = gdb.registers()["i386"]
    esp = int(regs["esp"], 16)
    ebp = int(regs["ebp"], 16)
    edx = int(regs["edx"], 16)
    row = {
        "address": f"0x{address:08x}",
        "registers": regs,
        "stack": memory_record(gdb, esp, 0x100),
    }
    if 0x10000 <= ebp < 0x90000000:
        row["value_stack"] = memory_record(gdb, ebp - 0x80, 0x100)
    if 0x10000 <= edx < 0x90000000:
        row["edx_memory"] = memory_record(gdb, edx, 0x80)
    return row


def vm_row(gdb: StepGDB, ordinal: int) -> dict:
    regs = gdb.registers()["i386"]
    esp = int(regs["esp"], 16)
    top = int(regs["ebp"], 16)
    stack = gdb.memory(esp, 0x100)
    pc = u32(gdb, esp + 0x10)
    return {
        "ordinal": ordinal,
        "registers": regs,
        "stack": memory_record(gdb, esp, 0x100),
        "pc": f"0x{pc:08x}",
        "opcode": f"0x{u32(gdb, pc):08x}",
        "top": f"0x{top:08x}",
        "value_stack": memory_record(gdb, top - 0x80, 0x100),
        "proto_candidates": active_proto(gdb, stack),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qmp-port", required=True, type=int)
    parser.add_argument("--gdb-port", required=True, type=int)
    parser.add_argument("--timeout", type=float, default=240.0)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must be new")

    out = {
        "schema": "dah2-xemu-vm-call-after-loader-callback6-v1",
        "started": stamp(),
        "callbacks": [],
        "vm_steps": [],
        "landmarks": [],
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
        out["cleanup"]["breakpoints_remaining"] = [
            f"0x{x:08x}" for x in sorted(active)
        ]

    def run(expected: int) -> dict:
        qmp.execute("cont")
        wait_stopped(qmp, max(0.1, deadline - time.monotonic()), 0.01)
        regs = gdb.registers()["i386"]
        actual = int(regs["eip"], 16)
        if actual != expected:
            raise ProbeError(f"expected 0x{expected:08x}, stopped at 0x{actual:08x}")
        return regs

    try:
        qmp.execute("stop")
        wait_stopped(qmp, 5, 0.01)
        qmp.execute("system_reset")
        qmp.execute("stop")
        wait_stopped(qmp, 5, 0.01)
        gdb = StepGDB(args.gdb_port, 5)
        out["initial_stop"] = gdb.request("?").decode(errors="replace")

        breakpoint(LOADER, True)
        out["loader"] = {"registers": run(LOADER)}
        breakpoint(LOADER, False)

        breakpoint(CALLBACK, True)
        for ordinal in range(1, 7):
            regs = run(CALLBACK)
            ebx = int(regs["ebx"], 16)
            out["callbacks"].append({
                "ordinal": ordinal,
                "target": f"0x{u32(gdb, ebx):08x}",
                "registers": regs,
            })
            breakpoint(CALLBACK, False)
            breakpoint(CALLBACK_RETURN, True)
            run(CALLBACK_RETURN)
            breakpoint(CALLBACK_RETURN, False)
            if ordinal != 6:
                breakpoint(CALLBACK, True)

        breakpoint(VM_DISPATCH, True)
        for ordinal in range(1, 3):
            run(VM_DISPATCH)
            out["vm_steps"].append(vm_row(gdb, ordinal))
            breakpoint(VM_DISPATCH, False)
            gdb.step()
            if ordinal != 2:
                breakpoint(VM_DISPATCH, True)

        out["single_steps"] = []
        for ordinal in range(1, 10001):
            gdb.step()
            regs = gdb.registers()["i386"]
            address = int(regs["eip"], 16)
            if ordinal <= 512:
                out["single_steps"].append(f"0x{address:08x}")
            if address in LANDMARKS:
                out["landmarks"].append(snapshot(gdb, address))
            if address == VM_DISPATCH:
                out["causal_steps"] = ordinal
                break
        else:
            raise ProbeError("next VM dispatch not reached within 10000 single steps")
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
        "vm_steps": len(out["vm_steps"]),
        "landmarks": [row["address"] for row in out["landmarks"]],
        "cleanup": out["cleanup"],
    }))


if __name__ == "__main__":
    main()